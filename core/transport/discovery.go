package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"aead.dev/minisign"
)

const (
	rendezvousNamespace    = "rendezvous-v1"
	rendezvousSchema       = 2
	rendezvousKeyMismatch  = "rendezvous public key does not match pinned key"
	rendezvousKeyNotPinned = "rendezvous public key is not pinned; call SetRendezvousPublicKey or pass rendezvous_public_key to ApplyPublicPlatformConfig"
)

// discoveryTrust is the process-wide trust anchor for rendezvous bundles. The
// key is pinned out of band (SetRendezvousPublicKey / ApplyPublicPlatformConfig
// with rendezvous_public_key), never taken from the ApplyDiscoveredEndpoints
// request that also carries the bundle. maxSeenSeq is the highest seq accepted
// under the pinned key during this process lifetime; the caller-persisted
// max_seen_seq is combined with it.
var discoveryTrust struct {
	sync.Mutex
	publicKey  string
	maxSeenSeq int64
}

// discoveryLocalNow is the device clock; replaceable in tests.
var discoveryLocalNow = time.Now

var forbiddenDiscoveryKeys = map[string]struct{}{
	"internal_ip":        {},
	"internalip":         {},
	"private_key":        {},
	"privatekey":         {},
	"psk2":               {},
	"server_private_key": {},
}

type applyDiscoveredRequest struct {
	EndpointsJSON        string `json:"endpoints_json"`
	EndpointsJSONMinisig string `json:"endpoints_json_minisig,omitempty"`
	Minisig              string `json:"minisig,omitempty"`
	PublicKey            string `json:"public_key,omitempty"`
	Now                  string `json:"now,omitempty"`
	MaxSeenSeq           int64  `json:"max_seen_seq,omitempty"`
	BaseConfigJSON       string `json:"base_config_json,omitempty"`
}

type discoveredBundle struct {
	Schema    int                 `json:"schema"`
	Namespace string              `json:"ns"`
	Seq       int64               `json:"seq"`
	IssuedAt  string              `json:"issued_at"`
	ExpiresAt string              `json:"expires_at"`
	Endpoints discoveredEndpoints `json:"endpoints"`
}

type discoveredEndpoints struct {
	AWG     []discoveredAWGEndpoint     `json:"awg"`
	Reality []discoveredRealityEndpoint `json:"reality"`
}

type discoveredAWGEndpoint struct {
	Priority        int    `json:"priority"`
	Endpoint        string `json:"endpoint"`
	EgressIP        string `json:"egress_ip,omitempty"`
	ServerPublicKey string `json:"server_public_key"`
	AWGPreset       preset `json:"awg_preset"`
}

type discoveredRealityEndpoint struct {
	Priority    int    `json:"priority"`
	Transport   string `json:"transport,omitempty"`
	Address     string `json:"address,omitempty"`
	EgressIP    string `json:"egress_ip,omitempty"`
	Port        int    `json:"port,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	Flow        string `json:"flow,omitempty"`
	Security    string `json:"security,omitempty"`
	Network     string `json:"network,omitempty"`
	ServerName  string `json:"serverName,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortID     string `json:"shortId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type applyDiscoveredResult struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Seq        int64  `json:"seq,omitempty"`
	ConfigJSON string `json:"config_json,omitempty"`
	// AWGMergeSkipped is set when the stored AWG config targets a non-base
	// worker profile or an IPv6 endpoint: the bundle's base IPv4 endpoint
	// would break it, so config_json is returned unchanged.
	AWGMergeSkipped bool `json:"awg_merge_skipped,omitempty"`
	// AWGRejected lists feed AWG entries skipped because of their dialect.
	// When no entry is usable the stored config is returned unchanged with
	// awg_merge_skipped set.
	AWGRejected []awgRouteRejection        `json:"awg_rejected,omitempty"`
	EgressIP    string                     `json:"egress_ip,omitempty"`
	Reality     *discoveredRealityEndpoint `json:"reality,omitempty"`
}

func ApplyDiscoveredEndpoints(requestJSON string) string {
	result, err := applyDiscoveredEndpoints(requestJSON)
	if err != nil {
		return encodeApplyDiscoveredResult(applyDiscoveredResult{OK: false, Error: err.Error()})
	}
	return encodeApplyDiscoveredResult(result)
}

func applyDiscoveredEndpoints(requestJSON string) (applyDiscoveredResult, error) {
	var req applyDiscoveredRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return applyDiscoveredResult{}, fmt.Errorf("parse request json: %w", err)
	}
	if strings.TrimSpace(req.EndpointsJSON) == "" {
		return applyDiscoveredResult{}, errors.New("endpoints_json is required")
	}
	signature := firstNonEmpty(req.EndpointsJSONMinisig, req.Minisig)
	if strings.TrimSpace(signature) == "" {
		return applyDiscoveredResult{}, errors.New("endpoints minisig is required")
	}
	pubkey, storedMaxSeq, err := discoveryTrustSnapshot(req.PublicKey)
	if err != nil {
		return applyDiscoveredResult{}, err
	}
	if err := verifyMinisignResult(req.EndpointsJSON, signature, pubkey); err != nil {
		return applyDiscoveredResult{}, err
	}
	if err := rejectForbiddenDiscoveryKeys([]byte(req.EndpointsJSON)); err != nil {
		return applyDiscoveredResult{}, err
	}
	var bundle discoveredBundle
	if err := json.Unmarshal([]byte(req.EndpointsJSON), &bundle); err != nil {
		return applyDiscoveredResult{}, fmt.Errorf("parse endpoints json: %w", err)
	}
	now, err := discoveryNow(req.Now)
	if err != nil {
		return applyDiscoveredResult{}, err
	}
	if err := validateDiscoveredBundle(bundle, max(storedMaxSeq, req.MaxSeenSeq), now); err != nil {
		return applyDiscoveredResult{}, err
	}
	awg, rejected, err := selectAWGEndpointSkipping(bundle.Endpoints.AWG)
	noUsableAWG := false
	if err != nil {
		if len(rejected) == 0 || len(rejected) != len(bundle.Endpoints.AWG) {
			return applyDiscoveredResult{}, err
		}
		// Every entry was rejected for its dialect: keep the stored AWG
		// config and still apply the rest of the feed.
		noUsableAWG = true
	}
	reality := selectRealityEndpoint(bundle.Endpoints.Reality)
	var mergedJSON string
	mergeSkipped := false
	if req.BaseConfigJSON != "" {
		// Caller-supplied base: a pure function of the request. The shared
		// provisioned config is neither read nor overwritten. Without stored
		// metadata only the endpoint family can be checked.
		meta := provisionedConfigMeta{v6: configEndpointIsIPv6(req.BaseConfigJSON)}
		if noUsableAWG {
			mergedJSON, mergeSkipped, err = keepBaseAWGConfig(req.BaseConfigJSON)
		} else {
			mergedJSON, mergeSkipped, err = mergeDiscoveredAWGConfigFor(req.BaseConfigJSON, meta, awg)
		}
		if err == nil {
			err = recordDiscoveredSeq(pubkey, bundle.Seq)
		}
		if err != nil {
			return applyDiscoveredResult{}, err
		}
	} else {
		// Read, merge and write back in one critical section so a concurrent
		// ApplyPublicPlatformConfig / ApplyDiscoveredEndpoints cannot be lost.
		pendingProvision.Lock()
		if pendingProvision.configJSON == "" {
			pendingProvision.Unlock()
			return applyDiscoveredResult{}, errors.New("provisioned config is missing")
		}
		if noUsableAWG {
			mergedJSON, mergeSkipped, err = keepBaseAWGConfig(pendingProvision.configJSON)
		} else {
			mergedJSON, mergeSkipped, err = mergeDiscoveredAWGConfigFor(pendingProvision.configJSON, pendingProvision.configMeta, awg)
		}
		if err == nil {
			err = recordDiscoveredSeq(pubkey, bundle.Seq)
		}
		if err == nil {
			pendingProvision.configJSON = mergedJSON
		}
		pendingProvision.Unlock()
		if err != nil {
			return applyDiscoveredResult{}, err
		}
	}
	result := applyDiscoveredResult{
		OK:         true,
		Seq:        bundle.Seq,
		ConfigJSON: mergedJSON,

		AWGMergeSkipped: mergeSkipped,
		AWGRejected:     rejected,
	}
	if reality != nil {
		result.Reality = reality
		result.EgressIP = reality.EgressIP
	}
	return result, nil
}

// SetRendezvousPublicKey pins the minisign public key that authenticates
// rendezvous bundles for ApplyDiscoveredEndpoints. Re-pinning the same key is a
// no-op; a different key cannot replace an already pinned one through this
// call (rotation goes through ApplyPublicPlatformConfig, which carries the
// currently verified signed client config). Returns {"ok":true} or
// {"ok":false,"error":"..."}.
func SetRendezvousPublicKey(publicKey string) string {
	if err := pinRendezvousPublicKey(publicKey, false); err != nil {
		return encodeMinisignVerifyResult(minisignVerifyResult{OK: false, Error: err.Error()})
	}
	return encodeMinisignVerifyResult(minisignVerifyResult{OK: true})
}

func pinRendezvousPublicKey(publicKey string, replace bool) error {
	canonical, err := canonicalRendezvousKey(publicKey)
	if err != nil {
		return err
	}
	discoveryTrust.Lock()
	defer discoveryTrust.Unlock()
	if discoveryTrust.publicKey == canonical {
		return nil
	}
	if discoveryTrust.publicKey != "" && !replace {
		return errors.New(rendezvousKeyMismatch)
	}
	// A new key starts a new seq space; the caller-persisted max_seen_seq
	// still applies on top of it.
	discoveryTrust.publicKey = canonical
	discoveryTrust.maxSeenSeq = 0
	return nil
}

func canonicalRendezvousKey(publicKey string) (string, error) {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return "", errors.New("rendezvous public key is empty")
	}
	var parsed minisign.PublicKey
	if err := parsed.UnmarshalText([]byte(publicKey)); err != nil {
		return "", errors.New("invalid rendezvous public key")
	}
	return parsed.String(), nil
}

// discoveryTrustSnapshot returns the pinned key and the in-process max seq.
// A public_key in the request is optional; when present it must equal the pin.
func discoveryTrustSnapshot(requestKey string) (string, int64, error) {
	discoveryTrust.Lock()
	pinned, maxSeenSeq := discoveryTrust.publicKey, discoveryTrust.maxSeenSeq
	discoveryTrust.Unlock()
	if pinned == "" {
		return "", 0, errors.New(rendezvousKeyNotPinned)
	}
	if strings.TrimSpace(requestKey) != "" {
		requested, err := canonicalRendezvousKey(requestKey)
		if err != nil {
			return "", 0, err
		}
		if requested != pinned {
			return "", 0, errors.New(rendezvousKeyMismatch)
		}
	}
	return pinned, maxSeenSeq, nil
}

// recordDiscoveredSeq ratchets the in-process max seq after a bundle has been
// fully validated. It re-checks the pin and the rollback bound under the lock
// so a concurrent key rotation or a newer bundle accepted in between wins.
func recordDiscoveredSeq(pubkey string, seq int64) error {
	discoveryTrust.Lock()
	defer discoveryTrust.Unlock()
	if discoveryTrust.publicKey != pubkey {
		return errors.New(rendezvousKeyMismatch)
	}
	if seq < discoveryTrust.maxSeenSeq {
		return fmt.Errorf("rendezvous rollback: seq=%d max_seen_seq=%d", seq, discoveryTrust.maxSeenSeq)
	}
	discoveryTrust.maxSeenSeq = seq
	return nil
}

func validateDiscoveredBundle(bundle discoveredBundle, maxSeenSeq int64, now time.Time) error {
	if bundle.Schema != rendezvousSchema {
		return fmt.Errorf("unsupported rendezvous schema: %d", bundle.Schema)
	}
	if bundle.Namespace != rendezvousNamespace {
		return fmt.Errorf("invalid rendezvous namespace: %q", bundle.Namespace)
	}
	if bundle.Seq < 0 {
		return errors.New("rendezvous seq must be non-negative")
	}
	if bundle.Seq < maxSeenSeq {
		return fmt.Errorf("rendezvous rollback: seq=%d max_seen_seq=%d", bundle.Seq, maxSeenSeq)
	}
	issuedAt, err := parseRendezvousTime(bundle.IssuedAt, "issued_at")
	if err != nil {
		return err
	}
	expiresAt, err := parseRendezvousTime(bundle.ExpiresAt, "expires_at")
	if err != nil {
		return err
	}
	if !expiresAt.After(issuedAt) {
		return errors.New("expires_at must be after issued_at")
	}
	if now.Before(issuedAt) {
		return errors.New("rendezvous bundle is not issued yet")
	}
	// The caller-supplied now (the mirror's Date header) is not signed and may
	// be replayed alongside an old bundle, so expiry is checked against the
	// later of it and the device clock: a bundle already expired locally is
	// rejected even when the mirror claims an earlier time. The trade-off is
	// that a device clock running far ahead rejects still-valid bundles; a
	// device clock running behind is still corrected by the supplied now.
	expiryNow := now
	if local := discoveryLocalNow().UTC(); local.After(expiryNow) {
		expiryNow = local
	}
	if !expiryNow.Before(expiresAt) {
		return errors.New("rendezvous bundle expired")
	}
	return nil
}

// mergeDiscoveredAWGConfigFor merges the rendezvous base-AWG endpoint unless
// the stored config targets a non-base profile or an IPv6 endpoint; then the
// base config is only validated and returned unchanged (skipped=true).
func mergeDiscoveredAWGConfigFor(baseJSON string, meta provisionedConfigMeta, awg discoveredAWGEndpoint) (string, bool, error) {
	if meta.acceptsDiscoveryMerge() {
		merged, err := mergeDiscoveredAWGConfig(baseJSON, awg)
		return merged, false, err
	}
	if _, err := parseConfig(baseJSON); err != nil {
		return "", false, fmt.Errorf("base config: %w", err)
	}
	return baseJSON, true, nil
}

// configEndpointIsIPv6 reports whether a stored config's endpoint is an IPv6
// literal; parse errors are left to the merge's own validation.
func configEndpointIsIPv6(configJSON string) bool {
	var cfg config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return false
	}
	ap, err := netip.ParseAddrPort(strings.TrimSpace(cfg.Endpoint))
	return err == nil && ap.Addr().Is6() && !ap.Addr().Is4In6()
}

func mergeDiscoveredAWGConfig(baseJSON string, awg discoveredAWGEndpoint) (string, error) {
	if _, err := parseConfig(baseJSON); err != nil {
		return "", fmt.Errorf("base config: %w", err)
	}
	var base config
	if err := json.Unmarshal([]byte(baseJSON), &base); err != nil {
		return "", fmt.Errorf("parse base config json: %w", err)
	}
	base.Endpoint = endpointUsingPinnedIP(strings.TrimSpace(awg.Endpoint), awg.EgressIP)
	base.ServerPublicKey = strings.TrimSpace(awg.ServerPublicKey)
	base.AWGPreset = awg.AWGPreset
	raw, err := json.Marshal(base)
	if err != nil {
		return "", err
	}
	if _, err := parseConfig(string(raw)); err != nil {
		return "", fmt.Errorf("merged config: %w", err)
	}
	return string(raw), nil
}

// keepBaseAWGConfig validates the stored config and returns it unchanged.
func keepBaseAWGConfig(baseJSON string) (string, bool, error) {
	if _, err := parseConfig(baseJSON); err != nil {
		return "", false, fmt.Errorf("base config: %w", err)
	}
	return baseJSON, true, nil
}

func selectAWGEndpoint(endpoints []discoveredAWGEndpoint) (discoveredAWGEndpoint, error) {
	selected, _, err := selectAWGEndpointSkipping(endpoints)
	return selected, err
}

// selectAWGEndpointSkipping returns the highest-priority entry, skipping
// entries whose dialect is not a production dialect (reported in rejected).
// Other defects of the selected entry still fail as before.
func selectAWGEndpointSkipping(endpoints []discoveredAWGEndpoint) (discoveredAWGEndpoint, []awgRouteRejection, error) {
	if len(endpoints) == 0 {
		return discoveredAWGEndpoint{}, nil, errors.New("no awg endpoints in bundle")
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		return endpoints[i].Priority < endpoints[j].Priority
	})
	var rejected []awgRouteRejection
	var lastErr error
	for i, candidate := range endpoints {
		selected, err := validateAWGEndpoint(candidate)
		if err == nil {
			return selected, rejected, nil
		}
		if !errors.Is(err, errNonProductionDialect) {
			return discoveredAWGEndpoint{}, rejected, err
		}
		rejected = append(rejected, awgRouteRejection{Route: fmt.Sprintf("awg[%d]", i), Reason: err.Error()})
		lastErr = err
	}
	return discoveredAWGEndpoint{}, rejected, lastErr
}

func validateAWGEndpoint(selected discoveredAWGEndpoint) (discoveredAWGEndpoint, error) {
	if strings.TrimSpace(selected.Endpoint) == "" ||
		strings.TrimSpace(selected.ServerPublicKey) == "" {
		return discoveredAWGEndpoint{}, errors.New("selected awg endpoint is incomplete")
	}
	if _, err := base64KeyToHex(selected.ServerPublicKey); err != nil {
		return discoveredAWGEndpoint{}, fmt.Errorf("discovered server_public_key: %w", err)
	}
	if err := validatePreset(selected.AWGPreset, defaultMTU); err != nil {
		return discoveredAWGEndpoint{}, fmt.Errorf("discovered awg_preset: %w", err)
	}
	return selected, nil
}

func selectRealityEndpoint(endpoints []discoveredRealityEndpoint) *discoveredRealityEndpoint {
	if len(endpoints) == 0 {
		return nil
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		return endpoints[i].Priority < endpoints[j].Priority
	})
	return &endpoints[0]
}

// discoveryNow returns the caller-supplied validation time (the mirror's Date,
// possibly SNTP-corrected by the app) or the device clock when it is empty.
// A stale value is deliberately not rejected: it cannot revive an expired
// bundle because expiry is checked against max(now, device clock) in
// validateDiscoveredBundle, and it only makes the "not issued yet" check
// stricter. Rejecting now < device clock - N would instead break every device
// whose clock runs ahead while the app supplies SNTP-corrected time.
func discoveryNow(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return discoveryLocalNow().UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("now: %w", err)
	}
	return parsed.UTC(), nil
}

func parseRendezvousTime(value string, field string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", field, err)
	}
	return parsed.UTC(), nil
}

func rejectForbiddenDiscoveryKeys(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	return rejectForbiddenDiscoveryValue(value, "")
}

func rejectForbiddenDiscoveryValue(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
			if _, forbidden := forbiddenDiscoveryKeys[normalized]; forbidden {
				if path == "" {
					return fmt.Errorf("forbidden discovery field: %s", key)
				}
				return fmt.Errorf("forbidden discovery field: %s.%s", path, key)
			}
			nextPath := key
			if path != "" {
				nextPath = path + "." + key
			}
			if err := rejectForbiddenDiscoveryValue(child, nextPath); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range typed {
			if err := rejectForbiddenDiscoveryValue(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func encodeApplyDiscoveredResult(result applyDiscoveredResult) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"marshal apply discovered result"}`
	}
	return string(raw)
}
