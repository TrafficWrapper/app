package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
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

// Size limits for ApplyDiscoveredEndpoints input. A signed rendezvous feed is a
// few KiB; the caps bound what an oversized (even validly signed) payload can
// make the phone allocate while decoding and walking it.
const (
	maxDiscoveryRequestBytes    = 1 << 20
	maxDiscoveryBundleBytes     = 256 << 10
	maxDiscoveryBaseConfigBytes = 256 << 10
	maxDiscoveryMinisigBytes    = 16 << 10
)

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
	// BaseSlot identifies the worker behind base_config_json. Optional: a
	// caller-supplied base without it keeps the legacy top-priority merge.
	BaseSlot *discoverySlotIdentity `json:"base_slot,omitempty"`
	// RealitySlot / Reality2Slot identify the workers of the REALITY slots.
	// A REALITY feed entry is returned only when it matches one of them, so
	// another worker's egress never becomes a slot's expected egress (X-M6).
	RealitySlot  *discoverySlotIdentity `json:"reality_slot,omitempty"`
	Reality2Slot *discoverySlotIdentity `json:"reality2_slot,omitempty"`
}

// discoverySlotIdentity is what a route slot knows about its worker: the
// client-bundle worker id and the expected egress IP (either may be empty).
type discoverySlotIdentity struct {
	WorkerID string `json:"worker_id,omitempty"`
	EgressIP string `json:"egress_ip,omitempty"`
}

// matches reports whether a feed entry belongs to the slot's worker: by
// worker_id when both sides carry one, otherwise by an equal egress IP.
func (s discoverySlotIdentity) matches(workerID, egressIP string) bool {
	slotWorker, entryWorker := strings.TrimSpace(s.WorkerID), strings.TrimSpace(workerID)
	if slotWorker != "" && entryWorker != "" {
		return slotWorker == entryWorker
	}
	slotEgress, ok := canonicalIP(s.EgressIP)
	if !ok {
		return false
	}
	entryEgress, ok := canonicalIP(egressIP)
	return ok && slotEgress == entryEgress
}

func canonicalIP(value string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
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
	WorkerID        string `json:"worker_id,omitempty"`
	Endpoint        string `json:"endpoint"`
	EgressIP        string `json:"egress_ip,omitempty"`
	ServerPublicKey string `json:"server_public_key"`
	AWGPreset       preset `json:"awg_preset"`
}

type discoveredRealityEndpoint struct {
	Priority    int    `json:"priority"`
	WorkerID    string `json:"worker_id,omitempty"`
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
	// AWGMergedSlots lists the stored slots ("awg_ru", "awg") whose config
	// was replaced by the entry of the same worker.
	AWGMergedSlots []string `json:"awg_merged_slots,omitempty"`
	// EgressIP / Reality belong to the entry matching reality_slot; Reality2
	// to the one matching reality2_slot. Absent when nothing matched.
	EgressIP string                     `json:"egress_ip,omitempty"`
	Reality  *discoveredRealityEndpoint `json:"reality,omitempty"`
	Reality2 *discoveredRealityEndpoint `json:"reality2,omitempty"`
}

func ApplyDiscoveredEndpoints(requestJSON string) string {
	result, err := applyDiscoveredEndpoints(requestJSON)
	if err != nil {
		return encodeApplyDiscoveredResult(applyDiscoveredResult{OK: false, Error: err.Error()})
	}
	return encodeApplyDiscoveredResult(result)
}

func applyDiscoveredEndpoints(requestJSON string) (applyDiscoveredResult, error) {
	if len(requestJSON) > maxDiscoveryRequestBytes {
		return applyDiscoveredResult{}, fmt.Errorf("discovery request too large: %d bytes", len(requestJSON))
	}
	var req applyDiscoveredRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return applyDiscoveredResult{}, fmt.Errorf("parse request json: %w", err)
	}
	if strings.TrimSpace(req.EndpointsJSON) == "" {
		return applyDiscoveredResult{}, errors.New("endpoints_json is required")
	}
	if len(req.EndpointsJSON) > maxDiscoveryBundleBytes {
		return applyDiscoveredResult{}, fmt.Errorf("endpoints_json too large: %d bytes", len(req.EndpointsJSON))
	}
	if len(req.BaseConfigJSON) > maxDiscoveryBaseConfigBytes {
		return applyDiscoveredResult{}, fmt.Errorf("base_config_json too large: %d bytes", len(req.BaseConfigJSON))
	}
	signature := firstNonEmpty(req.EndpointsJSONMinisig, req.Minisig)
	if strings.TrimSpace(signature) == "" {
		return applyDiscoveredResult{}, errors.New("endpoints minisig is required")
	}
	if len(signature) > maxDiscoveryMinisigBytes {
		return applyDiscoveredResult{}, fmt.Errorf("endpoints minisig too large: %d bytes", len(signature))
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
	// Every client version needs at least one AWG entry (reduced and full feeds).
	if len(bundle.Endpoints.AWG) == 0 {
		return applyDiscoveredResult{}, errors.New("no awg endpoints in bundle")
	}
	result := applyDiscoveredResult{OK: true, Seq: bundle.Seq}
	if req.BaseConfigJSON != "" {
		// Caller-supplied base: a pure function of the request. The shared
		// provisioned config is neither read nor overwritten. Without stored
		// metadata only the endpoint family can be checked.
		var awg discoveredAWGEndpoint
		matched := true
		if req.BaseSlot != nil {
			awg, matched, err = matchDiscoveredAWGEndpoint(bundle.Endpoints.AWG, *req.BaseSlot)
		} else {
			awg, err = selectAWGEndpoint(bundle.Endpoints.AWG)
		}
		if err != nil {
			return applyDiscoveredResult{}, err
		}
		mergedJSON, mergeSkipped := req.BaseConfigJSON, !matched
		if matched {
			meta := provisionedConfigMeta{v6: configEndpointIsIPv6(req.BaseConfigJSON)}
			mergedJSON, mergeSkipped, err = mergeDiscoveredAWGConfigFor(req.BaseConfigJSON, meta, awg)
		} else if _, err = parseConfig(req.BaseConfigJSON); err != nil {
			err = fmt.Errorf("base config: %w", err)
		}
		if err == nil {
			err = recordDiscoveredSeq(pubkey, bundle.Seq)
		}
		if err != nil {
			return applyDiscoveredResult{}, err
		}
		result.ConfigJSON, result.AWGMergeSkipped = mergedJSON, mergeSkipped
	} else {
		// Read, merge and write back in one critical section so a concurrent
		// ApplyPublicPlatformConfig / ApplyDiscoveredEndpoints cannot be lost.
		pendingProvision.Lock()
		merged, err := mergeDiscoveredIntoProvisionedSlots(bundle.Endpoints.AWG)
		if err == nil {
			err = recordDiscoveredSeq(pubkey, bundle.Seq)
		}
		if err == nil {
			merged.store()
		}
		pendingProvision.Unlock()
		if err != nil {
			return applyDiscoveredResult{}, err
		}
		result.ConfigJSON = merged.configJSON()
		result.AWGMergeSkipped = merged.skipped
		result.AWGMergedSlots = merged.slots
	}
	if req.RealitySlot != nil {
		if reality := matchDiscoveredRealityEndpoint(bundle.Endpoints.Reality, *req.RealitySlot); reality != nil {
			result.Reality = reality
			result.EgressIP = reality.EgressIP
		}
	}
	if req.Reality2Slot != nil {
		result.Reality2 = matchDiscoveredRealityEndpoint(bundle.Endpoints.Reality, *req.Reality2Slot)
	}
	return result, nil
}

// provisionedSlotMerge is the outcome of merging a feed into the stored AWG
// slots; it is computed and stored under pendingProvision's lock.
type provisionedSlotMerge struct {
	awgRU, awg       string
	awgRUSet, awgSet bool
	skipped          bool
	slots            []string
}

// mergeDiscoveredIntoProvisionedSlots matches feed entries to the stored
// AWG_RU (primary) and AWG (secondary) slots by their worker and merges each
// match into its own slot. A slot without a matching entry is left alone:
// the top-priority entry of another worker is never forced into it.
// Caller holds pendingProvision's lock.
func mergeDiscoveredIntoProvisionedSlots(entries []discoveredAWGEndpoint) (provisionedSlotMerge, error) {
	out := provisionedSlotMerge{awgRU: pendingProvision.awgRUConfigJSON, awg: pendingProvision.configJSON}
	if out.awg == "" && out.awgRU == "" {
		return provisionedSlotMerge{}, errors.New("provisioned config is missing")
	}
	type slot struct {
		name   string
		config string
		meta   provisionedConfigMeta
		dst    *string
		set    *bool
	}
	for _, s := range []slot{
		{"awg_ru", pendingProvision.awgRUConfigJSON, pendingProvision.awgRUConfigMeta, &out.awgRU, &out.awgRUSet},
		{"awg", pendingProvision.configJSON, pendingProvision.configMeta, &out.awg, &out.awgSet},
	} {
		if s.config == "" {
			continue
		}
		awg, matched, err := matchDiscoveredAWGEndpoint(entries, s.meta.slot)
		if err != nil {
			return provisionedSlotMerge{}, fmt.Errorf("%s: %w", s.name, err)
		}
		if !matched {
			continue
		}
		merged, skipped, err := mergeDiscoveredAWGConfigFor(s.config, s.meta, awg)
		if err != nil {
			return provisionedSlotMerge{}, fmt.Errorf("%s: %w", s.name, err)
		}
		if skipped {
			out.skipped = true
			continue
		}
		*s.dst, *s.set = merged, true
		out.slots = append(out.slots, s.name)
	}
	return out, nil
}

// store writes merged slots back. Caller holds pendingProvision's lock.
func (m provisionedSlotMerge) store() {
	if m.awgRUSet {
		pendingProvision.awgRUConfigJSON = m.awgRU
	}
	if m.awgSet {
		pendingProvision.configJSON = m.awg
	}
}

// configJSON is the config reported to the caller (diagnostics): a merged
// slot (primary first), otherwise the stored secondary, then primary, as-is.
func (m provisionedSlotMerge) configJSON() string {
	switch {
	case m.awgRUSet:
		return m.awgRU
	case m.awgSet, m.awg != "":
		return m.awg
	default:
		return m.awgRU
	}
}

// matchDiscoveredAWGEndpoint returns the top-priority entry of the slot's
// worker. A slot with no identity matches nothing. The matched entry must be
// complete; unrelated entries are not validated here.
func matchDiscoveredAWGEndpoint(entries []discoveredAWGEndpoint, slot discoverySlotIdentity) (discoveredAWGEndpoint, bool, error) {
	var candidates []discoveredAWGEndpoint
	for _, entry := range entries {
		if slot.matches(entry.WorkerID, entry.EgressIP) {
			candidates = append(candidates, entry)
		}
	}
	if len(candidates) == 0 {
		return discoveredAWGEndpoint{}, false, nil
	}
	selected, err := selectAWGEndpoint(candidates)
	if err != nil {
		return discoveredAWGEndpoint{}, false, err
	}
	return selected, true, nil
}

// matchDiscoveredRealityEndpoint returns the top-priority REALITY entry of the
// slot's worker with a valid egress IP, or nil. An empty list (reduced feed)
// never matches, so the expected egress stays untouched.
func matchDiscoveredRealityEndpoint(entries []discoveredRealityEndpoint, slot discoverySlotIdentity) *discoveredRealityEndpoint {
	var candidates []discoveredRealityEndpoint
	for _, entry := range entries {
		if _, ok := canonicalIP(entry.EgressIP); !ok {
			continue
		}
		if slot.matches(entry.WorkerID, entry.EgressIP) {
			candidates = append(candidates, entry)
		}
	}
	return selectRealityEndpoint(candidates)
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

func selectAWGEndpoint(endpoints []discoveredAWGEndpoint) (discoveredAWGEndpoint, error) {
	if len(endpoints) == 0 {
		return discoveredAWGEndpoint{}, errors.New("no awg endpoints in bundle")
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		return endpoints[i].Priority < endpoints[j].Priority
	})
	selected := endpoints[0]
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
	if path := forbiddenDiscoveryPath(value); path != nil {
		return fmt.Errorf("forbidden discovery field: %s", formatDiscoveryPath(path))
	}
	return nil
}

// forbiddenDiscoveryPath returns the path to the first forbidden key, leaf
// first, or nil. The path is only built while unwinding from a hit, so a clean
// document costs no per-key allocations regardless of its shape.
func forbiddenDiscoveryPath(value any) []string {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
			if _, forbidden := forbiddenDiscoveryKeys[normalized]; forbidden {
				return []string{key}
			}
			if path := forbiddenDiscoveryPath(child); path != nil {
				return append(path, key)
			}
		}
	case []any:
		for i, child := range typed {
			if path := forbiddenDiscoveryPath(child); path != nil {
				return append(path, "["+strconv.Itoa(i)+"]")
			}
		}
	}
	return nil
}

// formatDiscoveryPath renders a leaf-first path as root.key[0].leaf.
func formatDiscoveryPath(leafFirst []string) string {
	var b strings.Builder
	for i := len(leafFirst) - 1; i >= 0; i-- {
		segment := leafFirst[i]
		if b.Len() > 0 && !strings.HasPrefix(segment, "[") {
			b.WriteByte('.')
		}
		b.WriteString(segment)
	}
	return b.String()
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
