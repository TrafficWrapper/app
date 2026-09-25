package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/flynn/noise"

	awgdialect "github.com/TrafficWrapper/app/core/awg/dialect"
	"github.com/TrafficWrapper/app/core/internal/provisionclient"
)

const (
	orchestratorNoisePrologue   = "TrafficWrapper orchestrator worker v1"
	publicEnrollTimeout         = 35 * time.Second
	publicEnrollIdleConnTimeout = 30 * time.Second
	// maxUntrustedErrorRunes bounds server-controlled text copied into Error.
	maxUntrustedErrorRunes = 200
	untrustedServerPrefix  = "unauthenticated server response: "
)

type publicDeviceEnrollAPIRequest struct {
	OrchestratorURL string `json:"orchestrator_url"`
	OrchNoisePublic string `json:"orch_noise_public"`
	BootstrapToken  string `json:"bootstrap_token"`
	NoisePrivateKey string `json:"noise_private_key"`
	NoisePublicKey  string `json:"noise_public_key"`
	DeviceID        string `json:"device_id,omitempty"`
	AndroidID       string `json:"android_id,omitempty"`
	Model           string `json:"model,omitempty"`
	IdentityPubKey  string `json:"identity_pubkey"`
	IdentityKeyType string `json:"identity_key_type,omitempty"`
	EnrollmentNonce string `json:"enrollment_nonce,omitempty"`
	ClientVersion   string `json:"client_version,omitempty"`
	// ClientVersionCode and ClientCapabilities are passed through to the
	// orchestrator so it can gate newer AWG profiles / Reality flows per
	// client build. Both are optional.
	ClientVersionCode  int64    `json:"client_version_code,omitempty"`
	ClientCapabilities []string `json:"client_capabilities,omitempty"`
	AWGPrivateKey      string   `json:"awg_private_key,omitempty"`
	AWGPublicKey       string   `json:"awg_public_key,omitempty"`
	TimeoutSeconds     int64    `json:"timeout_seconds,omitempty"`
	// RealityFlowAck confirms a reality_flow_pending from an earlier enroll
	// response (two-phase Vision switch). Absent = no acknowledgement.
	RealityFlowAck *string `json:"reality_flow_ack,omitempty"`
	// SOCKSProxy routes enrollment through the app's loopback SOCKS router
	// (the running tunnel) instead of a direct connection.
	SOCKSProxy string `json:"socks_proxy,omitempty"`
	// OrchTLSSPKISHA256 are the bootstrap orch_tls_spki_sha256 pins; ReEnroll
	// selects the re-enrollment TLS rule (system roots or a pin).
	OrchTLSSPKISHA256 []string `json:"orch_tls_spki_sha256,omitempty"`
	ReEnroll          bool     `json:"reenroll,omitempty"`
}

// publicAWGProfileCredentials is the per-profile device AWG record the
// orchestrator issues (orchestrator store.go deviceAWGProfile), keyed by the
// worker AWG profile name. EndpointV6 is an optional client-side override.
type publicAWGProfileCredentials struct {
	AWGPublicKey string `json:"awg_public_key,omitempty"`
	InternalIP   string `json:"internal_ip,omitempty"`
	PSK2         string `json:"psk2,omitempty"`
	EndpointV6   string `json:"endpoint_v6,omitempty"`
}

type publicDeviceEnrollAPIResult struct {
	OK              bool            `json:"ok"`
	Error           string          `json:"error,omitempty"`
	DeviceID        string          `json:"device_id,omitempty"`
	Status          string          `json:"status,omitempty"`
	RealityUUID     string          `json:"reality_uuid,omitempty"`
	InternalIP      string          `json:"internal_ip,omitempty"`
	PSK2            string          `json:"psk2,omitempty"`
	ServerAWGPublic string          `json:"server_awg_public,omitempty"`
	SignerPublicKey string          `json:"signer_public_key,omitempty"`
	ClientBundle    json.RawMessage `json:"client_bundle,omitempty"`
	AWGPrivateKey   string          `json:"awg_private_key,omitempty"`
	AWGPublicKey    string          `json:"awg_public_key,omitempty"`
	// Code is the orchestrator's structured rejection code (ok=false). Rejected
	// marks an error that came from inside the Noise channel, i.e. an
	// authenticated orchestrator decision rather than a carrier failure.
	Code     string `json:"code,omitempty"`
	Rejected bool   `json:"rejected,omitempty"`
	publicEnrollExtras
}

// publicEnrollExtras are optional enrollment fields passed through verbatim
// from the orchestrator response to the platform layer. RealityFlow is a
// pointer so an explicit "" (flow disabled) survives while an absent field
// stays absent.
type publicEnrollExtras struct {
	AWGProfiles map[string]publicAWGProfileCredentials `json:"awg_profiles,omitempty"`
	RealityFlow *string                                `json:"reality_flow,omitempty"`
	// RealityFlowPending is the flow the orchestrator will switch the device
	// to once a later enroll acknowledges it (reality_flow_ack).
	RealityFlowPending *string `json:"reality_flow_pending,omitempty"`
}

type publicDeviceEnrollWireRequest struct {
	BootstrapToken  string `json:"bootstrap_token"`
	NoisePublicKey  string `json:"noise_public_key,omitempty"`
	DeviceID        string `json:"device_id,omitempty"`
	AndroidID       string `json:"android_id,omitempty"`
	Model           string `json:"model,omitempty"`
	IdentityPubKey  string `json:"identity_pubkey"`
	IdentityKeyType string `json:"identity_key_type,omitempty"`
	EnrollmentNonce string `json:"enrollment_nonce,omitempty"`
	ClientVersion   string `json:"client_version,omitempty"`
	AWGPublicKey    string `json:"awg_public_key,omitempty"`

	ClientVersionCode  int64    `json:"client_version_code,omitempty"`
	ClientCapabilities []string `json:"client_capabilities,omitempty"`
	RealityFlowAck     *string  `json:"reality_flow_ack,omitempty"`
	// Pad is random filler (ignored by the orchestrator) that varies the size
	// of the encrypted request.
	Pad string `json:"pad,omitempty"`
}

type publicDeviceEnrollWireResponse struct {
	OK              bool            `json:"ok"`
	Error           string          `json:"error,omitempty"`
	Code            string          `json:"code,omitempty"`
	DeviceID        string          `json:"device_id,omitempty"`
	Status          string          `json:"status,omitempty"`
	RealityUUID     string          `json:"reality_uuid,omitempty"`
	InternalIP      string          `json:"internal_ip,omitempty"`
	PSK2            string          `json:"psk2,omitempty"`
	ServerAWGPublic string          `json:"server_awg_public,omitempty"`
	SignerPublicKey string          `json:"signer_public_key,omitempty"`
	ClientBundle    json.RawMessage `json:"client_bundle,omitempty"`
	publicEnrollExtras
}

type publicNoiseStartRequest struct {
	Message string `json:"message"`
	Pad     string `json:"pad,omitempty"`
}

type publicNoiseStartResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	SID     string `json:"sid,omitempty"`
	Message string `json:"message,omitempty"`
}

type publicNoiseEnvelope struct {
	SID     string `json:"sid"`
	Message string `json:"message"`
	Payload string `json:"payload"`
	Pad     string `json:"pad,omitempty"`
}

type publicNoiseEnvelopeResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Payload string `json:"payload,omitempty"`
}

type publicApplyAPIRequest struct {
	AWGPrivateKey   string   `json:"awg_private_key"`
	InternalIP      string   `json:"internal_ip"`
	PSK2            string   `json:"psk2"`
	ServerAWGPublic string   `json:"server_awg_public"`
	DNSServers      []string `json:"dns_servers,omitempty"`
	// AWGProfiles holds per-profile device credentials from enrollment; a
	// route naming a profile present here uses its internal_ip/psk2 instead
	// of the top-level ones.
	AWGProfiles      map[string]publicAWGProfileCredentials `json:"awg_profiles,omitempty"`
	AWGRU            *publicRouteSpec                       `json:"awg_ru,omitempty"`
	AWG              *publicRouteSpec                       `json:"awg,omitempty"`
	AWGRUSOCKSListen string                                 `json:"awg_ru_socks_listen,omitempty"`
	SOCKSListen      string                                 `json:"socks_listen,omitempty"`
	MTU              int                                    `json:"mtu,omitempty"`
	// RendezvousPublicKey, when set, pins (or rotates) the minisign key that
	// ApplyDiscoveredEndpoints verifies rendezvous bundles against. It must
	// come from the verified client config (discovery_pubkey), not from the
	// network response that carries a bundle.
	RendezvousPublicKey string `json:"rendezvous_public_key,omitempty"`
}

type publicApplyAPIResult struct {
	OK                bool   `json:"ok"`
	Error             string `json:"error,omitempty"`
	ConfigStored      bool   `json:"config_stored,omitempty"`
	AWGRUConfigStored bool   `json:"awg_ru_config_stored,omitempty"`
	// AWGRejected lists AWG routes skipped because their dialect is not a
	// production dialect; their previously stored config is kept.
	AWGRejected []awgRouteRejection `json:"awg_rejected,omitempty"`
}

type publicRouteSpec struct {
	Type      string          `json:"type,omitempty"`
	Address   string          `json:"address,omitempty"`
	Port      int             `json:"port,omitempty"`
	Endpoint  string          `json:"endpoint,omitempty"`
	EgressIP  string          `json:"egress_ip,omitempty"`
	LegacyIP  string          `json:"expected_egress_ip,omitempty"`
	PublicKey string          `json:"public_key,omitempty"`
	Dialect   json.RawMessage `json:"dialect,omitempty"`
	AWGPreset json.RawMessage `json:"awg_preset,omitempty"`
	// Profile / AWGProfile name the worker AWG profile (awg_profile wins).
	Profile    string `json:"profile,omitempty"`
	AWGProfile string `json:"awg_profile,omitempty"`
	// EndpointV6 is "[addr]:port"; used when IPFamily is "v6".
	EndpointV6 string `json:"endpoint_v6,omitempty"`
	IPFamily   string `json:"ip_family,omitempty"`
	// DNS overrides dns_servers for this route when it has non-blank values.
	DNS []string `json:"dns,omitempty"`
}

// PublicDeviceEnroll performs public-platform device enrollment over the
// orchestrator Noise_XK HTTP envelope. The TLS channel is only a carrier here:
// authenticity is the pinned orchestrator static key.
func PublicDeviceEnroll(requestJSON string) string {
	var req publicDeviceEnrollAPIRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return encodePublicDeviceEnrollResult(publicDeviceEnrollAPIResult{OK: false, Error: fmt.Sprintf("parse request json: %v", err)})
	}
	result, err := publicDeviceEnroll(req)
	if err != nil {
		failure := publicDeviceEnrollAPIResult{OK: false, Error: err.Error()}
		var rejected *publicEnrollRejectedError
		if errors.As(err, &rejected) {
			failure.Code = rejected.code
			failure.Rejected = true
		}
		return encodePublicDeviceEnrollResult(failure)
	}
	return encodePublicDeviceEnrollResult(result)
}

// GenerateWireGuardKeyPair returns a fresh WireGuard/AmneziaWG keypair as JSON
// so Android can seal it before public-platform enrollment retries.
func GenerateWireGuardKeyPair() string {
	privateKey, publicKey, err := provisionclient.GenerateWireGuardKeyPair()
	if err != nil {
		return encodeIdentityResult(identityAPIResult{OK: false, Error: err.Error()})
	}
	return encodeIdentityResult(identityAPIResult{OK: true, PrivateKey: privateKey, PublicKey: publicKey})
}

func ApplyPublicPlatformConfig(requestJSON string) string {
	var req publicApplyAPIRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return encodePublicApplyResult(publicApplyAPIResult{OK: false, Error: fmt.Sprintf("parse request json: %v", err)})
	}
	result, err := applyPublicPlatformConfig(req)
	if err != nil {
		return encodePublicApplyResult(publicApplyAPIResult{OK: false, Error: err.Error()})
	}
	return encodePublicApplyResult(result)
}

func publicDeviceEnroll(req publicDeviceEnrollAPIRequest) (publicDeviceEnrollAPIResult, error) {
	if req.OrchestratorURL == "" || req.OrchNoisePublic == "" || req.BootstrapToken == "" ||
		req.NoisePrivateKey == "" || req.NoisePublicKey == "" || req.IdentityPubKey == "" {
		return publicDeviceEnrollAPIResult{}, errors.New("public enrollment request is incomplete")
	}
	awgPrivate, awgPublic, err := publicEnrollAWGKeyPair(req, provisionclient.GenerateWireGuardKeyPair)
	if err != nil {
		return publicDeviceEnrollAPIResult{}, err
	}
	timeout := publicEnrollTimeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	pins, err := parsePublicTLSPins(req.OrchTLSSPKISHA256)
	if err != nil {
		return publicDeviceEnrollAPIResult{}, err
	}
	client, err := publicHTTPClientWith(publicEnrollTransportOptions{
		socksProxy: strings.TrimSpace(req.SOCKSProxy),
		spkiPins:   pins,
		reEnroll:   req.ReEnroll,
	})
	if err != nil {
		return publicDeviceEnrollAPIResult{}, err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var wireResp publicDeviceEnrollWireResponse
	err = publicNoiseJSONRequestWithClient(
		ctx,
		client,
		req.OrchestratorURL,
		req.OrchNoisePublic,
		req.NoisePrivateKey,
		req.NoisePublicKey,
		"/d/v1/enroll",
		publicDeviceEnrollWireRequest{
			BootstrapToken:  req.BootstrapToken,
			NoisePublicKey:  req.NoisePublicKey,
			DeviceID:        req.DeviceID,
			AndroidID:       req.AndroidID,
			Model:           req.Model,
			IdentityPubKey:  req.IdentityPubKey,
			IdentityKeyType: req.IdentityKeyType,
			EnrollmentNonce: req.EnrollmentNonce,
			ClientVersion:   req.ClientVersion,
			AWGPublicKey:    awgPublic,

			ClientVersionCode:  req.ClientVersionCode,
			ClientCapabilities: req.ClientCapabilities,
			RealityFlowAck:     req.RealityFlowAck,
			Pad:                publicEnrollPad(),
		},
		&wireResp,
	)
	if err != nil {
		return publicDeviceEnrollAPIResult{}, err
	}
	if !wireResp.OK {
		return publicDeviceEnrollAPIResult{}, &publicEnrollRejectedError{
			code: sanitizePublicErrorCode(wireResp.Code),
			msg:  "public device enrollment rejected: " + sanitizeUntrustedText(wireResp.Error),
		}
	}
	return publicDeviceEnrollAPIResult{
		OK:              true,
		DeviceID:        wireResp.DeviceID,
		Status:          wireResp.Status,
		RealityUUID:     wireResp.RealityUUID,
		InternalIP:      wireResp.InternalIP,
		PSK2:            wireResp.PSK2,
		ServerAWGPublic: wireResp.ServerAWGPublic,
		SignerPublicKey: wireResp.SignerPublicKey,
		ClientBundle:    wireResp.ClientBundle,
		AWGPrivateKey:   awgPrivate,
		AWGPublicKey:    awgPublic,

		publicEnrollExtras: wireResp.publicEnrollExtras,
	}, nil
}

func publicEnrollAWGKeyPair(req publicDeviceEnrollAPIRequest, generate func() (string, string, error)) (string, string, error) {
	awgPrivate := strings.TrimSpace(req.AWGPrivateKey)
	awgPublic := strings.TrimSpace(req.AWGPublicKey)
	if awgPrivate != "" && awgPublic != "" {
		return awgPrivate, awgPublic, nil
	}
	if awgPrivate != "" || awgPublic != "" {
		return "", "", errors.New("stored awg keypair is incomplete")
	}
	generatedPrivate, generatedPublic, err := generate()
	if err != nil {
		return "", "", fmt.Errorf("generate awg keypair: %w", err)
	}
	if strings.TrimSpace(generatedPrivate) == "" || strings.TrimSpace(generatedPublic) == "" {
		return "", "", errors.New("generate awg keypair returned empty key")
	}
	return generatedPrivate, generatedPublic, nil
}

// publicEnrollRejectedError is an ok=false answer decrypted from the Noise
// channel: an authenticated orchestrator decision with an optional code.
type publicEnrollRejectedError struct {
	code string
	msg  string
}

func (e *publicEnrollRejectedError) Error() string { return e.msg }

// sanitizePublicErrorCode keeps a code token ([a-z0-9_], at most 64 bytes);
// anything else is dropped so the platform falls back to the error text.
func sanitizePublicErrorCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" || len(code) > 64 {
		return ""
	}
	for _, r := range code {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return ""
		}
	}
	return code
}

func publicNoiseJSONRequest(ctx context.Context, baseURL, serverPublic, clientPrivate, clientPublic, path string, req any, resp any) error {
	client := publicHTTPClient()
	defer client.CloseIdleConnections()
	return publicNoiseJSONRequestWithClient(ctx, client, baseURL, serverPublic, clientPrivate, clientPublic, path, req, resp)
}

func publicNoiseJSONRequestWithClient(ctx context.Context, client *http.Client, baseURL, serverPublic, clientPrivate, clientPublic, path string, req any, resp any) error {
	serverPub, err := decodeKeyBase64(serverPublic)
	if err != nil {
		return fmt.Errorf("orchestrator static public key: %w", err)
	}
	clientStatic, err := provisionclient.LoadKeyPairFromBase64(clientPrivate, clientPublic)
	if err != nil {
		return fmt.Errorf("client noise keypair: %w", err)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		Prologue:      []byte(orchestratorNoisePrologue),
		StaticKeypair: clientStatic,
		PeerStatic:    serverPub,
	})
	if err != nil {
		return err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	var start publicNoiseStartResponse
	if err := postJSON(ctx, client, joinPublicURL(baseURL, "/d/v1/handshake/start"), publicNoiseStartRequest{
		Message: base64.StdEncoding.EncodeToString(msg1),
		Pad:     publicEnrollPad(),
	}, &start); err != nil {
		return err
	}
	if !start.OK {
		// Pre-handshake reply: not authenticated by Noise.
		return untrustedServerError(start.Error)
	}
	msg2, err := base64.StdEncoding.DecodeString(start.Message)
	if err != nil {
		return err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		return err
	}
	msg3, sendCipher, recvCipher, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(req)
	if err != nil {
		return err
	}
	payload, err := sendCipher.Encrypt(nil, nil, plain)
	if err != nil {
		return err
	}
	var envelope publicNoiseEnvelopeResponse
	if err := postJSON(ctx, client, joinPublicURL(baseURL, path), publicNoiseEnvelope{
		SID:     start.SID,
		Message: base64.StdEncoding.EncodeToString(msg3),
		Payload: base64.StdEncoding.EncodeToString(payload),
		Pad:     publicEnrollPad(),
	}, &envelope); err != nil {
		return err
	}
	if !envelope.OK {
		// Envelope-level error is outside the Noise payload: unauthenticated.
		return untrustedServerError(envelope.Error)
	}
	encrypted, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return err
	}
	decrypted, err := recvCipher.Decrypt(nil, nil, encrypted)
	if err != nil {
		return err
	}
	return json.Unmarshal(decrypted, resp)
}

// publicHTTPClient is the legacy carrier (direct, no certificate pin; Noise
// pins the orchestrator static key). It deliberately has no
// http.Client.Timeout: the overall deadline comes from the request context
// (timeout_seconds), so a caller asking for more than publicEnrollTimeout is
// not silently cut short.
func publicHTTPClient() *http.Client {
	client, err := publicHTTPClientWith(publicEnrollTransportOptions{})
	if err != nil {
		// Unreachable: the zero options never fail.
		return &http.Client{Transport: &http.Transport{TLSClientConfig: publicTLSConfig(publicEnrollTransportOptions{})}}
	}
	return client
}

func postJSON(ctx context.Context, client *http.Client, endpoint string, req any, resp any) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if httpResp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %w", httpResp.StatusCode, untrustedServerError(string(body)))
	}
	if err := json.Unmarshal(body, resp); err != nil {
		return err
	}
	return nil
}

// untrustedServerError wraps text the server sent outside the Noise channel.
// It is bounded, stripped of control/format characters and clearly labelled
// so the UI never shows it as an authenticated message.
func untrustedServerError(message string) error {
	return errors.New(untrustedServerPrefix + sanitizeUntrustedText(message))
}

func sanitizeUntrustedText(message string) string {
	var b strings.Builder
	runes := 0
	lastSpace := false
	for _, r := range strings.TrimSpace(message) {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			r = ' '
		}
		if r == ' ' {
			if lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		if runes == maxUntrustedErrorRunes {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		runes++
	}
	return strings.TrimSpace(b.String())
}

func joinPublicURL(base, path string) string {
	u, err := url.Parse(base)
	if err != nil {
		return strings.TrimRight(base, "/") + path
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String()
}

func applyPublicPlatformConfig(req publicApplyAPIRequest) (publicApplyAPIResult, error) {
	if req.AWGPrivateKey == "" || req.InternalIP == "" || req.PSK2 == "" || req.ServerAWGPublic == "" {
		return publicApplyAPIResult{}, errors.New("public awg credentials are incomplete")
	}
	if req.MTU == 0 {
		req.MTU = defaultMTU
	}
	if req.SOCKSListen == "" {
		req.SOCKSListen = defaultSOCKSListen
	}
	if req.AWGRUSOCKSListen == "" {
		req.AWGRUSOCKSListen = defaultAWGRUSOCKSListen
	}
	var rejected []awgRouteRejection
	// A route whose dialect fails the production policy, or that targets an
	// AWG profile without device credentials (X-M4), is skipped (its stored
	// config is kept) so REALITY and the other AWG slot still apply.
	skipDialect := func(route string, err error) bool {
		if !errors.Is(err, errNonProductionDialect) && !errors.Is(err, errAWGProfileCredentialsMissing) {
			return false
		}
		log.Printf("transport: public %s route skipped: %v", route, err)
		rejected = append(rejected, awgRouteRejection{Route: route, Reason: err.Error()})
		return true
	}
	var defaultConfigJSON string
	var defaultMeta provisionedConfigMeta
	if req.AWG != nil {
		raw, meta, err := publicAWGConfigJSON(req.AWG, req, req.SOCKSListen)
		if err != nil && !skipDialect("awg", err) {
			return publicApplyAPIResult{}, fmt.Errorf("public awg config: %w", err)
		}
		if err == nil {
			defaultConfigJSON, defaultMeta = raw, meta
		}
	}
	var awgRUConfigJSON string
	var awgRUMeta provisionedConfigMeta
	if req.AWGRU != nil {
		raw, meta, err := publicAWGConfigJSON(req.AWGRU, req, req.AWGRUSOCKSListen)
		if err != nil && !skipDialect("awg_ru", err) {
			return publicApplyAPIResult{}, fmt.Errorf("public awg-ru config: %w", err)
		}
		if err == nil {
			awgRUConfigJSON, awgRUMeta = raw, meta
		}
	}
	if strings.TrimSpace(req.RendezvousPublicKey) != "" {
		// Replace is allowed: this request carries the currently verified
		// signed client config, which is where key rotation comes from.
		if err := pinRendezvousPublicKey(req.RendezvousPublicKey, true); err != nil {
			return publicApplyAPIResult{}, fmt.Errorf("rendezvous_public_key: %w", err)
		}
	}
	// A request that omits a route must not wipe the config stored for it
	// (e.g. an awg_ru-only refresh must keep the main awg config).
	pendingProvision.Lock()
	if defaultConfigJSON != "" {
		pendingProvision.configJSON = defaultConfigJSON
		pendingProvision.configMeta = defaultMeta
	}
	if awgRUConfigJSON != "" {
		pendingProvision.awgRUConfigJSON = awgRUConfigJSON
		pendingProvision.awgRUConfigMeta = awgRUMeta
	}
	pendingProvision.Unlock()
	return publicApplyAPIResult{
		OK:                true,
		ConfigStored:      defaultConfigJSON != "",
		AWGRUConfigStored: awgRUConfigJSON != "",
		AWGRejected:       rejected,
	}, nil
}

func publicAWGConfigJSON(route *publicRouteSpec, req publicApplyAPIRequest, socksListen string) (string, provisionedConfigMeta, error) {
	profile := route.profileName()
	internalIP, psk2 := req.InternalIP, req.PSK2
	var profileCreds *publicAWGProfileCredentials
	if !isBaseAWGProfile(profile) {
		creds, ok := req.AWGProfiles[profile]
		if !ok {
			// The base internal_ip/psk2 belong to the base profile only: the
			// worker has no peer for them on another profile (X-M4).
			return "", provisionedConfigMeta{}, fmt.Errorf("%w: %q", errAWGProfileCredentialsMissing, profile)
		}
		if strings.TrimSpace(creds.InternalIP) == "" || strings.TrimSpace(creds.PSK2) == "" {
			return "", provisionedConfigMeta{}, fmt.Errorf("awg_profiles[%q] credentials are incomplete", profile)
		}
		internalIP, psk2 = strings.TrimSpace(creds.InternalIP), strings.TrimSpace(creds.PSK2)
		profileCreds = &creds
	}
	endpoint, v6, err := route.endpointFor(profileCreds)
	if err != nil {
		return "", provisionedConfigMeta{}, err
	}
	serverKey := strings.TrimSpace(route.PublicKey)
	if serverKey == "" {
		serverKey = req.ServerAWGPublic
	}
	presetValue, err := route.preset()
	if err != nil {
		return "", provisionedConfigMeta{}, err
	}
	dnsServers, err := route.dnsServers(req.DNSServers)
	if err != nil {
		return "", provisionedConfigMeta{}, err
	}
	cfg := config{
		PrivateKey:      req.AWGPrivateKey,
		InternalIP:      internalIP,
		Endpoint:        endpoint,
		ServerPublicKey: serverKey,
		PSK2:            psk2,
		AWGPreset:       presetValue,
		SOCKSListen:     socksListen,
		MTU:             req.MTU,
		DNSServers:      dnsServers,
	}
	raw, err := validatedConfigJSON(cfg)
	if err != nil {
		return "", provisionedConfigMeta{}, err
	}
	return raw, provisionedConfigMeta{profile: profile, v6: v6}, nil
}

// errAWGProfileCredentialsMissing: a route names a non-base AWG profile the
// device holds no awg_profiles credentials for.
var errAWGProfileCredentialsMissing = errors.New("no device credentials for awg profile")

// profileName returns the worker AWG profile this route targets; awg_profile
// wins over the older profile key.
func (r *publicRouteSpec) profileName() string {
	if value := strings.TrimSpace(r.AWGProfile); value != "" {
		return value
	}
	return strings.TrimSpace(r.Profile)
}

// isBaseAWGProfile reports whether a profile name means the worker's base AWG
// inbound, which uses the top-level device credentials.
func isBaseAWGProfile(profile string) bool {
	return profile == "" || profile == "awg"
}

// endpointFor picks the peer endpoint: the IPv6 one when ip_family is "v6"
// and an IPv6 endpoint is known (a per-profile endpoint_v6 wins over the
// route's), otherwise the IPv4 endpoint. The bool reports an IPv6 choice.
func (r *publicRouteSpec) endpointFor(profile *publicAWGProfileCredentials) (string, bool, error) {
	if strings.EqualFold(strings.TrimSpace(r.IPFamily), "v6") {
		v6 := strings.TrimSpace(r.EndpointV6)
		if profile != nil && strings.TrimSpace(profile.EndpointV6) != "" {
			v6 = strings.TrimSpace(profile.EndpointV6)
		}
		if v6 != "" {
			endpoint, err := r.normalizeEndpointV6(v6)
			if err != nil {
				return "", false, err
			}
			return endpoint, true, nil
		}
	}
	endpoint := strings.TrimSpace(r.Endpoint)
	if endpoint == "" && r.Address != "" && r.Port > 0 {
		endpoint = net.JoinHostPort(strings.Trim(strings.TrimSpace(r.Address), "[]"), strconv.Itoa(r.Port))
	}
	return endpointUsingPinnedIP(endpoint, r.egressIP()), false, nil
}

// normalizeEndpointV6 accepts "[addr]:port" (the worker's format) or a bare
// IPv6 address combined with the route port.
func (r *publicRouteSpec) normalizeEndpointV6(value string) (string, error) {
	if ap, err := netip.ParseAddrPort(value); err == nil {
		if !ap.Addr().Is6() || ap.Addr().Is4In6() || ap.Port() == 0 {
			return "", fmt.Errorf("endpoint_v6 %q must be an IPv6 [addr]:port", value)
		}
		return ap.String(), nil
	}
	if addr, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil && addr.Is6() && !addr.Is4In6() && r.Port > 0 && r.Port <= 65535 {
		return netip.AddrPortFrom(addr, uint16(r.Port)).String(), nil
	}
	return "", fmt.Errorf("endpoint_v6 %q must be an IPv6 [addr]:port", value)
}

// dnsServers returns the route's own DNS servers when it lists any non-blank
// value (all must be IP literals), otherwise the request-wide fallback.
func (r *publicRouteSpec) dnsServers(fallback []string) ([]string, error) {
	out := make([]string, 0, len(r.DNS))
	for _, value := range r.DNS {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, err := netip.ParseAddr(value); err != nil {
			return nil, fmt.Errorf("route dns %q is not an IP address", value)
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return fallback, nil
	}
	return out, nil
}

func endpointUsingPinnedIP(endpoint string, ip string) string {
	endpoint = strings.TrimSpace(endpoint)
	ip = strings.TrimSpace(ip)
	if endpoint == "" || ip == "" {
		return endpoint
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return endpoint
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || port == "" {
		return endpoint
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return endpoint
	}
	return net.JoinHostPort(ip, port)
}

func (r *publicRouteSpec) egressIP() string {
	if value := strings.TrimSpace(r.EgressIP); value != "" {
		return value
	}
	return strings.TrimSpace(r.LegacyIP)
}

func (r *publicRouteSpec) preset() (preset, error) {
	raw := r.AWGPreset
	if len(raw) == 0 {
		raw = r.Dialect
	}
	if len(raw) == 0 || string(raw) == "null" {
		return awgdialect.Compat(), nil
	}
	var out preset
	if err := json.Unmarshal(raw, &out); err != nil {
		return preset{}, fmt.Errorf("awg dialect: %w", err)
	}
	return out, nil
}

func encodePublicDeviceEnrollResult(result publicDeviceEnrollAPIResult) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"marshal public enroll result"}`
	}
	return string(raw)
}

func encodePublicApplyResult(result publicApplyAPIResult) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"marshal public apply result"}`
	}
	return string(raw)
}
