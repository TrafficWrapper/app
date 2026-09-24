package transport

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"aead.dev/minisign"

	awgdialect "github.com/TrafficWrapper/app/core/awg/dialect"
)

func init() {
	// Fixtures use fixed 2026-06-13 timestamps; pin the device clock before
	// them so expiry is decided by the supplied now.
	discoveryLocalNow = func() time.Time { return time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC) }
}

func TestApplyDiscoveredEndpointsMergesAWGWithStoredSecrets(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	base := testBaseConfig(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	req := signer.request(t, bundle, base, 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if !result.OK {
		t.Fatalf("ApplyDiscoveredEndpoints failed: %s", result.Error)
	}
	if result.Seq != 10 {
		t.Fatalf("seq=%d, want 10", result.Seq)
	}
	if result.EgressIP != "203.0.113.77" {
		t.Fatalf("egress_ip=%q", result.EgressIP)
	}
	if _, err := parseConfig(result.ConfigJSON); err != nil {
		t.Fatalf("merged config does not parse: %v\n%s", err, result.ConfigJSON)
	}
	var merged config
	if err := json.Unmarshal([]byte(result.ConfigJSON), &merged); err != nil {
		t.Fatal(err)
	}
	var original config
	if err := json.Unmarshal([]byte(base), &original); err != nil {
		t.Fatal(err)
	}
	if merged.PrivateKey != original.PrivateKey {
		t.Fatal("private_key was not preserved")
	}
	if merged.PSK2 != original.PSK2 {
		t.Fatal("psk2 was not preserved")
	}
	if merged.InternalIP != original.InternalIP {
		t.Fatal("internal_ip was not preserved")
	}
	if merged.Endpoint != "198.51.100.50:51821" {
		t.Fatalf("endpoint=%q", merged.Endpoint)
	}
	if merged.ServerPublicKey != testDiscoveredServerKey {
		t.Fatalf("server_public_key=%q", merged.ServerPublicKey)
	}
	if !awgdialect.IsCompat(merged.AWGPreset) {
		t.Fatalf("awg_preset was not applied: %+v", merged.AWGPreset)
	}
	if merged.MTU != original.MTU {
		t.Fatalf("mtu=%d, want original %d", merged.MTU, original.MTU)
	}
}

func TestApplyDiscoveredEndpointsRejectsTamperedSignedBundle(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	message := mustJSON(t, bundle)
	signature := signer.sign(message)
	tampered := strings.Replace(message, "198.51.100.50", "198.51.100.51", 1)
	req := requestJSON(t, signer.publicKey, tampered, signature, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "invalid signature") {
		t.Fatalf("tampered bundle accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsHostnameAWGWithoutEgressIP(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	base := testBaseConfig(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	awg := bundle["endpoints"].(map[string]any)["awg"].([]any)[0].(map[string]any)
	delete(awg, "egress_ip")
	req := signer.request(t, bundle, base, 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK {
		t.Fatal("hostname AWG endpoint without egress_ip was accepted")
	}
	if !strings.Contains(result.Error, "must be an IP literal") {
		t.Fatalf("error=%q want IP literal failure", result.Error)
	}
}

func TestApplyDiscoveredEndpointsRejectsWrongSignature(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	other := newTestSigner(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	message := mustJSON(t, bundle)
	req := requestJSON(t, signer.publicKey, message, other.sign(message), testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "invalid signature") {
		t.Fatalf("wrong signature accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsUsesPinnedKeyWhenRequestOmitsIt(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	message := mustJSON(t, bundle)
	req := requestJSON(t, "", message, signer.sign(message), testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if !result.OK {
		t.Fatalf("pinned key was not used: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRequiresPinnedKey(t *testing.T) {
	signer := newTestSigner(t)
	resetDiscoveryTrust(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	// The request carries the bundle's own signer key: that must not be
	// enough on its own.
	req := signer.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "not pinned") {
		t.Fatalf("request-supplied key trusted without pin or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsRequestKeyDifferentFromPinned(t *testing.T) {
	pinned := newTestSigner(t)
	pinTestSigner(t, pinned)
	attacker := newTestSigner(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	req := attacker.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "does not match pinned key") {
		t.Fatalf("foreign key accepted or wrong error: %+v", result)
	}
	// Signed by the attacker but claiming the pinned key: signature check fails.
	message := mustJSON(t, bundle)
	req = requestJSON(t, pinned.publicKey, message, attacker.sign(message), testBaseConfig(t), 9, "2026-06-13T12:00:00Z")
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req)); result.OK {
		t.Fatal("bundle signed by a foreign key accepted")
	}
}

func TestSetRendezvousPublicKeyRefusesToReplacePinnedKey(t *testing.T) {
	first := newTestSigner(t)
	resetDiscoveryTrust(t)
	if got := decodeMinisignResult(t, SetRendezvousPublicKey(first.publicKey)); !got.OK {
		t.Fatalf("pinning failed: %+v", got)
	}
	if got := decodeMinisignResult(t, SetRendezvousPublicKey("  "+first.publicKey+"\n")); !got.OK {
		t.Fatalf("re-pinning same key failed: %+v", got)
	}
	second := newTestSigner(t)
	if got := decodeMinisignResult(t, SetRendezvousPublicKey(second.publicKey)); got.OK {
		t.Fatal("different key replaced pinned key")
	}
	if got := decodeMinisignResult(t, SetRendezvousPublicKey("garbage")); got.OK {
		t.Fatal("invalid key accepted")
	}
	if got := decodeMinisignResult(t, SetRendezvousPublicKey("")); got.OK {
		t.Fatal("empty key accepted")
	}
}

func TestApplyPublicPlatformConfigPinsAndRotatesRendezvousKey(t *testing.T) {
	first := newTestSigner(t)
	resetDiscoveryTrust(t)
	setPendingProvision(t, "", "")
	req := testPublicApplyRequest()
	req.RendezvousPublicKey = first.publicKey
	if _, err := applyPublicPlatformConfig(req); err != nil {
		t.Fatal(err)
	}
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(first.request(t, bundle, "", 0, "2026-06-13T12:00:00Z"))); !result.OK {
		t.Fatalf("bundle under key pinned by ApplyPublicPlatformConfig rejected: %+v", result)
	}

	// A signed client config update may rotate discovery_pubkey.
	second := newTestSigner(t)
	req.RendezvousPublicKey = second.publicKey
	if _, err := applyPublicPlatformConfig(req); err != nil {
		t.Fatal(err)
	}
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(first.request(t, bundle, "", 0, "2026-06-13T12:00:00Z"))); result.OK {
		t.Fatal("old key still trusted after rotation")
	}
	older := testBundle(t, 3, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(second.request(t, older, "", 0, "2026-06-13T12:00:00Z"))); !result.OK {
		t.Fatalf("new key starts a new seq space, got: %+v", result)
	}

	// Omitting the field keeps the pin.
	req.RendezvousPublicKey = ""
	if _, err := applyPublicPlatformConfig(req); err != nil {
		t.Fatal(err)
	}
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(second.request(t, older, "", 0, "2026-06-13T12:00:00Z"))); !result.OK {
		t.Fatalf("pin lost when rendezvous_public_key omitted: %+v", result)
	}

	req.RendezvousPublicKey = "garbage"
	if _, err := applyPublicPlatformConfig(req); err == nil {
		t.Fatal("invalid rendezvous_public_key accepted")
	}
}

func TestApplyDiscoveredEndpointsRemembersMaxSeenSeq(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	newer := testBundle(t, 20, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, newer, testBaseConfig(t), 0, "2026-06-13T12:00:00Z"))); !result.OK {
		t.Fatalf("newer bundle rejected: %+v", result)
	}
	// Caller forgot (or lost) its persisted max_seen_seq: core still refuses.
	older := testBundle(t, 15, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, older, testBaseConfig(t), 0, "2026-06-13T12:00:00Z")))
	if result.OK || !strings.Contains(result.Error, "rollback") {
		t.Fatalf("rollback below stored max_seen_seq accepted: %+v", result)
	}
	// Same seq is still accepted (idempotent re-apply).
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, newer, testBaseConfig(t), 0, "2026-06-13T12:00:00Z"))); !result.OK {
		t.Fatalf("re-applying same seq rejected: %+v", result)
	}
	// A caller-supplied higher bound still wins over the in-process one.
	newest := testBundle(t, 25, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	result = decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, newest, testBaseConfig(t), 30, "2026-06-13T12:00:00Z")))
	if result.OK || !strings.Contains(result.Error, "rollback") {
		t.Fatalf("caller max_seen_seq ignored: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsFailureDoesNotAdvanceSeq(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bad := testBundle(t, 50, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	bad["endpoints"].(map[string]any)["awg"].([]any)[0].(map[string]any)["egress_ip"] = ""
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, bad, testBaseConfig(t), 0, "2026-06-13T12:00:00Z"))); result.OK {
		t.Fatal("unmergeable bundle accepted")
	}
	good := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, good, testBaseConfig(t), 0, "2026-06-13T12:00:00Z"))); !result.OK {
		t.Fatalf("failed apply advanced max seq: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsDefaultsNowToDeviceClock(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	old := discoveryLocalNow
	discoveryLocalNow = func() time.Time { return time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC) }
	defer func() { discoveryLocalNow = old }()
	expired := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T11:00:00Z")
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, expired, testBaseConfig(t), 0, "")))
	if result.OK || !strings.Contains(result.Error, "expired") {
		t.Fatalf("expired bundle accepted without now or wrong error: %+v", result)
	}
	valid := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, valid, testBaseConfig(t), 0, ""))); !result.OK {
		t.Fatalf("valid bundle rejected without now: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsCallerBaseDoesNotTouchPendingProvision(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	stored := setPendingProvision(t, testBaseConfig(t), "")
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, bundle, testBaseConfig(t), 0, "2026-06-13T12:00:00Z")))
	if !result.OK {
		t.Fatalf("apply failed: %+v", result)
	}
	pendingProvision.Lock()
	got := pendingProvision.configJSON
	pendingProvision.Unlock()
	if got != stored {
		t.Fatal("caller-supplied base_config_json overwrote pendingProvision")
	}
}

func TestApplyDiscoveredEndpointsUsesAndUpdatesPendingProvision(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	setPendingProvision(t, testBaseConfig(t), "")
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	req := signer.request(t, bundle, "", 0, "2026-06-13T12:00:00Z")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req)); !result.OK {
				t.Errorf("apply failed: %+v", result)
			}
		}()
		go func() {
			defer wg.Done()
			_, _ = applyPublicPlatformConfig(testPublicApplyRequest())
		}()
	}
	wg.Wait()
	// Final state must be one of the two whole writes, never a torn mix.
	pendingProvision.Lock()
	got := pendingProvision.configJSON
	pendingProvision.Unlock()
	if _, err := parseConfig(got); err != nil {
		t.Fatalf("pending config invalid: %v", err)
	}
	if result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req)); !result.OK {
		t.Fatalf("apply failed: %+v", result)
	}
	pendingProvision.Lock()
	got = pendingProvision.configJSON
	pendingProvision.Unlock()
	var merged config
	if err := json.Unmarshal([]byte(got), &merged); err != nil {
		t.Fatal(err)
	}
	if merged.Endpoint != "198.51.100.50:51821" || merged.PrivateKey != testKey(1) {
		t.Fatalf("pending config not merged: endpoint=%q", merged.Endpoint)
	}
}

func TestApplyDiscoveredEndpointsMissingProvisionedConfig(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	setPendingProvision(t, "", "")
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, bundle, "", 0, "2026-06-13T12:00:00Z")))
	if result.OK || !strings.Contains(result.Error, "provisioned config is missing") {
		t.Fatalf("got %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsExpiredBundle(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T11:00:00Z")
	req := signer.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "expired") {
		t.Fatalf("expired bundle accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsRollback(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bundle := testBundle(t, 9, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	req := signer.request(t, bundle, testBaseConfig(t), 10, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "rollback") {
		t.Fatalf("rollback bundle accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsWrongNamespace(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	bundle["ns"] = "version-v1"
	req := signer.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "namespace") {
		t.Fatalf("wrong namespace accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsPublicBundleSecrets(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	awg := bundle["endpoints"].(map[string]any)["awg"].([]any)[0].(map[string]any)
	awg["psk2"] = testKey(8)
	req := signer.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "forbidden discovery field") {
		t.Fatalf("secret-bearing bundle accepted or wrong error: %+v", result)
	}
}

type testSigner struct {
	publicKey  string
	privateKey minisign.PrivateKey
}

func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{publicKey: string(rawPub), privateKey: priv}
}

func (s testSigner) sign(message string) string {
	return string(minisign.SignWithComments(
		s.privateKey,
		[]byte(message),
		"test rendezvous fixture",
		"signature from test key",
	))
}

func (s testSigner) request(t *testing.T, bundle map[string]any, baseConfig string, maxSeen int64, now string) string {
	t.Helper()
	message := mustJSON(t, bundle)
	return requestJSON(t, s.publicKey, message, s.sign(message), baseConfig, maxSeen, now)
}

func requestJSON(t *testing.T, publicKey, endpointsJSON, signature, baseConfig string, maxSeen int64, now string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"endpoints_json":         endpointsJSON,
		"endpoints_json_minisig": signature,
		"public_key":             publicKey,
		"base_config_json":       baseConfig,
		"max_seen_seq":           maxSeen,
		"now":                    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func decodeApplyResult(t *testing.T, raw string) applyDiscoveredResult {
	t.Helper()
	var result applyDiscoveredResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("decode apply result %s: %v", raw, err)
	}
	return result
}

func testBundle(t *testing.T, seq int64, issuedAt string, expiresAt string) map[string]any {
	t.Helper()
	return map[string]any{
		"schema":     2,
		"ns":         "rendezvous-v1",
		"seq":        seq,
		"issued_at":  issuedAt,
		"expires_at": expiresAt,
		"endpoints": map[string]any{
			"awg": []any{
				map[string]any{
					"priority":          0,
					"endpoint":          "worker.example:51821",
					"egress_ip":         "198.51.100.50",
					"server_public_key": testDiscoveredServerKey,
					"awg_preset":        awgdialect.Compat(),
				},
			},
			"reality": []any{
				map[string]any{
					"priority":    0,
					"transport":   "xray-vless-reality-vision",
					"address":     "tw.example.test",
					"egress_ip":   "203.0.113.77",
					"port":        443,
					"uuid":        "f60fc87e-691f-490c-999c-8313881742cc",
					"flow":        "xtls-rprx-vision",
					"security":    "reality",
					"network":     "tcp",
					"serverName":  "tw.example.test",
					"publicKey":   "4nkiNFwR_CaD1I4TSDpwnOECstRmPXj21CtitT3AgzA",
					"shortId":     "d713c2142c5b9035",
					"fingerprint": "chrome",
					"spiderX":     "/",
				},
			},
		},
	}
}

func testBaseConfig(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(config{
		PrivateKey:      testKey(1),
		InternalIP:      "10.13.13.42/32",
		Endpoint:        "203.0.113.10:51821",
		ServerPublicKey: testKey(2),
		PSK2:            testKey(3),
		AWGPreset:       awgdialect.Compat(),
		SOCKSListen:     "127.0.0.1:18080",
		MTU:             1420,
		DNSServers:      []string{"1.1.1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func testKey(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

var testDiscoveredServerKey = testKey(4)

func TestDiscoveryNowUsesUTC(t *testing.T) {
	got, err := discoveryNow("2026-06-13T12:00:00+03:00")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 6, 13, 9, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func resetDiscoveryTrust(t *testing.T) {
	t.Helper()
	discoveryTrust.Lock()
	oldKey, oldSeq := discoveryTrust.publicKey, discoveryTrust.maxSeenSeq
	discoveryTrust.publicKey, discoveryTrust.maxSeenSeq = "", 0
	discoveryTrust.Unlock()
	t.Cleanup(func() {
		discoveryTrust.Lock()
		discoveryTrust.publicKey, discoveryTrust.maxSeenSeq = oldKey, oldSeq
		discoveryTrust.Unlock()
	})
}

func pinTestSigner(t *testing.T, signer testSigner) {
	t.Helper()
	resetDiscoveryTrust(t)
	if err := pinRendezvousPublicKey(signer.publicKey, false); err != nil {
		t.Fatal(err)
	}
}

func setPendingProvision(t *testing.T, configJSON, awgRUConfigJSON string) string {
	t.Helper()
	pendingProvision.Lock()
	oldConfig, oldAWGRU := pendingProvision.configJSON, pendingProvision.awgRUConfigJSON
	pendingProvision.configJSON, pendingProvision.awgRUConfigJSON = configJSON, awgRUConfigJSON
	pendingProvision.Unlock()
	t.Cleanup(func() {
		pendingProvision.Lock()
		pendingProvision.configJSON, pendingProvision.awgRUConfigJSON = oldConfig, oldAWGRU
		pendingProvision.Unlock()
	})
	return configJSON
}

func decodeMinisignResult(t *testing.T, raw string) minisignVerifyResult {
	t.Helper()
	var result minisignVerifyResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("decode minisign result %s: %v", raw, err)
	}
	return result
}

func testPublicApplyRequest() publicApplyAPIRequest {
	return publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		AWG:             &publicRouteSpec{Endpoint: "203.0.113.10:51821"},
	}
}
