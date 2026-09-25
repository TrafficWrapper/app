package transport

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/flynn/noise"

	awgdialect "github.com/TrafficWrapper/app/core/awg/dialect"
	"github.com/TrafficWrapper/app/core/internal/provisionclient"
)

// fakeOrchestrator is a minimal Noise_XK responder for /d/v1/enroll: it
// records the decrypted request and answers with a fixed JSON payload.
type fakeOrchestrator struct {
	t        *testing.T
	static   noise.DHKey
	response string

	mu       sync.Mutex
	sessions map[string]*noise.HandshakeState
	request  []byte
}

func newFakeOrchestrator(t *testing.T, response string) (*fakeOrchestrator, *httptest.Server) {
	t.Helper()
	private, public, err := provisionclient.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	static, err := provisionclient.LoadKeyPairFromBase64(private, public)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOrchestrator{t: t, static: static, response: response, sessions: map[string]*noise.HandshakeState{}}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	return f, server
}

func (f *fakeOrchestrator) publicKey() string {
	return base64.StdEncoding.EncodeToString(f.static.Public)
}

func (f *fakeOrchestrator) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/d/v1/handshake/start":
		var req publicNoiseStartRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		hs, err := noise.NewHandshakeState(noise.Config{
			CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
			Pattern:       noise.HandshakeXK,
			Initiator:     false,
			Prologue:      []byte(orchestratorNoisePrologue),
			StaticKeypair: f.static,
		})
		if err != nil {
			f.t.Error(err)
			return
		}
		msg1, _ := base64.StdEncoding.DecodeString(req.Message)
		if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
			f.t.Error(err)
			return
		}
		msg2, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			f.t.Error(err)
			return
		}
		f.mu.Lock()
		f.sessions["sid"] = hs
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(publicNoiseStartResponse{OK: true, SID: "sid", Message: base64.StdEncoding.EncodeToString(msg2)})
	case "/d/v1/enroll":
		var env publicNoiseEnvelope
		_ = json.NewDecoder(r.Body).Decode(&env)
		f.mu.Lock()
		hs := f.sessions[env.SID]
		f.mu.Unlock()
		msg3, _ := base64.StdEncoding.DecodeString(env.Message)
		_, recv, send, err := hs.ReadMessage(nil, msg3)
		if err != nil {
			f.t.Error(err)
			return
		}
		payload, _ := base64.StdEncoding.DecodeString(env.Payload)
		plain, err := recv.Decrypt(nil, nil, payload)
		if err != nil {
			f.t.Error(err)
			return
		}
		f.mu.Lock()
		f.request = plain
		f.mu.Unlock()
		sealed, err := send.Encrypt(nil, nil, []byte(f.response))
		if err != nil {
			f.t.Error(err)
			return
		}
		_ = json.NewEncoder(w).Encode(publicNoiseEnvelopeResponse{OK: true, Payload: base64.StdEncoding.EncodeToString(sealed)})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeOrchestrator) lastRequest(t *testing.T) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out map[string]any
	if err := json.Unmarshal(f.request, &out); err != nil {
		t.Fatalf("decode wire request %q: %v", f.request, err)
	}
	return out
}

func runPublicEnroll(t *testing.T, orchestratorResponse string, extra map[string]any) (map[string]any, map[string]any) {
	t.Helper()
	orch, server := newFakeOrchestrator(t, orchestratorResponse)
	noisePrivate, noisePublic, err := provisionclient.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	req := map[string]any{
		"orchestrator_url":  server.URL,
		"orch_noise_public": orch.publicKey(),
		"bootstrap_token":   "token",
		"noise_private_key": noisePrivate,
		"noise_public_key":  noisePublic,
		"identity_pubkey":   "identity",
		"client_version":    "1.2.3",
		"timeout_seconds":   10,
	}
	for k, v := range extra {
		req[k] = v
	}
	raw := PublicDeviceEnroll(mustJSON(t, req))
	var result map[string]any
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("decode result %s: %v", raw, err)
	}
	if result["ok"] != true {
		t.Fatalf("enroll failed: %s", raw)
	}
	return orch.lastRequest(t), result
}

const legacyEnrollResponse = `{"ok":true,"device_id":"dev1","status":"approved","reality_uuid":"u","internal_ip":"10.13.13.42/32","psk2":"p","server_awg_public":"s"}`

func TestPublicDeviceEnrollLegacyRequestAndResponseUnchanged(t *testing.T) {
	wire, result := runPublicEnroll(t, legacyEnrollResponse, nil)
	for _, key := range []string{"client_capabilities", "capabilities", "client_version_code"} {
		if _, ok := wire[key]; ok {
			t.Fatalf("legacy request sent %s: %v", key, wire)
		}
	}
	if wire["client_version"] != "1.2.3" || wire["bootstrap_token"] != "token" {
		t.Fatalf("wire=%v", wire)
	}
	for _, key := range []string{"awg_profiles", "reality_flow", "reality_short_ids", "reality_short_id"} {
		if _, ok := result[key]; ok {
			t.Fatalf("legacy result carries %s: %v", key, result)
		}
	}
	if result["internal_ip"] != "10.13.13.42/32" || result["psk2"] != "p" || result["device_id"] != "dev1" {
		t.Fatalf("result=%v", result)
	}
}

func TestPublicDeviceEnrollPassesCapabilitiesAndNewResultFields(t *testing.T) {
	response := `{"ok":true,"device_id":"dev1","status":"approved","internal_ip":"10.13.13.42/32","psk2":"p",` +
		`"awg_profiles":{"awg":{"awg_public_key":"k","internal_ip":"10.13.13.42/32","psk2":"p"},` +
		`"awg_v2":{"awg_public_key":"k","internal_ip":"10.14.0.7/32","psk2":"p2"}},` +
		`"reality_flow":"xtls-rprx-vision"}`
	wire, result := runPublicEnroll(t, response, map[string]any{
		"client_capabilities": []string{"reality_vision", "ipv6_endpoints"},
		"client_version_code": 42,
	})
	if !reflect.DeepEqual(wire["client_capabilities"], []any{"reality_vision", "ipv6_endpoints"}) {
		t.Fatalf("client_capabilities=%v", wire["client_capabilities"])
	}
	if wire["client_version_code"] != float64(42) {
		t.Fatalf("client_version_code=%v", wire["client_version_code"])
	}
	if result["reality_flow"] != "xtls-rprx-vision" {
		t.Fatalf("reality_flow=%v", result["reality_flow"])
	}
	profiles, ok := result["awg_profiles"].(map[string]any)
	if !ok || len(profiles) != 2 {
		t.Fatalf("awg_profiles=%v", result["awg_profiles"])
	}
	v2 := profiles["awg_v2"].(map[string]any)
	if v2["internal_ip"] != "10.14.0.7/32" || v2["psk2"] != "p2" || v2["awg_public_key"] != "k" {
		t.Fatalf("awg_v2=%v", v2)
	}
}

func TestPublicDeviceEnrollKeepsExplicitEmptyRealityFlow(t *testing.T) {
	_, result := runPublicEnroll(t, `{"ok":true,"device_id":"dev1","status":"pending","reality_flow":""}`, nil)
	flow, ok := result["reality_flow"]
	if !ok || flow != "" {
		t.Fatalf("explicit empty reality_flow lost: %v", result)
	}
}

func testWidePreset() awgdialect.Dialect {
	return awgdialect.Dialect{
		Jc: 16, Jmin: 40, Jmax: 200,
		S1: 20, S2: 40, S3: 10, S4: 8,
		H1: "100000000-110000000", H2: "600000000-610000000",
		H3: "1100000000-1110000000", H4: "1600000000-1610000000",
	}
}

func decodeConfig(t *testing.T, raw string) config {
	t.Helper()
	var cfg config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestApplyPublicPlatformConfigLegacyJSONUnchanged(t *testing.T) {
	setPendingProvision(t, "", "")
	raw := `{"awg_private_key":"` + testKey(1) + `","internal_ip":"10.13.13.42/32","psk2":"` + testKey(3) +
		`","server_awg_public":"` + testKey(2) + `","dns_servers":["9.9.9.9"],` +
		`"awg":{"type":"awg","address":"203.0.113.10","port":51821,"public_key":"` + testKey(2) + `"}}`
	var result publicApplyAPIResult
	if err := json.Unmarshal([]byte(ApplyPublicPlatformConfig(raw)), &result); err != nil || !result.OK {
		t.Fatalf("apply failed: %+v %v", result, err)
	}
	pendingProvision.Lock()
	stored, meta := pendingProvision.configJSON, pendingProvision.configMeta
	pendingProvision.Unlock()
	cfg := decodeConfig(t, stored)
	if cfg.Endpoint != "203.0.113.10:51821" || cfg.InternalIP != "10.13.13.42/32" || cfg.PSK2 != testKey(3) {
		t.Fatalf("cfg=%+v", cfg)
	}
	if !reflect.DeepEqual(cfg.DNSServers, []string{"9.9.9.9"}) {
		t.Fatalf("dns=%v", cfg.DNSServers)
	}
	if meta != (provisionedConfigMeta{}) || !meta.acceptsDiscoveryMerge() {
		t.Fatalf("meta=%+v", meta)
	}
}

func TestPublicAWGConfigJSONUsesProfileCredentials(t *testing.T) {
	req := testPublicApplyRequest()
	req.AWGProfiles = map[string]publicAWGProfileCredentials{
		"awg":    {InternalIP: "10.13.13.99/32", PSK2: testKey(9)},
		"awg_v2": {AWGPublicKey: "k", InternalIP: "10.14.0.7/32", PSK2: testKey(5)},
	}
	for _, tc := range []struct {
		name       string
		route      publicRouteSpec
		internalIP string
		psk2       string
		profile    string
	}{
		{"awg_profile", publicRouteSpec{AWGProfile: "awg_v2", Profile: "ignored"}, "10.14.0.7/32", testKey(5), "awg_v2"},
		{"profile fallback", publicRouteSpec{Profile: "awg_v2"}, "10.14.0.7/32", testKey(5), "awg_v2"},
		{"base profile uses top-level", publicRouteSpec{AWGProfile: "awg"}, "10.13.13.42/32", testKey(3), "awg"},
		{"no profile", publicRouteSpec{}, "10.13.13.42/32", testKey(3), ""},
		{"unknown profile falls back", publicRouteSpec{AWGProfile: "awg_v9"}, "10.13.13.42/32", testKey(3), "awg_v9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := tc.route
			route.Endpoint = "203.0.113.10:51821"
			raw, meta, err := publicAWGConfigJSON(&route, req, "127.0.0.1:18080")
			if err != nil {
				t.Fatal(err)
			}
			cfg := decodeConfig(t, raw)
			if cfg.InternalIP != tc.internalIP || cfg.PSK2 != tc.psk2 || cfg.PrivateKey != testKey(1) {
				t.Fatalf("cfg internal_ip=%q psk2=%q", cfg.InternalIP, cfg.PSK2)
			}
			if meta.profile != tc.profile || meta.v6 {
				t.Fatalf("meta=%+v", meta)
			}
		})
	}
	req.AWGProfiles["awg_v3"] = publicAWGProfileCredentials{InternalIP: "10.15.0.2/32"}
	if _, _, err := publicAWGConfigJSON(&publicRouteSpec{Endpoint: "203.0.113.10:51821", AWGProfile: "awg_v3"}, req, "127.0.0.1:18080"); err == nil {
		t.Fatal("incomplete profile credentials accepted")
	}
}

func TestPublicAWGConfigJSONSelectsIPv6Endpoint(t *testing.T) {
	req := testPublicApplyRequest()
	for _, tc := range []struct {
		name     string
		route    publicRouteSpec
		profiles map[string]publicAWGProfileCredentials
		endpoint string
		v6       bool
	}{
		{"default family is v4", publicRouteSpec{Endpoint: "203.0.113.10:51821", EndpointV6: "[2001:db8::1]:51821"}, nil, "203.0.113.10:51821", false},
		{"explicit v4", publicRouteSpec{Endpoint: "203.0.113.10:51821", EndpointV6: "[2001:db8::1]:51821", IPFamily: "v4"}, nil, "203.0.113.10:51821", false},
		{"v6", publicRouteSpec{Endpoint: "203.0.113.10:51821", EndpointV6: "[2001:db8::1]:51821", IPFamily: "v6"}, nil, "[2001:db8::1]:51821", true},
		{"v6 without endpoint_v6 falls back", publicRouteSpec{Endpoint: "203.0.113.10:51821", IPFamily: "v6"}, nil, "203.0.113.10:51821", false},
		{"v6 bare address uses route port", publicRouteSpec{Address: "203.0.113.10", Port: 51900, EndpointV6: "2001:db8::2", IPFamily: "V6"}, nil, "[2001:db8::2]:51900", true},
		{"profile endpoint_v6 wins", publicRouteSpec{Endpoint: "203.0.113.10:51821", EndpointV6: "[2001:db8::1]:51821", IPFamily: "v6", AWGProfile: "awg_v2"},
			map[string]publicAWGProfileCredentials{"awg_v2": {InternalIP: "10.14.0.7/32", PSK2: testKey(5), EndpointV6: "[2001:db8::7]:51822"}}, "[2001:db8::7]:51822", true},
		{"address ipv6 literal joins with brackets", publicRouteSpec{Address: "2001:db8::3", Port: 51821}, nil, "[2001:db8::3]:51821", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := req
			req.AWGProfiles = tc.profiles
			route := tc.route
			raw, meta, err := publicAWGConfigJSON(&route, req, "127.0.0.1:18080")
			if err != nil {
				t.Fatal(err)
			}
			if cfg := decodeConfig(t, raw); cfg.Endpoint != tc.endpoint {
				t.Fatalf("endpoint=%q want %q", cfg.Endpoint, tc.endpoint)
			}
			if meta.v6 != tc.v6 {
				t.Fatalf("meta.v6=%t want %t", meta.v6, tc.v6)
			}
		})
	}
	for _, bad := range []string{"203.0.113.10:51821", "[2001:db8::1]", "worker.example:51821", "[::ffff:1.2.3.4]:51821"} {
		route := publicRouteSpec{Endpoint: "203.0.113.10:51821", EndpointV6: bad, IPFamily: "v6"}
		if _, _, err := publicAWGConfigJSON(&route, req, "127.0.0.1:18080"); err == nil {
			t.Fatalf("endpoint_v6 %q accepted", bad)
		}
	}
}

func TestPublicAWGConfigJSONRouteDNS(t *testing.T) {
	req := testPublicApplyRequest()
	req.DNSServers = []string{"9.9.9.9"}
	for _, tc := range []struct {
		name string
		dns  []string
		want []string
	}{
		{"absent uses dns_servers", nil, []string{"9.9.9.9"}},
		{"empty list uses dns_servers", []string{}, []string{"9.9.9.9"}},
		{"blank values use dns_servers", []string{" ", ""}, []string{"9.9.9.9"}},
		{"route dns overrides", []string{" 10.13.13.1 ", "", "2001:db8::53"}, []string{"10.13.13.1", "2001:db8::53"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := publicRouteSpec{Endpoint: "203.0.113.10:51821", DNS: tc.dns}
			raw, _, err := publicAWGConfigJSON(&route, req, "127.0.0.1:18080")
			if err != nil {
				t.Fatal(err)
			}
			if cfg := decodeConfig(t, raw); !reflect.DeepEqual(cfg.DNSServers, tc.want) {
				t.Fatalf("dns=%v want %v", cfg.DNSServers, tc.want)
			}
		})
	}
	setPendingProvision(t, "stored", "")
	bad := req
	bad.AWG = &publicRouteSpec{Endpoint: "203.0.113.10:51821", DNS: []string{"10.13.13.1", "dns.example"}}
	if _, err := applyPublicPlatformConfig(bad); err == nil || !strings.Contains(err.Error(), "dns") {
		t.Fatalf("invalid route dns accepted: %v", err)
	}
	pendingProvision.Lock()
	defer pendingProvision.Unlock()
	if pendingProvision.configJSON != "stored" {
		t.Fatal("failed apply replaced stored config")
	}
}

func TestApplyPublicPlatformConfigStoresProfileMetaAndWideDialect(t *testing.T) {
	setPendingProvision(t, "", "")
	preset := mustJSON(t, testWidePreset())
	raw := `{"awg_private_key":"` + testKey(1) + `","internal_ip":"10.13.13.42/32","psk2":"` + testKey(3) +
		`","server_awg_public":"` + testKey(2) + `",` +
		`"awg_profiles":{"awg_v2":{"awg_public_key":"k","internal_ip":"10.14.0.7/32","psk2":"` + testKey(5) + `"}},` +
		`"awg":{"endpoint":"203.0.113.10:51822","awg_profile":"awg_v2","awg_preset":` + preset + `},` +
		`"awg_ru":{"endpoint":"203.0.113.11:51821","endpoint_v6":"[2001:db8::11]:51821","ip_family":"v6","dns":["10.13.13.1"]}}`
	var result publicApplyAPIResult
	if err := json.Unmarshal([]byte(ApplyPublicPlatformConfig(raw)), &result); err != nil || !result.OK {
		t.Fatalf("apply failed: %+v %v", result, err)
	}
	pendingProvision.Lock()
	cfgJSON, meta := pendingProvision.configJSON, pendingProvision.configMeta
	ruJSON, ruMeta := pendingProvision.awgRUConfigJSON, pendingProvision.awgRUConfigMeta
	pendingProvision.Unlock()
	if meta != (provisionedConfigMeta{profile: "awg_v2"}) || meta.acceptsDiscoveryMerge() {
		t.Fatalf("awg meta=%+v", meta)
	}
	if ruMeta != (provisionedConfigMeta{v6: true}) || ruMeta.acceptsDiscoveryMerge() {
		t.Fatalf("awg_ru meta=%+v", ruMeta)
	}
	cfg := decodeConfig(t, cfgJSON)
	if cfg.InternalIP != "10.14.0.7/32" || cfg.AWGPreset != testWidePreset() {
		t.Fatalf("awg cfg=%+v", cfg)
	}
	ru := decodeConfig(t, ruJSON)
	if ru.Endpoint != "[2001:db8::11]:51821" || !reflect.DeepEqual(ru.DNSServers, []string{"10.13.13.1"}) || ru.InternalIP != "10.13.13.42/32" {
		t.Fatalf("awg_ru cfg=%+v", ru)
	}
}

func TestSelectAWGEndpointAcceptsWideDialect(t *testing.T) {
	selected, err := selectAWGEndpoint([]discoveredAWGEndpoint{{
		Endpoint:        "198.51.100.50:51821",
		ServerPublicKey: testDiscoveredServerKey,
		AWGPreset:       testWidePreset(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if selected.AWGPreset != testWidePreset() {
		t.Fatalf("preset=%+v", selected.AWGPreset)
	}
	if err := validatePreset(testWidePreset(), defaultMTU); err != nil {
		t.Fatal(err)
	}
	if _, err := awgdialect.EffectiveMTU(defaultMTU, testWidePreset()); err != nil {
		t.Fatal(err)
	}
}

func TestApplyDiscoveredEndpointsMergePreservesDNSServers(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	setPendingProvision(t, testBaseConfig(t), "")
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, bundle, "", 0, "2026-06-13T12:00:00Z")))
	if !result.OK || result.AWGMergeSkipped {
		t.Fatalf("apply=%+v", result)
	}
	merged := decodeConfig(t, result.ConfigJSON)
	if merged.Endpoint != "198.51.100.50:51821" {
		t.Fatalf("endpoint=%q", merged.Endpoint)
	}
	if !reflect.DeepEqual(merged.DNSServers, []string{"1.1.1.1"}) {
		t.Fatalf("dns_servers=%v, want preserved [1.1.1.1]", merged.DNSServers)
	}
}

func TestApplyDiscoveredEndpointsSkipsMergeForProfileOrIPv6Config(t *testing.T) {
	for _, meta := range []provisionedConfigMeta{{profile: "awg_v2"}, {v6: true}, {profile: "awg", v6: true}} {
		signer := newTestSigner(t)
		pinTestSigner(t, signer)
		stored := setPendingProvision(t, testBaseConfig(t), "")
		pendingProvision.Lock()
		meta.slot = testSlotMeta().slot // same worker as the feed entry
		pendingProvision.configMeta = meta
		pendingProvision.Unlock()
		bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
		result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, bundle, "", 0, "2026-06-13T12:00:00Z")))
		if !result.OK || !result.AWGMergeSkipped || result.Seq != 10 {
			t.Fatalf("meta=%+v apply=%+v", meta, result)
		}
		if result.ConfigJSON != stored {
			t.Fatalf("meta=%+v config_json changed", meta)
		}
		pendingProvision.Lock()
		got := pendingProvision.configJSON
		pendingProvision.Unlock()
		if got != stored {
			t.Fatalf("meta=%+v pending config overwritten", meta)
		}
	}
	for _, meta := range []provisionedConfigMeta{{}, {profile: "awg"}} {
		if !meta.acceptsDiscoveryMerge() {
			t.Fatalf("base meta %+v refuses merge", meta)
		}
	}
}

func TestApplyDiscoveredEndpointsSkipsMergeForIPv6CallerBase(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	cfg := decodeConfig(t, testBaseConfig(t))
	cfg.Endpoint = "[2001:db8::1]:51821"
	base := mustJSON(t, cfg)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, bundle, base, 0, "2026-06-13T12:00:00Z")))
	if !result.OK || !result.AWGMergeSkipped || result.ConfigJSON != base {
		t.Fatalf("apply=%+v", result)
	}
}
