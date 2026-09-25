package transport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TrafficWrapper/app/core/internal/provisionclient"
)

// enrollRaw runs PublicDeviceEnroll against orchestratorURL/orchPublic and
// returns the decoded result without requiring ok=true.
func enrollRaw(t *testing.T, orchestratorURL, orchPublic string, extra map[string]any) map[string]any {
	t.Helper()
	noisePrivate, noisePublic, err := provisionclient.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	req := map[string]any{
		"orchestrator_url":  orchestratorURL,
		"orch_noise_public": orchPublic,
		"bootstrap_token":   "token",
		"noise_private_key": noisePrivate,
		"noise_public_key":  noisePublic,
		"identity_pubkey":   "identity",
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
	return result
}

// testSOCKSRouter is a loopback SOCKS5 server that requires the router
// proof, records the requested target and connects every request to
// upstream (standing in for the tunnel).
type testSOCKSRouter struct {
	ln       net.Listener
	upstream string
	mu       sync.Mutex
	targets  []string
}

func newTestSOCKSRouter(t *testing.T, upstream string) *testSOCKSRouter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &testSOCKSRouter{ln: ln, upstream: upstream}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.handle(conn)
		}
	}()
	return r
}

func (r *testSOCKSRouter) handle(conn net.Conn) {
	defer conn.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != socksVersion5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	_, password, err := localSOCKSCredentials()
	if err != nil || testSOCKSServerRouterProof(conn, methods, password) != nil {
		return
	}
	target, err := readSOCKSConnect(conn)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.targets = append(r.targets, target.String())
	r.mu.Unlock()
	upstream, err := net.Dial("tcp", r.upstream)
	if err != nil {
		_ = writeSOCKSReply(conn, 0x05)
		return
	}
	defer upstream.Close()
	if err := writeSOCKSReply(conn, 0x00); err != nil {
		return
	}
	_ = proxy(context.Background(), conn, upstream)
}

func (r *testSOCKSRouter) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.targets...)
}

func TestPublicDeviceEnrollThroughTunnelSOCKSUsesRemoteNames(t *testing.T) {
	orch, server := newFakeOrchestrator(t, legacyEnrollResponse)
	upstream := strings.TrimPrefix(server.URL, "http://")
	router := newTestSOCKSRouter(t, upstream)
	// The host name is not resolvable locally: only a proxy that receives the
	// name (not a locally resolved IP) can complete this request.
	result := enrollRaw(t, "http://orchestrator.invalid:8443", orch.publicKey(), map[string]any{
		"socks_proxy": router.ln.Addr().String(),
	})
	if result["ok"] != true {
		t.Fatalf("enroll via socks failed: %v", result)
	}
	targets := router.seen()
	if len(targets) == 0 {
		t.Fatal("enrollment did not use the socks router")
	}
	for _, target := range targets {
		if target != "orchestrator.invalid:8443" {
			t.Fatalf("socks target=%q, want the orchestrator host name", target)
		}
	}
}

func TestPublicDeviceEnrollRejectsNonLoopbackSOCKSProxy(t *testing.T) {
	result := enrollRaw(t, "http://orchestrator.invalid", base64.StdEncoding.EncodeToString(make([]byte, 32)), map[string]any{
		"socks_proxy": "203.0.113.5:1080",
	})
	if result["ok"] != false || !strings.Contains(result["error"].(string), "loopback") {
		t.Fatalf("result=%v", result)
	}
}

func TestPublicDeviceEnrollRejectionCarriesAuthenticatedCode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
		code     any
	}{
		{"new orchestrator", `{"ok":false,"error":"device is not approved","code":"device_not_approved"}`, "device_not_approved"},
		{"old orchestrator", `{"ok":false,"error":"device is not approved"}`, nil},
		{"garbage code dropped", `{"ok":false,"error":"x","code":"Bad Code!"}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orch, server := newFakeOrchestrator(t, tc.response)
			result := enrollRaw(t, server.URL, orch.publicKey(), nil)
			if result["ok"] != false || result["rejected"] != true {
				t.Fatalf("result=%v", result)
			}
			if result["code"] != tc.code {
				t.Fatalf("code=%v want %v", result["code"], tc.code)
			}
			if !strings.HasPrefix(result["error"].(string), "public device enrollment rejected: ") {
				t.Fatalf("error=%v", result["error"])
			}
		})
	}
}

func TestPublicDeviceEnrollCarrierErrorIsNotAnAuthenticatedRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"ok":false,"error":"device_not_approved","code":"device_revoked"}`))
	}))
	defer server.Close()
	_, public, err := provisionclient.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	result := enrollRaw(t, server.URL, public, nil)
	if result["ok"] != false {
		t.Fatalf("result=%v", result)
	}
	if _, ok := result["rejected"]; ok {
		t.Fatalf("carrier error marked as orchestrator rejection: %v", result)
	}
	if _, ok := result["code"]; ok {
		t.Fatalf("carrier error carries a code: %v", result)
	}
}

func TestPublicDeviceEnrollRealityFlowAckAndPending(t *testing.T) {
	response := `{"ok":true,"device_id":"dev1","status":"approved","reality_flow":"","reality_flow_pending":"xtls-rprx-vision"}`
	wire, result := runPublicEnroll(t, response, map[string]any{"reality_flow_ack": "xtls-rprx-vision"})
	if wire["reality_flow_ack"] != "xtls-rprx-vision" {
		t.Fatalf("wire=%v", wire)
	}
	if result["reality_flow"] != "" || result["reality_flow_pending"] != "xtls-rprx-vision" {
		t.Fatalf("result=%v", result)
	}
	// Old orchestrator / no ack: nothing extra on the wire or in the result.
	wire, result = runPublicEnroll(t, legacyEnrollResponse, nil)
	for _, key := range []string{"reality_flow_ack", "socks_proxy", "orch_tls_spki_sha256", "reenroll"} {
		if _, ok := wire[key]; ok {
			t.Fatalf("wire carries %s: %v", key, wire)
		}
	}
	if _, ok := result["reality_flow_pending"]; ok {
		t.Fatalf("legacy result carries reality_flow_pending: %v", result)
	}
}

func newFakeOrchestratorTLS(t *testing.T, response string) (*fakeOrchestrator, *httptest.Server, *atomic.Int32) {
	t.Helper()
	f, plain := newFakeOrchestrator(t, response)
	plain.Close()
	var h2 atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			h2.Add(1)
		}
		f.serve(w, r)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return f, server, &h2
}

func TestPublicDeviceEnrollTLSPins(t *testing.T) {
	orch, server, h2 := newFakeOrchestratorTLS(t, legacyEnrollResponse)
	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	good := hex.EncodeToString(sum[:])
	goodB64 := base64.StdEncoding.EncodeToString(sum[:])
	wrong := strings.Repeat("00", sha256.Size)

	for _, tc := range []struct {
		name  string
		extra map[string]any
		ok    bool
	}{
		{"legacy without pins", nil, true},
		{"first enroll pinned hex", map[string]any{"orch_tls_spki_sha256": []string{wrong, good}}, true},
		{"first enroll pinned base64", map[string]any{"orch_tls_spki_sha256": []string{goodB64}}, true},
		{"first enroll wrong pin", map[string]any{"orch_tls_spki_sha256": []string{wrong}}, false},
		// Re-enroll: a self-signed certificate is accepted only through a pin;
		// a CA-issued one would pass the system roots.
		{"reenroll pinned", map[string]any{"orch_tls_spki_sha256": []string{good}, "reenroll": true}, true},
		{"reenroll untrusted and unpinned", map[string]any{"orch_tls_spki_sha256": []string{wrong}, "reenroll": true}, false},
		{"malformed pin", map[string]any{"orch_tls_spki_sha256": []string{"not-a-pin"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := enrollRaw(t, server.URL, orch.publicKey(), tc.extra)
			if (result["ok"] == true) != tc.ok {
				t.Fatalf("ok=%v want %v: %v", result["ok"], tc.ok, result)
			}
			if !tc.ok {
				if _, ok := result["rejected"]; ok {
					t.Fatalf("tls failure marked as orchestrator rejection: %v", result)
				}
			}
		})
	}
	if h2.Load() == 0 {
		t.Fatal("enrollment never negotiated h2 via ALPN")
	}
}

func TestPublicTLSConfigOffersBrowserALPN(t *testing.T) {
	cfg := publicTLSConfig(publicEnrollTransportOptions{})
	if strings.Join(cfg.NextProtos, ",") != "h2,http/1.1" {
		t.Fatalf("NextProtos=%v", cfg.NextProtos)
	}
}

func TestPublicEnrollPadVariesSize(t *testing.T) {
	sizes := map[int]bool{}
	for i := 0; i < 64; i++ {
		pad := publicEnrollPad()
		if len(pad) > publicEnrollPadMaxBytes {
			t.Fatalf("pad length %d", len(pad))
		}
		sizes[len(pad)] = true
	}
	if len(sizes) < 8 {
		t.Fatalf("pad sizes do not vary: %v", sizes)
	}
}

func TestValidatePublicSOCKSProxy(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:18080", "[::1]:18080"} {
		if _, err := validatePublicSOCKSProxy(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "localhost:18080", "10.0.0.1:18080", "127.0.0.1:0", "127.0.0.1"} {
		if _, err := validatePublicSOCKSProxy(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestApplyPublicPlatformConfigSkipsProfileWithoutCredentials(t *testing.T) {
	setPendingProvision(t, "stored-default", "stored-awg-ru")
	req := testPublicApplyRequest()
	req.AWGRU = &publicRouteSpec{Endpoint: "203.0.113.10:51822", AWGProfile: "awg2", AWGPreset: testBasePresetRaw()}
	result, err := applyPublicPlatformConfig(req)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ConfigStored || result.AWGRUConfigStored || len(result.AWGRejected) != 1 || result.AWGRejected[0].Route != "awg_ru" {
		t.Fatalf("result=%+v", result)
	}
	pendingProvision.Lock()
	kept := pendingProvision.awgRUConfigJSON
	pendingProvision.Unlock()
	if kept != "stored-awg-ru" {
		t.Fatalf("awg_ru config replaced with base credentials: %q", kept)
	}
}
