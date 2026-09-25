package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TrafficWrapper/app/core/internal/provisionclient"
)

func TestPublicEnrollAWGKeyPairReplaysStoredKeys(t *testing.T) {
	called := false
	privateKey, publicKey, err := publicEnrollAWGKeyPair(
		publicDeviceEnrollAPIRequest{
			AWGPrivateKey: "stored-private",
			AWGPublicKey:  "stored-public",
		},
		func() (string, string, error) {
			called = true
			return "", "", nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("generator called despite stored awg keypair")
	}
	if privateKey != "stored-private" || publicKey != "stored-public" {
		t.Fatalf("unexpected stored keypair: private=%q public=%q", privateKey, publicKey)
	}
}

func TestPublicEnrollAWGKeyPairGeneratesFallbackWhenMissing(t *testing.T) {
	privateKey, publicKey, err := publicEnrollAWGKeyPair(
		publicDeviceEnrollAPIRequest{},
		func() (string, string, error) {
			return "generated-private", "generated-public", nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if privateKey != "generated-private" || publicKey != "generated-public" {
		t.Fatalf("unexpected generated keypair: private=%q public=%q", privateKey, publicKey)
	}
}

func TestPublicEnrollAWGKeyPairRejectsPartialStoredKeypair(t *testing.T) {
	if _, _, err := publicEnrollAWGKeyPair(
		publicDeviceEnrollAPIRequest{AWGPublicKey: "stored-public"},
		func() (string, string, error) {
			return "generated-private", "generated-public", nil
		},
	); err == nil {
		t.Fatal("partial stored keypair accepted")
	}
	if _, _, err := publicEnrollAWGKeyPair(
		publicDeviceEnrollAPIRequest{},
		func() (string, string, error) {
			return "", "", errors.New("boom")
		},
	); err == nil {
		t.Fatal("generator error ignored")
	}
}

func TestParseConfigInjectsDefaultDNSServers(t *testing.T) {
	cfg := config{
		PrivateKey:      testKey(1),
		InternalIP:      "10.13.13.42/32",
		Endpoint:        "203.0.113.10:51821",
		ServerPublicKey: testKey(2),
		PSK2:            testKey(3),
		AWGPreset:       testBasePreset(),
		MTU:             1420,
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseConfig(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed.DNSServers, defaultDNSServers) {
		t.Fatalf("dns_servers=%v want %v", parsed.DNSServers, defaultDNSServers)
	}
	if len(parsed.dnsServers) != len(defaultDNSServers) {
		t.Fatalf("parsed dns len=%d want %d", len(parsed.dnsServers), len(defaultDNSServers))
	}
}

func TestPublicAWGConfigJSONWritesDNSServers(t *testing.T) {
	route := &publicRouteSpec{
		Endpoint:  "203.0.113.5:51888",
		PublicKey: testKey(2),
		AWGPreset: testBasePresetRaw(),
	}
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		MTU:             1420,
	}
	raw, _, err := publicAWGConfigJSON(route, req, "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.DNSServers, defaultDNSServers) {
		t.Fatalf("default dns_servers=%v want %v", cfg.DNSServers, defaultDNSServers)
	}

	req.DNSServers = []string{"9.9.9.9", "149.112.112.112"}
	raw, _, err = publicAWGConfigJSON(route, req, "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.DNSServers, req.DNSServers) {
		t.Fatalf("override dns_servers=%v want %v", cfg.DNSServers, req.DNSServers)
	}
}

func TestPublicAWGConfigJSONPinsHostnameEndpointWithExpectedEgressIP(t *testing.T) {
	var route publicRouteSpec
	if err := json.Unmarshal([]byte(fmt.Sprintf(
		`{"endpoint":"worker.example:51888","egress_ip":"198.51.100.44","public_key":%q,"awg_preset":%s}`,
		testKey(2), testBasePresetRaw(),
	)), &route); err != nil {
		t.Fatal(err)
	}
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		MTU:             1420,
	}
	raw, _, err := publicAWGConfigJSON(&route, req, "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "198.51.100.44:51888" {
		t.Fatalf("endpoint=%q want pinned IP endpoint", cfg.Endpoint)
	}
}

func TestPublicAWGConfigJSONRejectsHostnameEndpointWithoutPinnedIP(t *testing.T) {
	route := &publicRouteSpec{
		Endpoint:  "worker.example:51888",
		PublicKey: testKey(2),
		AWGPreset: testBasePresetRaw(),
	}
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		MTU:             1420,
	}
	if _, _, err := publicAWGConfigJSON(route, req, "127.0.0.1:18080"); err == nil {
		t.Fatal("hostname endpoint without egress_ip was accepted")
	}
}

func TestPublicHTTPClientUsesContextTimeoutOnly(t *testing.T) {
	client := publicHTTPClient()
	defer client.CloseIdleConnections()
	if client.Timeout != 0 {
		t.Fatalf("client timeout=%s overrides timeout_seconds from the request context", client.Timeout)
	}
}

func TestPostJSONHonoursContextDeadline(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	client := publicHTTPClient()
	defer client.CloseIdleConnections()
	var resp map[string]any
	if err := postJSON(ctx, client, server.URL, map[string]string{}, &resp); err == nil {
		t.Fatal("request succeeded past context deadline")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("request did not stop at context deadline")
	}
}

func TestPostJSONSanitizesUnauthenticatedErrorBody(t *testing.T) {
	body := "bad\x1b[31m\nrequest\u202e" + strings.Repeat("A", 5000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, body, http.StatusBadRequest)
	}))
	defer server.Close()

	client := publicHTTPClient()
	defer client.CloseIdleConnections()
	var resp map[string]any
	err := postJSON(context.Background(), client, server.URL, map[string]string{}, &resp)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "http 400: unauthenticated server response: bad [31m request") {
		t.Fatalf("error not marked unauthenticated: %q", msg)
	}
	if strings.ContainsAny(msg, "\x1b\n\r\u202e") {
		t.Fatalf("error contains control characters: %q", msg)
	}
	if len(msg) > 300 {
		t.Fatalf("error length=%d, want truncated", len(msg))
	}
}

func TestPublicNoiseRequestSanitizesUnauthenticatedErrors(t *testing.T) {
	_, serverPublic, err := provisionclient.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate, clientPublic, err := provisionclient.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    false,
			"error": "Enrollment approved\n\x1b[2Jcall +1-555" + strings.Repeat("!", 1000),
		})
	}))
	defer server.Close()
	var resp map[string]any
	err = publicNoiseJSONRequest(context.Background(), server.URL, serverPublic, clientPrivate, clientPublic, "/d/v1/enroll", map[string]string{}, &resp)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, untrustedServerPrefix) {
		t.Fatalf("error not marked unauthenticated: %q", msg)
	}
	if strings.ContainsAny(msg, "\n\x1b") || len([]rune(msg)) > len(untrustedServerPrefix)+maxUntrustedErrorRunes+3 {
		t.Fatalf("error not sanitized: %q", msg)
	}
}

func TestSanitizeUntrustedText(t *testing.T) {
	if got := sanitizeUntrustedText("  a\u202eb\x00c\n\t d "); got != "a b c d" {
		t.Fatalf("got %q", got)
	}
	long := sanitizeUntrustedText(strings.Repeat("я", 500))
	if n := len([]rune(long)); n != maxUntrustedErrorRunes+3 || !strings.HasSuffix(long, "...") {
		t.Fatalf("rune length=%d", n)
	}
	if got := sanitizeUntrustedText(strings.Repeat("b", maxUntrustedErrorRunes)); strings.HasSuffix(got, "...") {
		t.Fatal("text at the limit was marked truncated")
	}
}

func TestApplyPublicPlatformConfigKeepsStoredConfigs(t *testing.T) {
	setPendingProvision(t, "stored-default", "stored-awg-ru")
	base := testPublicApplyRequest()
	base.AWG = nil
	route := &publicRouteSpec{Endpoint: "203.0.113.10:51821", AWGPreset: testBasePresetRaw()}

	onlyRU := base
	onlyRU.AWGRU = route
	result, err := applyPublicPlatformConfig(onlyRU)
	if err != nil {
		t.Fatal(err)
	}
	if result.ConfigStored || !result.AWGRUConfigStored {
		t.Fatalf("result=%+v", result)
	}
	pendingProvision.Lock()
	defaultJSON, ruJSON := pendingProvision.configJSON, pendingProvision.awgRUConfigJSON
	pendingProvision.Unlock()
	if defaultJSON != "stored-default" {
		t.Fatalf("default config was overwritten: %q", defaultJSON)
	}
	if ruJSON == "stored-awg-ru" || ruJSON == "" {
		t.Fatal("awg_ru config was not updated")
	}

	onlyDefault := base
	onlyDefault.AWG = route
	if _, err := applyPublicPlatformConfig(onlyDefault); err != nil {
		t.Fatal(err)
	}
	pendingProvision.Lock()
	defaultJSON, ruAfter := pendingProvision.configJSON, pendingProvision.awgRUConfigJSON
	pendingProvision.Unlock()
	if defaultJSON == "stored-default" || defaultJSON == "" {
		t.Fatal("default config was not updated")
	}
	if ruAfter != ruJSON {
		t.Fatal("awg_ru config was cleared by request without awg_ru")
	}

	// A failing request leaves both slots untouched.
	bad := onlyDefault
	bad.SOCKSListen = "0.0.0.0:1080"
	if _, err := applyPublicPlatformConfig(bad); err == nil {
		t.Fatal("non-loopback socks_listen accepted")
	}
	pendingProvision.Lock()
	defer pendingProvision.Unlock()
	if pendingProvision.configJSON != defaultJSON || pendingProvision.awgRUConfigJSON != ruJSON {
		t.Fatal("failed apply modified stored configs")
	}
}
