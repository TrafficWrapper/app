package transport

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	awgdialect "github.com/TrafficWrapper/app/core/awg/dialect"
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
		AWGPreset:       awgdialect.Compat(),
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
	}
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		MTU:             1420,
	}
	raw, err := publicAWGConfigJSON(route, req, "127.0.0.1:18080")
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
	raw, err = publicAWGConfigJSON(route, req, "127.0.0.1:18080")
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
	route := &publicRouteSpec{
		Endpoint:  "worker.example:51888",
		EgressIP:  "198.51.100.44",
		PublicKey: testKey(2),
	}
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		MTU:             1420,
	}
	raw, err := publicAWGConfigJSON(route, req, "127.0.0.1:18080")
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
	}
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		MTU:             1420,
	}
	if _, err := publicAWGConfigJSON(route, req, "127.0.0.1:18080"); err == nil {
		t.Fatal("hostname endpoint without expected_egress_ip was accepted")
	}
}
