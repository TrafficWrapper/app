package transport

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	awgdialect "github.com/TrafficWrapper/app/core/awg/dialect"
)

// testBasePreset is a production dialect in the shape of the worker's legacy
// generator; fixtures use it wherever a server-issued dialect is expected.
func testBasePreset() awgdialect.Dialect {
	return awgdialect.Dialect{
		Jc: 6, Jmin: 8, Jmax: 64,
		S1: 30, S2: 40, S3: 12, S4: 6,
		H1: "150000000-160000000", H2: "700000000-710000000",
		H3: "1200000000-1210000000", H4: "1700000000-1710000000",
	}
}

func testBasePresetRaw() json.RawMessage {
	raw, err := json.Marshal(testBasePreset())
	if err != nil {
		panic(err)
	}
	return raw
}

func TestParseConfigRejectsCompatDialect(t *testing.T) {
	raw := testConfigWith(t, func(c *config) { c.AWGPreset = awgdialect.Compat() })
	if _, err := parseConfig(raw); err == nil {
		t.Fatal("compat dialect accepted from server config")
	}
	raw = testConfigWith(t, func(c *config) { c.AWGPreset = awgdialect.Dialect{} })
	if _, err := parseConfig(raw); err == nil {
		t.Fatal("empty dialect accepted from server config")
	}
}

func TestPublicAWGConfigJSONRejectsRouteWithoutDialect(t *testing.T) {
	req := testPublicApplyRequest()
	route := publicRouteSpec{Endpoint: "203.0.113.10:51821"}
	if _, _, err := publicAWGConfigJSON(&route, req, "127.0.0.1:18080"); err == nil {
		t.Fatal("route without dialect produced a plain WireGuard config")
	}
}

// Static dialects on the edges of the worker generator must keep producing
// a valid config.
func TestParseConfigAcceptsWideDialectFixtures(t *testing.T) {
	raw := readWideDialectFixtures(t)
	for _, fx := range raw {
		t.Run(fx.Name, func(t *testing.T) {
			cfgJSON := testConfigWith(t, func(c *config) { c.AWGPreset = fx.Dialect })
			if _, err := parseConfig(cfgJSON); err != nil {
				t.Fatalf("rejected: %v", err)
			}
			route := publicRouteSpec{Endpoint: "203.0.113.10:51821"}
			route.AWGPreset, _ = json.Marshal(fx.Dialect)
			if _, _, err := publicAWGConfigJSON(&route, testPublicApplyRequest(), "127.0.0.1:18080"); err != nil {
				t.Fatalf("public route rejected: %v", err)
			}
		})
	}
}

type wideDialectFixture struct {
	Name    string             `json:"name"`
	Dialect awgdialect.Dialect `json:"dialect"`
}

func readWideDialectFixtures(t *testing.T) []wideDialectFixture {
	t.Helper()
	raw, err := os.ReadFile("../awg/dialect/testdata/wide_dialects.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []wideDialectFixture
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no fixtures")
	}
	return out
}

func TestParseConfigDNSServersIPv4Only(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"ipv4 kept", []string{"9.9.9.9", "10.13.13.1"}, []string{"9.9.9.9", "10.13.13.1"}},
		{"ipv6 dropped", []string{"2001:db8::53", "9.9.9.9"}, []string{"9.9.9.9"}},
		{"mapped unmapped", []string{"::ffff:9.9.9.9"}, []string{"9.9.9.9"}},
		{"only ipv6 uses defaults", []string{"2001:db8::53", "2001:db8::54"}, defaultDNSServers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseConfig(testConfigWith(t, func(c *config) { c.DNSServers = tc.in }))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(cfg.DNSServers, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("dns_servers=%v want %v", cfg.DNSServers, tc.want)
			}
			if len(cfg.dnsServers) != len(tc.want) {
				t.Fatalf("netstack dns=%v", cfg.dnsServers)
			}
			for _, addr := range cfg.dnsServers {
				if !addr.Is4() {
					t.Fatalf("non-IPv4 netstack dns %s", addr)
				}
			}
		})
	}
	if _, err := parseConfig(testConfigWith(t, func(c *config) { c.DNSServers = []string{"dns.example"} })); err == nil {
		t.Fatal("non-literal dns accepted")
	}
}
