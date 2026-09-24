package transport

import (
	"encoding/json"
	"testing"

	awgdialect "github.com/TrafficWrapper/app/core/awg/dialect"
)

func testConfigWith(t *testing.T, mutate func(*config)) string {
	t.Helper()
	var cfg config
	if err := json.Unmarshal([]byte(testBaseConfig(t)), &cfg); err != nil {
		t.Fatal(err)
	}
	mutate(&cfg)
	return mustJSON(t, cfg)
}

func TestParseConfigRejectsNonLoopbackSOCKSListen(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:1080", ":1080", "192.168.1.5:1080", "[::]:1080", "example.com:1080", "127.0.0.1"} {
		raw := testConfigWith(t, func(c *config) { c.SOCKSListen = listen })
		if _, err := parseConfig(raw); err == nil {
			t.Fatalf("socks_listen %q accepted", listen)
		}
	}
	for _, listen := range []string{"127.0.0.1:1080", "127.0.0.2:0", "[::1]:1080", "localhost:1080", ""} {
		raw := testConfigWith(t, func(c *config) { c.SOCKSListen = listen })
		if _, err := parseConfig(raw); err != nil {
			t.Fatalf("socks_listen %q rejected: %v", listen, err)
		}
	}
}

func TestStartSOCKSServerRejectsNonLoopbackListen(t *testing.T) {
	if server, err := startSOCKSServer("0.0.0.0:0", 0, nil); err == nil {
		server.close()
		t.Fatal("non-loopback socks listener started")
	}
}

func TestParseConfigSOCKSMaxConns(t *testing.T) {
	if _, err := parseConfig(testConfigWith(t, func(c *config) { c.SOCKSMaxConns = -1 })); err == nil {
		t.Fatal("negative socks_max_conns accepted")
	}
	cfg, err := parseConfig(testConfigWith(t, func(c *config) { c.SOCKSMaxConns = 16 }))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SOCKSMaxConns != 16 {
		t.Fatalf("socks_max_conns=%d", cfg.SOCKSMaxConns)
	}
}

func TestParseConfigRejectsLineBreaksInUAPIFields(t *testing.T) {
	mutations := map[string]func(*config){
		"private_key":       func(c *config) { c.PrivateKey = c.PrivateKey[:20] + "\n" + c.PrivateKey[20:] },
		"server_public_key": func(c *config) { c.ServerPublicKey += "\r\n" },
		"psk2":              func(c *config) { c.PSK2 = "\n" + c.PSK2 },
		"psk2 nul":          func(c *config) { c.PSK2 += "\x00" },
		"endpoint":          func(c *config) { c.Endpoint += "\nallowed_ip=10.0.0.0/8" },
		"internal_ip":       func(c *config) { c.InternalIP += "\n" },
		"socks_listen":      func(c *config) { c.SOCKSListen = "127.0.0.1:1080\n" },
		"awg_preset compat": func(c *config) { c.AWGPreset.H1 = "1\nreplace_peers=true" },
		"awg_preset prod": func(c *config) {
			d, err := awgdialect.Generate()
			if err != nil {
				t.Fatal(err)
			}
			d.H2 += "\nreplace_peers=true"
			c.AWGPreset = d
		},
		"awg_preset trailing newline": func(c *config) {
			d, err := awgdialect.Generate()
			if err != nil {
				t.Fatal(err)
			}
			d.H4 += "\n"
			c.AWGPreset = d
		},
	}
	for name, mutate := range mutations {
		if _, err := parseConfig(testConfigWith(t, mutate)); err == nil {
			t.Fatalf("%s with line break accepted", name)
		}
	}
}
