package transport

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	awgdialect "github.com/TrafficWrapper/app/core/awg/dialect"
)

const (
	defaultMTU              = 1420
	defaultSOCKSListen      = "127.0.0.1:18080"
	defaultAWGRUSOCKSListen = "127.0.0.1:18084"
	keySize                 = 32
)

var defaultDNSServers = []string{"1.1.1.1", "1.0.0.1"}

type preset = awgdialect.Dialect

type config struct {
	PrivateKey      string `json:"private_key"`
	InternalIP      string `json:"internal_ip"`
	Endpoint        string `json:"endpoint"`
	ServerPublicKey string `json:"server_public_key"`
	PSK2            string `json:"psk2"`
	AWGPreset       preset `json:"awg_preset"`
	SOCKSListen     string `json:"socks_listen,omitempty"`
	// SOCKSMaxConns caps concurrent SOCKS client connections; 0 means
	// defaultSOCKSMaxConns.
	SOCKSMaxConns int      `json:"socks_max_conns,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	DNSServers    []string `json:"dns_servers,omitempty"`
}

type normalizedConfig struct {
	config
	localAddr  netip.Addr
	dnsServers []netip.Addr
}

func parseConfig(configJSON string) (normalizedConfig, error) {
	var cfg config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return normalizedConfig{}, fmt.Errorf("parse config json: %w", err)
	}
	if cfg.MTU == 0 {
		cfg.MTU = defaultMTU
	}
	if cfg.SOCKSListen == "" {
		cfg.SOCKSListen = defaultSOCKSListen
	}
	if cfg.PrivateKey == "" || cfg.InternalIP == "" || cfg.Endpoint == "" || cfg.ServerPublicKey == "" || cfg.PSK2 == "" {
		return normalizedConfig{}, errors.New("config is incomplete")
	}
	// These values end up in newline-delimited UAPI text (or next to it); a
	// line break or NUL would terminate the operation early or smuggle keys.
	for _, field := range []struct{ name, value string }{
		{"private_key", cfg.PrivateKey},
		{"internal_ip", cfg.InternalIP},
		{"endpoint", cfg.Endpoint},
		{"server_public_key", cfg.ServerPublicKey},
		{"psk2", cfg.PSK2},
		{"socks_listen", cfg.SOCKSListen},
	} {
		if strings.ContainsAny(field.value, "\r\n\x00") {
			return normalizedConfig{}, fmt.Errorf("%s contains a line break or NUL", field.name)
		}
	}
	if err := validateSOCKSListen(cfg.SOCKSListen); err != nil {
		return normalizedConfig{}, err
	}
	if cfg.SOCKSMaxConns < 0 {
		return normalizedConfig{}, fmt.Errorf("socks_max_conns must be non-negative, got %d", cfg.SOCKSMaxConns)
	}
	endpoint, err := normalizeEndpoint(cfg.Endpoint)
	if err != nil {
		return normalizedConfig{}, err
	}
	cfg.Endpoint = endpoint
	if _, err := base64KeyToHex(cfg.PrivateKey); err != nil {
		return normalizedConfig{}, fmt.Errorf("private_key: %w", err)
	}
	if _, err := base64KeyToHex(cfg.ServerPublicKey); err != nil {
		return normalizedConfig{}, fmt.Errorf("server_public_key: %w", err)
	}
	if _, err := base64KeyToHex(cfg.PSK2); err != nil {
		return normalizedConfig{}, fmt.Errorf("psk2: %w", err)
	}
	if err := validatePreset(cfg.AWGPreset, cfg.MTU); err != nil {
		return normalizedConfig{}, err
	}
	effectiveMTU, err := awgdialect.EffectiveMTU(cfg.MTU, cfg.AWGPreset)
	if err != nil {
		return normalizedConfig{}, err
	}
	cfg.MTU = effectiveMTU
	prefix, err := netip.ParsePrefix(cfg.InternalIP)
	if err != nil {
		return normalizedConfig{}, fmt.Errorf("internal_ip: %w", err)
	}
	if !prefix.Addr().Is4() {
		return normalizedConfig{}, fmt.Errorf("internal_ip must be IPv4, got %s", cfg.InternalIP)
	}
	dnsStrings, dns, err := netstackDNSServers(cfg.DNSServers)
	if err != nil {
		return normalizedConfig{}, err
	}
	cfg.DNSServers = dnsStrings
	return normalizedConfig{config: cfg, localAddr: prefix.Addr(), dnsServers: dns}, nil
}

// netstackDNSServers returns the DNS servers the IPv4-only netstack can
// reach. Entries must be IP literals; IPv4-mapped IPv6 addresses are unmapped
// and other IPv6 servers are dropped. When no IPv4 server remains, the
// defaults are used rather than failing the config: a config that lists only
// IPv6 resolvers was accepted before and must keep starting, it just could
// never resolve names through them.
func netstackDNSServers(values []string) ([]string, []netip.Addr, error) {
	values = effectiveDNSServerStrings(values)
	outStrings := make([]string, 0, len(values))
	out := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return nil, nil, fmt.Errorf("dns server %q: %w", value, err)
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			continue
		}
		outStrings = append(outStrings, addr.String())
		out = append(out, addr)
	}
	if len(out) == 0 {
		for _, value := range defaultDNSServers {
			out = append(out, netip.MustParseAddr(value))
		}
		outStrings = append(outStrings, defaultDNSServers...)
	}
	return outStrings, out, nil
}

func effectiveDNSServerStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), defaultDNSServers...)
	}
	return out
}

func validatedConfigJSON(cfg config) (string, error) {
	dnsServers, _, err := netstackDNSServers(cfg.DNSServers)
	if err != nil {
		return "", err
	}
	cfg.DNSServers = dnsServers
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	if _, err := parseConfig(string(raw)); err != nil {
		return "", err
	}
	return string(raw), nil
}

// validateSOCKSListen only allows loopback listeners: the SOCKS server proxies
// into the tunnel and must never be reachable from the LAN.
func validateSOCKSListen(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("socks_listen %q: %w", listen, err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return fmt.Errorf("socks_listen %q must be a loopback address", listen)
	}
	return nil
}

func normalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if _, err := netip.ParseAddrPort(endpoint); err == nil {
		return endpoint, nil
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return endpoint, nil
	}
	return "", fmt.Errorf("endpoint host %q must be an IP literal; refusing system DNS lookup", host)
}

// validatePreset applies the production dialect policy to the AWG preset.
// Every config reaching the core comes from the server (enrollment, signed
// client config or rendezvous feed), and workers only ever issue production
// dialects, so the Compat (plain WireGuard) profile is refused here instead
// of producing a tunnel that could never complete a handshake.
//
// Failures wrap errNonProductionDialect so server-config callers can skip
// the one AWG route instead of failing the whole apply.
func validatePreset(p preset, mtu int) error {
	if err := awgdialect.ValidateProduction(p, mtu); err != nil {
		return fmt.Errorf("%w: %v", errNonProductionDialect, err)
	}
	return nil
}

// errNonProductionDialect marks an AWG dialect that is missing, the Compat
// profile or outside the production bounds.
var errNonProductionDialect = errors.New("awg dialect is not a production dialect")

// awgRouteRejection reports an AWG route that was skipped because of its
// dialect; the rest of the config is still applied.
type awgRouteRejection struct {
	Route  string `json:"route"`
	Reason string `json:"reason"`
}

func base64KeyToHex(value string) (string, error) {
	raw, err := decodeKeyBase64(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func decodeKeyBase64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(raw) != keySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", keySize, len(raw))
	}
	return raw, nil
}
