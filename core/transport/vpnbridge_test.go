package transport

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	netstacktun "github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

func TestVpnBridgeBuildSOCKS5ConnectRequestIPv4(t *testing.T) {
	req, err := vpnBridgeBuildSOCKS5ConnectRequest("1.2.3.4", 443)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	got := hex.EncodeToString(req)
	want := "050100010102030401bb"
	if got != want {
		t.Fatalf("request mismatch: got %s want %s", got, want)
	}
}

func TestVpnBridgeBuildSOCKS5ConnectRequestDomain(t *testing.T) {
	req, err := vpnBridgeBuildSOCKS5ConnectRequest("example.com", 80)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	got := hex.EncodeToString(req)
	want := "050100030b6578616d706c652e636f6d0050"
	if got != want {
		t.Fatalf("request mismatch: got %s want %s", got, want)
	}
}

func TestVpnBridgeBuildSOCKS5ConnectRequestRejectsIPv6(t *testing.T) {
	if _, err := vpnBridgeBuildSOCKS5ConnectRequest("2001:db8::1", 443); err == nil {
		t.Fatal("expected IPv6 target rejection")
	}
}

func TestVpnBridgeReadSOCKS5ConnectResponse(t *testing.T) {
	resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90}
	if err := vpnBridgeReadSOCKS5ConnectResponse(bytes.NewReader(resp)); err != nil {
		t.Fatalf("read response: %v", err)
	}
}

func TestVpnBridgeReadSOCKS5ConnectResponseFailure(t *testing.T) {
	resp := []byte{0x05, 0x05, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90}
	if err := vpnBridgeReadSOCKS5ConnectResponse(bytes.NewReader(resp)); err == nil {
		t.Fatal("expected failed reply")
	}
}

func TestVpnBridgeDNSOverTCPFrameRoundTrip(t *testing.T) {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01}
	frame, err := vpnBridgeDNSOverTCPFrame(query)
	if err != nil {
		t.Fatalf("frame query: %v", err)
	}
	if got, want := hex.EncodeToString(frame[:2]), "0006"; got != want {
		t.Fatalf("length prefix mismatch: got %s want %s", got, want)
	}
	decoded, err := vpnBridgeReadDNSOverTCPFrame(bytes.NewReader(frame), 512)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if !bytes.Equal(decoded, query) {
		t.Fatalf("decoded mismatch: got %x want %x", decoded, query)
	}
}

func TestVpnBridgeReadDNSOverTCPFrameRejectsOversize(t *testing.T) {
	frame := []byte{0x00, 0x06, 1, 2, 3, 4, 5, 6}
	_, err := vpnBridgeReadDNSOverTCPFrame(bytes.NewReader(frame), 5)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too large error, got %v", err)
	}
}

func TestVpnBridgeDNSUDPSizeDefaultAndEDNS0(t *testing.T) {
	plain := vpnBridgeTestDNSQuery(0)
	if got, want := vpnBridgeDNSUDPSize(plain), 512; got != want {
		t.Fatalf("plain udp size: got %d want %d", got, want)
	}
	edns := vpnBridgeTestDNSQuery(1232)
	if got, want := vpnBridgeDNSUDPSize(edns), 1232; got != want {
		t.Fatalf("edns udp size: got %d want %d", got, want)
	}
}

func TestVpnBridgeDNSFitUDPTruncatesWithTC(t *testing.T) {
	query := vpnBridgeTestDNSQuery(0)
	response := bytes.Repeat([]byte{0xab}, 700)
	out := vpnBridgeDNSFitUDP(query, response)
	questionEnd, ok := vpnBridgeDNSQuestionEnd(query)
	if !ok {
		t.Fatal("test query question parse failed")
	}
	if got, want := len(out), questionEnd; got != want {
		t.Fatalf("truncated len: got %d want %d", got, want)
	}
	if !bytes.Equal(out[:2], query[:2]) {
		t.Fatalf("id mismatch: got %x want %x", out[:2], query[:2])
	}
	flags := binary.BigEndian.Uint16(out[2:4])
	if flags&0x8000 == 0 || flags&0x0200 == 0 || flags&0x0100 == 0 {
		t.Fatalf("flags missing QR/TC/RD: %016b", flags)
	}
	if got := binary.BigEndian.Uint16(out[4:6]); got != 1 {
		t.Fatalf("qdcount: got %d want 1", got)
	}
	if got := binary.BigEndian.Uint16(out[6:8]); got != 0 {
		t.Fatalf("ancount: got %d want 0", got)
	}
	if got := binary.BigEndian.Uint16(out[8:10]); got != 0 {
		t.Fatalf("nscount: got %d want 0", got)
	}
	if got := binary.BigEndian.Uint16(out[10:12]); got != 0 {
		t.Fatalf("arcount: got %d want 0", got)
	}
	if !bytes.Equal(out[12:], query[12:questionEnd]) {
		t.Fatalf("question mismatch: got %x want %x", out[12:], query[12:questionEnd])
	}
}

func TestVpnBridgeDNSFitUDPRespectsEDNS0(t *testing.T) {
	query := vpnBridgeTestDNSQuery(1232)
	response := bytes.Repeat([]byte{0xcd}, 700)
	out := vpnBridgeDNSFitUDP(query, response)
	if !bytes.Equal(out, response) {
		t.Fatal("response under EDNS0 limit should not be truncated")
	}
	out = vpnBridgeDNSFitUDP(query, bytes.Repeat([]byte{0xef}, 1400))
	flags := binary.BigEndian.Uint16(out[2:4])
	if flags&0x0200 == 0 {
		t.Fatalf("expected TC bit for response over EDNS0 limit: %016b", flags)
	}
}

func TestVpnBridgeDNSCacheRewritesTransactionID(t *testing.T) {
	b := &vpnBridgeInstance{dnsCache: make(map[string]vpnBridgeDNSCacheEntry)}
	query := vpnBridgeTestDNSQuery(0)
	response := append([]byte(nil), query...)
	response[2] = 0x81
	response[3] = 0x80
	response[0], response[1] = 0xaa, 0xbb
	b.cacheDNSResponse(query, response)

	nextQuery := append([]byte(nil), query...)
	nextQuery[0], nextQuery[1] = 0xcc, 0xdd
	cached, ok := b.cachedDNSResponse(nextQuery)
	if !ok {
		t.Fatal("expected cached DNS response")
	}
	if got, want := hex.EncodeToString(cached[:2]), "ccdd"; got != want {
		t.Fatalf("transaction id not rewritten: got %s want %s", got, want)
	}
	if cached[2] != 0x81 || cached[3] != 0x80 {
		t.Fatalf("cached flags changed: %x", cached[2:4])
	}
}

func TestVpnBridgeNormalizeUDPRoute(t *testing.T) {
	tests := map[string]string{
		"":                                "",
		"off":                             "",
		"auto":                            vpnBridgeAutoUDPRoute,
		"netstack:default":                defaultInstanceName,
		"awg:worker-a":                    "worker-a",
		"socks:tcp-a@127.0.0.1:18085":     "tcp-a@127.0.0.1:18085",
		"socks:warm.reserve@127.0.0.1:81": "warm.reserve@127.0.0.1:81",
	}
	for input, want := range tests {
		got, err := vpnBridgeNormalizeUDPRoute(input)
		if err != nil {
			t.Fatalf("route %q returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("route %q: got %q want %q", input, got, want)
		}
	}
	if _, err := vpnBridgeNormalizeUDPRoute("bogus"); err == nil {
		t.Fatal("invalid route accepted")
	}
	if _, err := vpnBridgeNormalizeUDPRoute("awg-ru"); err == nil {
		t.Fatal("legacy deployment-specific route alias accepted")
	}
	if _, err := vpnBridgeNormalizeUDPRoute("socks:bad token@127.0.0.1:18085"); err == nil {
		t.Fatal("invalid route label accepted")
	}
	if _, err := vpnBridgeNormalizeUDPRoute("socks:tcp-a@[::1]:18085"); err == nil {
		t.Fatal("ipv6 socks udp proxy accepted")
	}
}

func TestVpnBridgeAutoUDPRouteSelectsRunningNetstack(t *testing.T) {
	singleton.Lock()
	oldInstances := singleton.instances
	singleton.instances = map[string]*instance{
		"secondary":         {net: nil},
		defaultInstanceName: {net: nil},
	}
	singleton.Unlock()
	t.Cleanup(func() {
		singleton.Lock()
		singleton.instances = oldInstances
		singleton.Unlock()
	})
	if got := vpnBridgeSelectAutoUDPRoute(); got != "" {
		t.Fatalf("empty auto selection got %q", got)
	}
	singleton.Lock()
	singleton.instances[defaultInstanceName] = &instance{net: &netstacktun.Net{}}
	singleton.Unlock()
	if got := vpnBridgeSelectAutoUDPRoute(); got != defaultInstanceName {
		t.Fatalf("default auto selection got %q", got)
	}
}

func TestVpnBridgeAddrPortTargetRequiresIPv4(t *testing.T) {
	target, err := vpnBridgeAddrPortTarget("1.1.1.1:53")
	if err != nil {
		t.Fatalf("ipv4 target rejected: %v", err)
	}
	if got, want := target.String(), "1.1.1.1:53"; got != want {
		t.Fatalf("target mismatch: got %s want %s", got, want)
	}
	if _, err := vpnBridgeAddrPortTarget("dns.example:53"); err == nil {
		t.Fatal("domain DNS target accepted for UDP")
	}
	if _, err := vpnBridgeAddrPortTarget("[2606:4700:4700::1111]:53"); err == nil {
		t.Fatal("IPv6 DNS target accepted for UDP")
	}
}

func TestVpnBridgeSOCKS5UDPDatagramRoundTrip(t *testing.T) {
	target := netip.MustParseAddrPort("1.2.3.4:443")
	payload := []byte("hello-quic")
	frame, err := vpnBridgeBuildSOCKS5UDPDatagram(target, payload)
	if err != nil {
		t.Fatalf("build udp datagram: %v", err)
	}
	if got, want := hex.EncodeToString(frame[:10]), "000000010102030401bb"; got != want {
		t.Fatalf("udp header mismatch: got %s want %s", got, want)
	}
	decoded, err := vpnBridgeParseSOCKS5UDPDatagram(frame)
	if err != nil {
		t.Fatalf("parse udp datagram: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("payload mismatch: got %q want %q", decoded, payload)
	}
}

func TestVpnBridgeSOCKS5UDPDatagramRejectsFragment(t *testing.T) {
	frame := []byte{0x00, 0x00, 0x01, vpnBridgeSOCKSIPv4, 1, 2, 3, 4, 0, 53, 1}
	if _, err := vpnBridgeParseSOCKS5UDPDatagram(frame); err == nil {
		t.Fatal("fragmented udp datagram accepted")
	}
}

func TestVpnBridgeReadSOCKS5UDPAssociateResponseUsesProxyHostForUnspecified(t *testing.T) {
	resp := []byte{0x05, 0x00, 0x00, vpnBridgeSOCKSIPv4, 0, 0, 0, 0, 0x9c, 0x40}
	addr, err := vpnBridgeReadSOCKS5UDPAssociateResponse(bytes.NewReader(resp), "127.0.0.1")
	if err != nil {
		t.Fatalf("read udp associate response: %v", err)
	}
	if got, want := addr.String(), "127.0.0.1:40000"; got != want {
		t.Fatalf("relay addr mismatch: got %s want %s", got, want)
	}
}

func TestVpnBridgeListenSOCKS5UDPUsesConcreteIPv4Endpoint(t *testing.T) {
	conn, local, err := vpnBridgeListenSOCKS5UDP("127.0.0.1")
	if err != nil {
		t.Fatalf("listen socks udp: %v", err)
	}
	defer conn.Close()
	if got, want := local.IP.String(), "127.0.0.1"; got != want {
		t.Fatalf("local ip: got %s want %s", got, want)
	}
	if local.Port == 0 {
		t.Fatal("expected non-zero local UDP port")
	}
	if len(local.IP) != 4 {
		t.Fatalf("expected IPv4 byte form for ASSOCIATE request, got len=%d", len(local.IP))
	}
}

func vpnBridgeTestDNSQuery(ednsUDPSize uint16) []byte {
	qname := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	query := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(query[0:2], 0x1234)
	binary.BigEndian.PutUint16(query[2:4], 0x0100) // RD.
	binary.BigEndian.PutUint16(query[4:6], 1)
	if ednsUDPSize > 0 {
		binary.BigEndian.PutUint16(query[10:12], 1)
	}
	query = append(query, qname...)
	query = binary.BigEndian.AppendUint16(query, 1)
	query = binary.BigEndian.AppendUint16(query, 1)
	if ednsUDPSize > 0 {
		query = append(query, 0)
		query = binary.BigEndian.AppendUint16(query, 41)
		query = binary.BigEndian.AppendUint16(query, ednsUDPSize)
		query = append(query, 0, 0, 0, 0)
		query = binary.BigEndian.AppendUint16(query, 0)
	}
	return query
}
