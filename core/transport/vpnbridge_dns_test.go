package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func vpnBridgeTestDNSResponse(query []byte, ttl uint32) []byte {
	questionEnd, ok := vpnBridgeDNSQuestionEnd(query)
	if !ok {
		panic("bad test query")
	}
	resp := make([]byte, 0, questionEnd+16)
	resp = append(resp, query[:2]...)
	resp = binary.BigEndian.AppendUint16(resp, 0x8180)
	resp = binary.BigEndian.AppendUint16(resp, 1) // qd
	resp = binary.BigEndian.AppendUint16(resp, 1) // an
	resp = binary.BigEndian.AppendUint16(resp, 0) // ns
	resp = binary.BigEndian.AppendUint16(resp, 0) // ar
	resp = append(resp, query[12:questionEnd]...)
	resp = append(resp, 0xc0, 0x0c)
	resp = binary.BigEndian.AppendUint16(resp, 1)
	resp = binary.BigEndian.AppendUint16(resp, 1)
	resp = binary.BigEndian.AppendUint32(resp, ttl)
	resp = binary.BigEndian.AppendUint16(resp, 4)
	resp = append(resp, 1, 2, 3, 4)
	return resp
}

func vpnBridgeTestDNSQueryName(name string) []byte {
	query := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(query[0:2], 0x4242)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range splitDNSLabels(name) {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0)
	query = binary.BigEndian.AppendUint16(query, 1)
	query = binary.BigEndian.AppendUint16(query, 1)
	return query
}

func splitDNSLabels(name string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

func TestVpnBridgeDNSCacheKeyIgnoresIDCaseAndEDNS(t *testing.T) {
	plain := vpnBridgeTestDNSQuery(0)
	edns := vpnBridgeTestDNSQuery(1232)
	edns[0], edns[1] = 0x99, 0x98
	upper := vpnBridgeTestDNSQueryName("EXAMPLE.com")
	k1, ok1 := vpnBridgeDNSQuestionKey(plain)
	k2, ok2 := vpnBridgeDNSQuestionKey(edns)
	k3, ok3 := vpnBridgeDNSQuestionKey(upper)
	if !ok1 || !ok2 || !ok3 {
		t.Fatal("question key parse failed")
	}
	if k1 != k2 || k1 != k3 {
		t.Fatalf("keys differ: %x %x %x", k1, k2, k3)
	}
	other, _ := vpnBridgeDNSQuestionKey(vpnBridgeTestDNSQueryName("example.org"))
	if other == k1 {
		t.Fatal("different names share a key")
	}
}

func TestVpnBridgeDNSCacheHonoursTTL(t *testing.T) {
	var cache vpnBridgeDNSCache
	query := vpnBridgeTestDNSQuery(0)
	now := time.Now()
	cache.put(query, vpnBridgeTestDNSResponse(query, 30), now)

	resp, ok := cache.get(query, now.Add(10*time.Second), false)
	if !ok {
		t.Fatal("fresh entry missing")
	}
	offsets, ttls, _, ok := vpnBridgeDNSPositiveTTLs(resp)
	if !ok || len(offsets) != 1 {
		t.Fatalf("cached response unparsable: %v %v", offsets, ok)
	}
	if ttls[0] != 20 {
		t.Fatalf("ttl not decremented: got %d want 20", ttls[0])
	}
	if _, ok := cache.get(query, now.Add(31*time.Second), false); ok {
		t.Fatal("expired entry served as fresh")
	}
	stale, ok := cache.get(query, now.Add(40*time.Second), true)
	if !ok {
		t.Fatal("stale entry not served as fallback")
	}
	_, staleTTLs, _, _ := vpnBridgeDNSPositiveTTLs(stale)
	if staleTTLs[0] != vpnBridgeDNSStaleServe {
		t.Fatalf("stale ttl=%d want %d", staleTTLs[0], vpnBridgeDNSStaleServe)
	}
	if _, ok := cache.get(query, now.Add(30*time.Second+vpnBridgeDNSStaleTTL+time.Second), true); ok {
		t.Fatal("entry served beyond stale window")
	}
}

func TestVpnBridgeDNSCacheSkipsNegativeAndTruncated(t *testing.T) {
	var cache vpnBridgeDNSCache
	query := vpnBridgeTestDNSQuery(0)
	now := time.Now()

	nx := vpnBridgeTestDNSResponse(query, 30)
	nx[3] |= 0x03 // NXDOMAIN
	cache.put(query, nx, now)
	tc := vpnBridgeTestDNSResponse(query, 30)
	tc[2] |= 0x02 // TC
	cache.put(query, tc, now)
	zero := vpnBridgeTestDNSResponse(query, 0)
	cache.put(query, zero, now)
	mismatch := vpnBridgeTestDNSResponse(vpnBridgeTestDNSQueryName("example.org"), 30)
	cache.put(query, mismatch, now)
	if cache.len() != 0 {
		t.Fatalf("non-cacheable responses stored: %d", cache.len())
	}
}

func TestVpnBridgeDNSCacheIsBounded(t *testing.T) {
	var cache vpnBridgeDNSCache
	now := time.Now()
	first := vpnBridgeTestDNSQueryName("host0.example")
	for i := 0; i < vpnBridgeDNSCacheSize+50; i++ {
		query := vpnBridgeTestDNSQueryName(fmt.Sprintf("host%d.example", i))
		cache.put(query, vpnBridgeTestDNSResponse(query, 300), now)
	}
	if got := cache.len(); got != vpnBridgeDNSCacheSize {
		t.Fatalf("cache size=%d want %d", got, vpnBridgeDNSCacheSize)
	}
	if _, ok := cache.get(first, now, false); ok {
		t.Fatal("least recently used entry was not evicted")
	}
}

func TestVpnBridgeDNSUDPSizeClampsSmallEDNS(t *testing.T) {
	if got := vpnBridgeDNSUDPSize(vpnBridgeTestDNSQuery(100)); got != 512 {
		t.Fatalf("edns size below 512: got %d want 512", got)
	}
}

func TestVpnBridgeDoHClientReusesConnections(t *testing.T) {
	b := &vpnBridgeInstance{}
	client := b.newDoHClient()
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport %T", client.Transport)
	}
	if tr.DisableKeepAlives || !tr.ForceAttemptHTTP2 || tr.IdleConnTimeout <= 0 || tr.MaxIdleConnsPerHost <= 0 {
		t.Fatalf("doh transport is not pooled: %+v", tr)
	}
	if tr.Proxy != nil {
		t.Fatal("doh transport must not use environment proxies")
	}
}

// TestVpnBridgeDNSMuxSharesOneAssociate verifies that concurrent DNS queries
// over a SOCKS UDP route share one authenticated UDP ASSOCIATE and each get
// their own answer with the original transaction ID.
func TestVpnBridgeDNSMuxSharesOneAssociate(t *testing.T) {
	proxy := startTestSOCKSUDPServer(t, func(payload []byte) []byte {
		return vpnBridgeTestDNSResponse(payload, 60)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &vpnBridgeInstance{ctx: ctx, cancel: cancel, dnsAddr: "1.1.1.1:53"}
	b.dnsMux.b = b
	defer b.dnsMux.close()
	route := "test@" + proxy.addr

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			query := vpnBridgeTestDNSQueryName(fmt.Sprintf("q%d.example", i))
			binary.BigEndian.PutUint16(query[:2], 0x1234) // same app-side ID for all
			resp, err := b.resolveDNSOverUDPRoute(query, route)
			if err != nil {
				errs <- err
				return
			}
			if binary.BigEndian.Uint16(resp[:2]) != 0x1234 {
				errs <- fmt.Errorf("id not restored: %x", resp[:2])
				return
			}
			qk, _ := vpnBridgeDNSQuestionKey(query)
			rk, _ := vpnBridgeDNSQuestionKey(resp)
			if qk != rk {
				errs <- fmt.Errorf("query %d got answer for another question", i)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := proxy.associates.Load(); got != 1 {
		t.Fatalf("udp associates=%d want 1", got)
	}
	b.dnsMux.close()
	b.wg.Wait()
}

type testSOCKSUDPServer struct {
	addr       string
	associates atomic.Int32
}

// startTestSOCKSUDPServer runs a minimal authenticated SOCKS5 server that
// supports UDP ASSOCIATE; reply maps each datagram payload to a response.
func startTestSOCKSUDPServer(t *testing.T, reply func([]byte) []byte) *testSOCKSUDPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = relay.Close()
	})
	server := &testSOCKSUDPServer{addr: ln.Addr().String()}
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := relay.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n < 10 {
				continue
			}
			header := append([]byte(nil), buf[:10]...)
			out := append(header, reply(append([]byte(nil), buf[10:n]...))...)
			_, _ = relay.WriteToUDPAddrPort(out, from)
		}
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				head := make([]byte, 2)
				if _, err := readFull(conn, head); err != nil {
					return
				}
				methods := make([]byte, head[1])
				if _, err := readFull(conn, methods); err != nil {
					return
				}
				if err := socksServerAuthenticate(conn, methods); err != nil {
					return
				}
				req := make([]byte, 10)
				if _, err := readFull(conn, req); err != nil || req[1] != vpnBridgeSOCKSUDPAssociate {
					return
				}
				server.associates.Add(1)
				ap := relay.LocalAddr().(*net.UDPAddr).AddrPort()
				resp := []byte{socksVersion5, 0x00, 0x00, 0x01}
				resp = append(resp, ap.Addr().Unmap().AsSlice()...)
				resp = binary.BigEndian.AppendUint16(resp, ap.Port())
				_, _ = conn.Write(resp)
				one := make([]byte, 1)
				_, _ = conn.Read(one)
			}()
		}
	}()
	return server
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestVpnBridgeSOCKS5UDPConnAuthenticatesAndRoundTrips(t *testing.T) {
	proxy := startTestSOCKSUDPServer(t, func(payload []byte) []byte {
		return append([]byte("echo:"), payload...)
	})
	target := netip.MustParseAddrPort("198.51.100.1:443")
	conn, err := vpnBridgeSOCKS5UDPAssociate(context.Background(), proxy.addr, target)
	if err != nil {
		t.Fatalf("udp associate: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 3; i++ {
		msg := []byte(fmt.Sprintf("ping-%d", i))
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, vpnBridgeUDPBufLen)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if got, want := string(buf[:n]), "echo:"+string(msg); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
		small := make([]byte, 64)
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write: %v", err)
		}
		n, err = conn.Read(small)
		if err != nil || string(small[:n]) != "echo:"+string(msg) {
			t.Fatalf("small-buffer read got %q err %v", small[:n], err)
		}
	}
}
