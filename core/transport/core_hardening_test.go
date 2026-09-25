package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// --- helpers -----------------------------------------------------------

func testUDPPacket(srcPort, dstPort uint16, payload []byte) []byte {
	src := tcpip.AddrFrom4([4]byte{10, 111, 0, 2})
	dst := tcpip.AddrFrom4([4]byte{10, 111, 0, 53})
	pkt := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	udpHdr := header.UDP(pkt[header.IPv4MinimumSize:])
	udpHdr.Encode(&header.UDPFields{SrcPort: srcPort, DstPort: dstPort, Length: uint16(header.UDPMinimumSize + len(payload))})
	copy(pkt[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	// A zero UDP checksum means "not computed", which IPv4 allows.
	return pkt
}

func currentTestBridge(t *testing.T) *vpnBridgeInstance {
	t.Helper()
	vpnBridgeMu.Lock()
	defer vpnBridgeMu.Unlock()
	if vpnBridgeCurrent == nil {
		t.Fatal("bridge not running")
	}
	return vpnBridgeCurrent
}

func (b *vpnBridgeInstance) testDNSFlowCount() int {
	b.dnsFlowMu.Lock()
	defer b.dnsFlowMu.Unlock()
	return len(b.dnsFlows)
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// stubDoH answers every DoH request with a positive answer for the query.
func stubDoH(calls *atomic.Int32) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		query, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(vpnBridgeTestDNSResponse(query, 60))),
			Header:     make(http.Header),
		}, nil
	})}
}

func newTestDNSBridge(t *testing.T) *vpnBridgeInstance {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	b := &vpnBridgeInstance{ctx: ctx, cancel: cancel, dnsAddr: "1.1.1.1:53", dnsSem: make(chan struct{}, vpnBridgeDNSMaxParallel)}
	b.dnsMux.b = b
	t.Cleanup(func() {
		cancel()
		b.dnsMux.close()
		b.beginStop()
		b.wg.Wait()
	})
	return b
}

func setTestUDPRoute(t *testing.T, route string) {
	t.Helper()
	old := vpnBridgeCurrentUDPRoute()
	vpnBridgeUDPRoute.Store(route)
	t.Cleanup(func() { vpnBridgeUDPRoute.Store(old) })
}

// --- APP-M24 / APP-I3: DNS flow limits ---------------------------------

func TestVpnBridgeDNSFlowsAreBoundedAndCloseWhenIdle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()
	oldAddr := vpnBridgeSOCKSAddr
	vpnBridgeSOCKSAddr = deadAddr // DoH fails fast, nothing is answered
	setTestUDPRoute(t, "")
	t.Cleanup(func() {
		StopVpnBridge()
		vpnBridgeSOCKSAddr = oldAddr
	})
	fd, peer := testTunPair(t)
	startTestBridge(t, fd)
	b := currentTestBridge(t)

	query := vpnBridgeTestDNSQueryName("flood.example")
	const flows = 3 * vpnBridgeMaxDNSFlows
	maxSeen := 0
	for i := 0; i < flows; i++ {
		if _, err := peer.Write(testUDPPacket(uint16(20000+i), 53, query)); err != nil {
			t.Fatal(err)
		}
		if n := b.testDNSFlowCount(); n > maxSeen {
			maxSeen = n
		}
	}
	waitFor(t, 5*time.Second, func() bool { return b.stats.dnsQueries.Load() >= vpnBridgeMaxDNSFlows }, "queries")
	if maxSeen > vpnBridgeMaxDNSFlows {
		t.Fatalf("dns flows=%d exceed limit %d", maxSeen, vpnBridgeMaxDNSFlows)
	}
	waitFor(t, 5*time.Second, func() bool { return b.stats.dnsEvicted.Load() > 0 }, "lru eviction")
	// All flows end shortly after going idle.
	waitFor(t, 10*time.Second, func() bool { return b.testDNSFlowCount() == 0 }, "idle dns flows to close")
}

func TestVpnBridgeDNSDropsShortDatagrams(t *testing.T) {
	setTestUDPRoute(t, "")
	t.Cleanup(func() { StopVpnBridge() })
	fd, peer := testTunPair(t)
	startTestBridge(t, fd)
	b := currentTestBridge(t)
	for _, payload := range [][]byte{{}, {1, 2, 3}, make([]byte, vpnBridgeDNSHeaderLen-1)} {
		if _, err := peer.Write(testUDPPacket(30000, 53, payload)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 5*time.Second, func() bool { return b.stats.dnsDropped.Load() >= 2 }, "short datagrams to be dropped")
	if q := b.stats.dnsQueries.Load(); q != 0 {
		t.Fatalf("short datagrams were forwarded as queries: %d", q)
	}
}

func TestVpnBridgeResolveDNSRejectsShortQuery(t *testing.T) {
	b := newTestDNSBridge(t)
	var calls atomic.Int32
	b.doh = stubDoH(&calls)
	if _, err := b.resolveDNS([]byte{1, 2, 3}); err == nil {
		t.Fatal("short query resolved")
	}
	if calls.Load() != 0 {
		t.Fatal("short query was sent to DoH")
	}
}

// --- APP-L34: head start, DoH race and circuit breaker -----------------

func TestVpnBridgeDNSFallsBackToDoHAfterHeadStartAndTripsBreaker(t *testing.T) {
	proxy := startTestSOCKSUDPServer(t, func([]byte) []byte { return nil }) // dead leg: never answers
	_ = proxy
	b := newTestDNSBridge(t)
	var dohCalls atomic.Int32
	b.doh = stubDoH(&dohCalls)
	setTestUDPRoute(t, "dead@"+proxy.addr)

	for i := 0; i < vpnBridgeDNSBreakerThreshold; i++ {
		start := time.Now()
		resp, err := b.resolveDNS(vpnBridgeTestDNSQueryName(fmt.Sprintf("slow%d.example", i)))
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if len(resp) < vpnBridgeDNSHeaderLen {
			t.Fatal("empty answer")
		}
		if d := time.Since(start); d >= vpnBridgeDNSQueryTO {
			t.Fatalf("query %d took %s: DoH did not race the dead UDP leg", i, d)
		}
	}
	if b.dnsBreaker.allow(time.Now()) {
		t.Fatal("breaker did not open after repeated UDP failures")
	}
	start := time.Now()
	if _, err := b.resolveDNS(vpnBridgeTestDNSQueryName("fast.example")); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d >= vpnBridgeDNSDoHHeadStart {
		t.Fatalf("open breaker still waited for the UDP head start: %s", d)
	}
}

func TestVpnBridgeDNSBreaker(t *testing.T) {
	var c vpnBridgeDNSBreaker
	now := time.Now()
	for i := 0; i < vpnBridgeDNSBreakerThreshold-1; i++ {
		if c.failure(now) {
			t.Fatal("opened early")
		}
	}
	if !c.failure(now) || c.allow(now) {
		t.Fatal("breaker not open at threshold")
	}
	later := now.Add(vpnBridgeDNSBreakerCooldown)
	if !c.allow(later) {
		t.Fatal("breaker not half-open after cooldown")
	}
	if !c.failure(later) {
		t.Fatal("single failure after cooldown did not re-open")
	}
	c.success()
	if !c.allow(later) {
		t.Fatal("success did not close the breaker")
	}
}

// --- APP-L35: random IDs, question check, SOCKS UDP source filter -------

func TestVpnBridgeDNSMuxUsesRandomIDs(t *testing.T) {
	var mu sync.Mutex
	var ids []uint16
	proxy := startTestSOCKSUDPServer(t, func(payload []byte) []byte {
		mu.Lock()
		ids = append(ids, binary.BigEndian.Uint16(payload[:2]))
		mu.Unlock()
		return vpnBridgeTestDNSResponse(payload, 60)
	})
	b := newTestDNSBridge(t)
	route := "test@" + proxy.addr
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 16; i++ {
		if _, err := b.resolveDNSOverUDPRoute(ctx, vpnBridgeTestDNSQueryName(fmt.Sprintf("r%d.example", i)), route); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	sequential := true
	for i := 1; i < len(ids); i++ {
		if ids[i] != ids[i-1]+1 {
			sequential = false
		}
	}
	if sequential {
		t.Fatalf("upstream ids are sequential: %v", ids)
	}
}

func TestVpnBridgeDNSMuxIgnoresAnswerForOtherQuestion(t *testing.T) {
	proxy := startTestSOCKSUDPServer(t, func(payload []byte) []byte {
		other := vpnBridgeTestDNSQueryName("attacker.example")
		copy(other[:2], payload[:2]) // right ID, wrong question
		return vpnBridgeTestDNSResponse(other, 60)
	})
	b := newTestDNSBridge(t)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := b.resolveDNSOverUDPRoute(ctx, vpnBridgeTestDNSQueryName("victim.example"), "test@"+proxy.addr); err == nil {
		t.Fatal("answer for another question accepted")
	}
	if b.stats.dnsMismatched.Load() == 0 {
		t.Fatal("mismatch not counted")
	}
}

func TestVpnBridgeDNSAnswerMatches(t *testing.T) {
	query := vpnBridgeTestDNSQueryName("a.example")
	q, _ := vpnBridgeDNSQuestionKey(query)
	if !vpnBridgeDNSAnswerMatches(q, vpnBridgeTestDNSResponse(query, 60)) {
		t.Fatal("matching answer rejected")
	}
	if vpnBridgeDNSAnswerMatches(q, query) {
		t.Fatal("query (QR=0) accepted as answer")
	}
	refused := make([]byte, vpnBridgeDNSHeaderLen)
	binary.BigEndian.PutUint16(refused[2:4], 0x8005)
	if !vpnBridgeDNSAnswerMatches(q, refused) {
		t.Fatal("question-less error answer rejected")
	}
	noerror := make([]byte, vpnBridgeDNSHeaderLen)
	binary.BigEndian.PutUint16(noerror[2:4], 0x8000)
	if vpnBridgeDNSAnswerMatches(q, noerror) {
		t.Fatal("question-less NOERROR accepted")
	}
}

func TestVpnBridgeSOCKS5UDPConnDropsForeignSource(t *testing.T) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	target := netip.MustParseAddrPort("198.51.100.1:53")
	relayAddr := relay.LocalAddr().(*net.UDPAddr)
	c := &vpnBridgeSOCKS5UDPConn{
		control: nopConn{},
		udp:     local,
		relay:   relayAddr,
		relayAP: relayAddr.AddrPort(),
		target:  target,
	}
	defer c.Close()
	foreign, _ := vpnBridgeBuildSOCKS5UDPDatagram(netip.MustParseAddrPort("203.0.113.9:53"), []byte("forged"))
	wrongPort, _ := vpnBridgeBuildSOCKS5UDPDatagram(netip.MustParseAddrPort("198.51.100.1:54"), []byte("forged"))
	genuine, _ := vpnBridgeBuildSOCKS5UDPDatagram(target, []byte("genuine"))
	for _, frame := range [][]byte{foreign, wrongPort, genuine} {
		if _, err := relay.WriteToUDP(frame, local.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "genuine" {
		t.Fatalf("got %q from a foreign source", got)
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

// --- APP-L42: cache adopts the current query ---------------------------

func TestVpnBridgeDNSCacheAdoptsQuestionCaseAndFlags(t *testing.T) {
	var cache vpnBridgeDNSCache
	now := time.Now()
	first := vpnBridgeTestDNSQueryName("MiXeD.Example")
	binary.BigEndian.PutUint16(first[2:4], 0x0100) // RD
	resp := vpnBridgeTestDNSResponse(first, 300)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180) // QR RD RA
	cache.put(first, resp, now)

	second := vpnBridgeTestDNSQueryName("mIxEd.eXAMPLE")
	binary.BigEndian.PutUint16(second[0:2], 0xbeef)
	binary.BigEndian.PutUint16(second[2:4], 0x0010) // CD, no RD
	got, ok := cache.get(second, now, false)
	if !ok {
		t.Fatal("cache miss")
	}
	qEnd, _ := vpnBridgeDNSQuestionEnd(second)
	if !bytes.Equal(got[vpnBridgeDNSHeaderLen:qEnd], second[vpnBridgeDNSHeaderLen:qEnd]) {
		t.Fatalf("question not taken from the current query: %q", got[vpnBridgeDNSHeaderLen:qEnd])
	}
	flags := binary.BigEndian.Uint16(got[2:4])
	if flags&0x0100 != 0 || flags&0x0010 == 0 {
		t.Fatalf("RD/CD not taken from the current query: %#04x", flags)
	}
	if flags&0x8080 != 0x8080 {
		t.Fatalf("QR/RA lost: %#04x", flags)
	}
	if binary.BigEndian.Uint16(got[:2]) != 0xbeef {
		t.Fatal("id not rewritten")
	}
}

// --- APP-M25 / APP-L38: SOCKS pre-auth budget and accept loop ----------

func TestSOCKSPreAuthUsesSeparateBudget(t *testing.T) {
	server, err := startSOCKSServer("127.0.0.1:0", 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.close()

	authed, err := net.Dial("tcp", server.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer authed.Close()
	if err := socksClientAuthenticate(authed); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(server.sem) == 1 && len(server.preAuth) == 0 }, "authenticated conn to move to a main slot")

	silent, err := net.Dial("tcp", server.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	waitFor(t, 2*time.Second, func() bool { return len(server.preAuth) == 1 }, "silent conn in pre-auth budget")
	if n := len(server.sem); n != 1 {
		t.Fatalf("unauthenticated connection holds a main slot: sem=%d", n)
	}
}

func TestSOCKSPreAuthTimeoutClosesSilentClient(t *testing.T) {
	old := socksPreAuthTimeout
	socksPreAuthTimeout = 100 * time.Millisecond
	defer func() { socksPreAuthTimeout = old }()
	server, err := startSOCKSServer("127.0.0.1:0", 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.close()
	silent, err := net.Dial("tcp", server.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	_ = silent.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := silent.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("silent pre-auth client was not closed")
	}
	waitFor(t, 2*time.Second, func() bool { return len(server.preAuth) == 0 }, "pre-auth slot release")
}

func TestSOCKSAcceptPermanentErrorKeepsRetryingAndReportsDead(t *testing.T) {
	oldMin, oldMax, oldFail := socksAcceptBackoffMin, socksAcceptBackoffMax, socksAcceptFailBackoffMax
	socksAcceptBackoffMin, socksAcceptBackoffMax, socksAcceptFailBackoffMax = time.Millisecond, time.Millisecond, time.Millisecond
	defer func() {
		socksAcceptBackoffMin, socksAcceptBackoffMax, socksAcceptFailBackoffMax = oldMin, oldMax, oldFail
	}()
	permanent := errors.New("accept: bad file descriptor")
	listener := &scriptedListener{errs: []error{permanent, permanent, permanent}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &socksServer{listener: listener, ctx: ctx, cancel: cancel}
	server.wg.Add(1)
	server.serve(ctx)
	if got := listener.calls.Load(); got != 4 {
		t.Fatalf("Accept calls=%d, want 4 (loop stopped on a permanent error)", got)
	}
	if !server.isDead() {
		t.Fatal("failing listener not reported as dead")
	}
}

// --- APP-L3: no destinations in release logs --------------------------

func TestReleaseLogsOmitDestinations(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	oldOut := log.Writer()
	log.SetOutput(lockedWriter{w: &buf, mu: &mu})
	defer log.SetOutput(oldOut)
	code := socksReplyCodeForRequest(t, socksConnectRequestIPv6(net.ParseIP("2001:db8::77"), 443))
	if code != 0x08 {
		t.Fatalf("reply=%#x", code)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(buf.String(), "2001:db8::77") {
		t.Fatalf("destination logged: %q", buf.String())
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// --- APP-I5: panics in flow goroutines are contained -------------------

func TestVpnBridgeWorkerPanicIsRecovered(t *testing.T) {
	b := newTestDNSBridge(t)
	before := recoveredPanics.Load()
	done := make(chan struct{})
	if !b.startWorker(func() {
		defer close(done)
		panic("boom")
	}) {
		t.Fatal("worker not started")
	}
	<-done
	b.wg.Wait()
	if recoveredPanics.Load() != before+1 {
		t.Fatal("panic not counted")
	}
}

type panicConn struct{ net.Conn }

func (panicConn) Read([]byte) (int, error) { panic("read boom") }

func TestProxyPairSurvivesPanickingConn(t *testing.T) {
	left, leftPeer := net.Pipe()
	defer leftPeer.Close()
	right, rightPeer := net.Pipe()
	defer rightPeer.Close()
	done := make(chan error, 1)
	go func() { done <- proxyPair(panicConn{left}, right, time.Second, nil, nil) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("proxyPair hung after a panicking copy")
	}
}

// --- fuzz targets (seed corpora run as ordinary tests) ------------------

func FuzzVpnBridgeDNSMessage(f *testing.F) {
	q := vpnBridgeTestDNSQueryName("fuzz.example")
	f.Add(q, vpnBridgeTestDNSResponse(q, 60))
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 12), make([]byte, 11))
	f.Add(vpnBridgeTestDNSQuery(4096), []byte{0, 0, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c})
	f.Fuzz(func(t *testing.T, query, response []byte) {
		_, _ = vpnBridgeDNSQuestionKey(query)
		_, _, _, _ = vpnBridgeDNSPositiveTTLs(response)
		_ = vpnBridgeDNSUDPSize(query)
		_ = vpnBridgeDNSTruncatedResponse(query)
		_ = vpnBridgeDNSFitUDP(query, response)
		q, _ := vpnBridgeDNSQuestionKey(query)
		_ = vpnBridgeDNSAnswerMatches(q, response)
		var cache vpnBridgeDNSCache
		now := time.Now()
		cache.put(query, response, now)
		if got, ok := cache.get(query, now, false); ok && len(got) != len(response) {
			t.Fatalf("cached length changed: %d != %d", len(got), len(response))
		}
		_, _ = cache.get(query, now.Add(time.Hour), true)
	})
}

func FuzzVpnBridgeSOCKS5UDPDatagram(f *testing.F) {
	frame, _ := vpnBridgeBuildSOCKS5UDPDatagram(netip.MustParseAddrPort("198.51.100.1:53"), []byte("x"))
	f.Add(frame)
	f.Add([]byte{0, 0, 0, 3, 5, 'a'})
	f.Add([]byte{0, 0, 0, 4})
	f.Fuzz(func(t *testing.T, frame []byte) {
		_, _ = vpnBridgeParseSOCKS5UDPDatagram(frame)
		_, _, _ = vpnBridgeParseSOCKS5UDPDatagramFrom(frame)
		_ = vpnBridgeReadSOCKS5ConnectResponse(bytes.NewReader(frame))
		_, _ = vpnBridgeReadSOCKS5UDPAssociateResponse(bytes.NewReader(frame), "127.0.0.1")
	})
}

func FuzzReadSOCKSConnect(f *testing.F) {
	f.Add(socksConnectRequestDomain("example.com", 443))
	f.Add(socksConnectRequestIPv6(net.ParseIP("2001:db8::1"), 443))
	f.Add([]byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80})
	f.Add([]byte{5, 1, 0, 3, 255})
	f.Fuzz(func(t *testing.T, req []byte) {
		_, _ = readSOCKSConnect(bytes.NewReader(req))
		rw := struct {
			io.Reader
			io.Writer
		}{bytes.NewReader(req), io.Discard}
		_ = socksHandshake(rw)
	})
}
