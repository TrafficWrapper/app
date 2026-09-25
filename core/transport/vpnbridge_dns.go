package transport

import (
	"bytes"
	"container/list"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	vpnBridgeDNSHeaderLen = 12
	vpnBridgeDNSTypeOPT   = 41
)

// vpnBridgeDNSFlow is one app-side DNS 5-tuple being served.
type vpnBridgeDNSFlow struct {
	conn         io.Closer
	lastActivity atomic.Int64
	evicted      atomic.Bool
}

func (f *vpnBridgeDNSFlow) touch() {
	f.lastActivity.Store(time.Now().UnixNano())
}

// registerDNSFlow adds a flow, evicting the least recently active one when
// the bridge already serves vpnBridgeMaxDNSFlows.
func (b *vpnBridgeInstance) registerDNSFlow(flow *vpnBridgeDNSFlow) func() {
	b.dnsFlowMu.Lock()
	if b.dnsFlows == nil {
		b.dnsFlows = make(map[*vpnBridgeDNSFlow]struct{})
	}
	var victim *vpnBridgeDNSFlow
	if len(b.dnsFlows) >= vpnBridgeMaxDNSFlows {
		for candidate := range b.dnsFlows {
			if victim == nil || candidate.lastActivity.Load() < victim.lastActivity.Load() {
				victim = candidate
			}
		}
		delete(b.dnsFlows, victim)
	}
	b.dnsFlows[flow] = struct{}{}
	b.dnsFlowMu.Unlock()
	if victim != nil {
		b.stats.dnsEvicted.Add(1)
		victim.evicted.Store(true)
		_ = victim.conn.Close()
	}
	return func() {
		b.dnsFlowMu.Lock()
		delete(b.dnsFlows, flow)
		b.dnsFlowMu.Unlock()
	}
}

// handleDNS serves one app-side DNS 5-tuple. Queries are answered
// concurrently (bounded by the bridge-wide dnsSem) so a slow upstream answer
// does not stall later queries from the same socket. The number of flows is
// bounded (LRU eviction), each uses a small read buffer, and a flow ends once
// it has been idle for vpnBridgeDNSIdleTO with no answer outstanding.
func (b *vpnBridgeInstance) handleDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	untrackConn := b.trackConn(conn)
	defer untrackConn()
	flow := &vpnBridgeDNSFlow{conn: conn}
	flow.touch()
	unregister := b.registerDNSFlow(flow)
	defer unregister()
	var inflight sync.WaitGroup
	defer inflight.Wait()
	var outstanding atomic.Int32
	buf := make([]byte, vpnBridgeDNSQueryBufLen)
	for {
		if b.ctx.Err() != nil || flow.evicted.Load() {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(vpnBridgeDNSIdleTO))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if b.ctx.Err() != nil || flow.evicted.Load() {
				return
			}
			if vpnBridgeIsTimeout(err) {
				if outstanding.Load() > 0 {
					continue // keep the socket until pending answers are sent
				}
				return
			}
			b.stats.dnsFailures.Add(1)
			return
		}
		flow.touch()
		if n < vpnBridgeDNSHeaderLen {
			// Not a DNS message; never forward it upstream.
			b.stats.dnsDropped.Add(1)
			continue
		}
		query := append([]byte(nil), buf[:n]...)
		b.stats.dnsQueries.Add(1)
		b.stats.dnsBytesUp.Add(uint64(len(query)))
		select {
		case b.dnsSem <- struct{}{}:
		case <-b.ctx.Done():
			return
		}
		inflight.Add(1)
		outstanding.Add(1)
		if !b.startWorker(func() {
			defer inflight.Done()
			defer outstanding.Add(-1)
			defer func() { <-b.dnsSem }()
			b.answerDNS(conn, query)
		}) {
			outstanding.Add(-1)
			inflight.Done()
			<-b.dnsSem
			return
		}
	}
}

func (b *vpnBridgeInstance) answerDNS(conn *gonet.UDPConn, query []byte) {
	response, err := b.resolveDNS(query)
	if err != nil {
		b.stats.dnsFailures.Add(1)
		debugLogf("transport: vpn bridge dns query failed: %v", err)
		return
	}
	response = vpnBridgeDNSFitUDP(query, response)
	b.stats.dnsBytesDown.Add(uint64(len(response)))
	_ = conn.SetWriteDeadline(time.Now().Add(vpnBridgeDNSQueryTO))
	if _, err := conn.Write(response); err != nil && b.ctx.Err() == nil {
		b.stats.dnsFailures.Add(1)
	}
}

// resolveDNS answers query from the cache, the tunnel UDP route (dnsAddr)
// or DoH. The UDP route gets a short head start before DoH is raced against
// it, and a circuit breaker skips a UDP route that keeps failing.
func (b *vpnBridgeInstance) resolveDNS(query []byte) ([]byte, error) {
	if len(query) < vpnBridgeDNSHeaderLen {
		return nil, errors.New("short dns query")
	}
	if cached, ok := b.dnsCache.get(query, time.Now(), false); ok {
		return cached, nil
	}
	route := vpnBridgeCurrentUDPRoute()
	var (
		response []byte
		err      error
	)
	if route != "" && b.dnsBreaker.allow(time.Now()) {
		response, err = b.resolveDNSRace(query, route)
	} else {
		ctx, cancel := context.WithTimeout(b.ctx, vpnBridgeDNSQueryTO)
		response, err = b.resolveDNSOverHTTPS(ctx, query)
		cancel()
	}
	if err == nil {
		b.dnsCache.put(query, response, time.Now())
		return response, nil
	}
	if cached, ok := b.dnsCache.get(query, time.Now(), true); ok {
		b.stats.dnsStaleServed.Add(1)
		return cached, nil
	}
	return nil, err
}

type vpnBridgeDNSResult struct {
	response []byte
	err      error
	doh      bool
}

// resolveDNSRace queries the UDP route and, if it has not answered within
// vpnBridgeDNSDoHHeadStart (or failed earlier), DoH in parallel; the first
// good answer wins. The UDP route's outcome feeds the circuit breaker.
func (b *vpnBridgeInstance) resolveDNSRace(query []byte, route string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(b.ctx, vpnBridgeDNSQueryTO+vpnBridgeDNSDoHHeadStart)
	defer cancel()
	results := make(chan vpnBridgeDNSResult, 2)
	running := 0
	if b.startWorker(func() {
		response, err := b.resolveDNSOverUDPRoute(ctx, query, route)
		results <- vpnBridgeDNSResult{response: response, err: err}
	}) {
		running++
	} else {
		return nil, errors.New("vpn bridge stopped")
	}
	dohStarted := false
	startDoH := func() {
		if dohStarted {
			return
		}
		dohStarted = true
		if b.startWorker(func() {
			response, err := b.resolveDNSOverHTTPS(ctx, query)
			results <- vpnBridgeDNSResult{response: response, err: err, doh: true}
		}) {
			running++
		}
	}
	headStart := time.NewTimer(vpnBridgeDNSDoHHeadStart)
	defer headStart.Stop()
	udpDone := false
	var lastErr error
	for running > 0 {
		select {
		case r := <-results:
			running--
			if !r.doh {
				udpDone = true
				if r.err == nil {
					b.dnsBreaker.success()
				} else {
					b.recordDNSRouteFailure(route)
					debugLogf("transport: vpn bridge tunnel dns failed route=%s: %v", vpnBridgeRouteLabel(route), r.err)
				}
			}
			if r.err == nil {
				if r.doh {
					b.stats.dnsDoHFallback.Add(1)
					if !udpDone {
						// DoH beat the UDP route's head start: count it as
						// a route failure so a dead leg trips the breaker.
						b.recordDNSRouteFailure(route)
					}
				}
				return r.response, nil
			}
			lastErr = r.err
			if !r.doh {
				startDoH()
			}
		case <-headStart.C:
			startDoH()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("dns resolution failed")
	}
	return nil, lastErr
}

func (b *vpnBridgeInstance) recordDNSRouteFailure(route string) {
	if b.dnsBreaker.failure(time.Now()) {
		b.stats.dnsBreakerTrip.Add(1)
		log.Printf("transport: vpn bridge tunnel dns route=%s failing; using doh for %s", vpnBridgeRouteLabel(route), vpnBridgeDNSBreakerCooldown)
	}
}

// vpnBridgeDNSBreaker remembers a failing UDP DNS route so each uncached
// query does not pay the head start again. After
// vpnBridgeDNSBreakerThreshold consecutive failures the route is skipped for
// vpnBridgeDNSBreakerCooldown; afterwards a single failure re-opens it and a
// success closes it.
type vpnBridgeDNSBreaker struct {
	mu        sync.Mutex
	failures  int
	openUntil time.Time
}

func (c *vpnBridgeDNSBreaker) allow(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !now.Before(c.openUntil)
}

func (c *vpnBridgeDNSBreaker) success() {
	c.mu.Lock()
	c.failures = 0
	c.openUntil = time.Time{}
	c.mu.Unlock()
}

// failure records one failure and reports whether the breaker just opened.
func (c *vpnBridgeDNSBreaker) failure(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Before(c.openUntil) {
		return false
	}
	c.failures++
	if c.failures < vpnBridgeDNSBreakerThreshold {
		return false
	}
	c.openUntil = now.Add(vpnBridgeDNSBreakerCooldown)
	c.failures = vpnBridgeDNSBreakerThreshold - 1
	return true
}

func (c *vpnBridgeDNSBreaker) isOpen(now time.Time) bool {
	return !c.allow(now)
}

// resolveDNSOverUDPRoute sends query to dnsAddr over the tunnel UDP route.
// dnsAddr is only used here: with the UDP route disabled, DNS goes to DoH.
func (b *vpnBridgeInstance) resolveDNSOverUDPRoute(ctx context.Context, query []byte, route string) ([]byte, error) {
	if route == "" {
		return nil, errors.New("udp route disabled")
	}
	target, err := vpnBridgeAddrPortTarget(b.dnsAddr)
	if err != nil {
		return nil, err
	}
	return b.dnsMux.exchange(ctx, route, target, query)
}

// newDoHClient returns the pooled DoH client. Connections are dialed through
// the local SOCKS router and kept alive (HTTP/2 when negotiated), so queries
// do not pay a TCP+SOCKS+TLS handshake each.
func (b *vpnBridgeInstance) newDoHClient() *http.Client {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			conn, untrack, err := vpnBridgeSOCKS5Connect(ctx, vpnBridgeSOCKSAddr, addr, b.trackConn)
			if err != nil {
				return nil, fmt.Errorf("socks connect: %w", err)
			}
			return &vpnBridgeTrackedConn{Conn: conn, untrack: untrack}, nil
		},
		TLSClientConfig: &tls.Config{
			ServerName: vpnBridgeDoHHost,
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   vpnBridgeDNSQueryTO,
		ResponseHeaderTimeout: vpnBridgeDNSQueryTO,
	}
	return &http.Client{Transport: transport, Timeout: vpnBridgeDNSQueryTO}
}

type vpnBridgeTrackedConn struct {
	net.Conn
	once    sync.Once
	untrack func()
}

func (c *vpnBridgeTrackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.untrack)
	return err
}

func (b *vpnBridgeInstance) resolveDNSOverHTTPS(ctx context.Context, query []byte) ([]byte, error) {
	if b.doh == nil {
		return nil, errors.New("doh client unavailable")
	}
	if len(query) < vpnBridgeDNSHeaderLen {
		return nil, errors.New("short dns query")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+vpnBridgeDoHHost+vpnBridgeDoHPath, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := b.doh.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("doh http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(vpnBridgeMaxDNSUDP)+1))
	if err != nil {
		return nil, err
	}
	if len(body) < vpnBridgeDNSHeaderLen {
		return nil, errors.New("short doh response")
	}
	if len(body) > vpnBridgeMaxDNSUDP {
		return nil, fmt.Errorf("doh response too large: %d", len(body))
	}
	copy(body[:2], query[:2])
	return body, nil
}

// vpnBridgeDNSMux multiplexes DNS queries over one long-lived UDP flow per
// route instead of a fresh UDP ASSOCIATE (or netstack socket) per query.
// Upstream transaction IDs are rewritten to random, unused values so queries
// from different apps cannot collide and answers cannot be guessed; an answer
// is only accepted when its question matches the query.
type vpnBridgeDNSMux struct {
	b       *vpnBridgeInstance
	mu      sync.Mutex
	cur     *vpnBridgeDNSMuxConn
	dialing *vpnBridgeDNSMuxDial
	closed  bool
}

type vpnBridgeDNSPending struct {
	ch       chan []byte
	question string // vpnBridgeDNSQuestionKey of the query, "" if unparsable
}

type vpnBridgeDNSMuxDial struct {
	route string
	done  chan struct{}
	conn  *vpnBridgeDNSMuxConn
	err   error
}

type vpnBridgeDNSMuxConn struct {
	route     string
	conn      net.Conn
	untrack   func()
	pending   map[uint16]*vpnBridgeDNSPending
	done      chan struct{}
	closeOnce sync.Once
}

func (c *vpnBridgeDNSMuxConn) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.conn.Close()
		if c.untrack != nil {
			c.untrack()
		}
	})
}

func (m *vpnBridgeDNSMux) exchange(ctx context.Context, route string, target netip.AddrPort, query []byte) ([]byte, error) {
	if len(query) < vpnBridgeDNSHeaderLen {
		return nil, errors.New("short dns query")
	}
	c, err := m.conn(ctx, route, target)
	if err != nil {
		return nil, err
	}
	question, _ := vpnBridgeDNSQuestionKey(query)
	m.mu.Lock()
	if len(c.pending) >= vpnBridgeDNSMaxPending {
		m.mu.Unlock()
		return nil, errors.New("too many pending dns queries")
	}
	id := vpnBridgeRandomDNSID()
	for {
		if _, busy := c.pending[id]; !busy {
			break
		}
		id = vpnBridgeRandomDNSID()
	}
	p := &vpnBridgeDNSPending{ch: make(chan []byte, 1), question: question}
	c.pending[id] = p
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if c.pending[id] == p {
			delete(c.pending, id)
		}
		m.mu.Unlock()
	}()

	out := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(out[:2], id)
	if _, err := c.conn.Write(out); err != nil {
		m.detach(c)
		return nil, err
	}
	select {
	case resp := <-p.ch:
		copy(resp[:2], query[:2])
		return resp, nil
	case <-c.done:
		return nil, errors.New("dns upstream closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// vpnBridgeRandomDNSID returns an unpredictable transaction ID.
func vpnBridgeRandomDNSID() uint16 {
	var raw [2]byte
	_, _ = rand.Read(raw[:])
	return binary.BigEndian.Uint16(raw[:])
}

// vpnBridgeDNSAnswerMatches reports whether response answers the query whose
// question key is question. Error responses without a question section are
// accepted, as some servers omit it.
func vpnBridgeDNSAnswerMatches(question string, response []byte) bool {
	if len(response) < vpnBridgeDNSHeaderLen || binary.BigEndian.Uint16(response[2:4])&0x8000 == 0 {
		return false
	}
	if question == "" {
		return true
	}
	if binary.BigEndian.Uint16(response[4:6]) == 0 {
		return binary.BigEndian.Uint16(response[2:4])&0x000f != 0
	}
	got, ok := vpnBridgeDNSQuestionKey(response)
	return ok && got == question
}

func (m *vpnBridgeDNSMux) conn(ctx context.Context, route string, target netip.AddrPort) (*vpnBridgeDNSMuxConn, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("vpn bridge stopped")
	}
	if c := m.cur; c != nil {
		if c.route == route {
			m.mu.Unlock()
			return c, nil
		}
		m.detachLocked(c)
	}
	if d := m.dialing; d != nil && d.route == route {
		// Concurrent cold-start queries share one dial.
		m.mu.Unlock()
		select {
		case <-d.done:
			return d.conn, d.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	d := &vpnBridgeDNSMuxDial{route: route, done: make(chan struct{})}
	m.dialing = d
	m.mu.Unlock()
	defer close(d.done)

	// The dial is shared with other waiters, so it is bounded by its own
	// timeout rather than by the first caller's context.
	dialCtx, cancel := context.WithTimeout(m.b.ctx, vpnBridgeDNSQueryTO)
	defer cancel()
	d.conn, d.err = m.dial(dialCtx, d, route, target)
	return d.conn, d.err
}

func (m *vpnBridgeDNSMux) dial(ctx context.Context, d *vpnBridgeDNSMuxDial, route string, target netip.AddrPort) (*vpnBridgeDNSMuxConn, error) {
	upstream, untrack, label, err := m.b.dialUDPRoute(ctx, route, target)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dialing == d {
		m.dialing = nil
	}
	if err != nil {
		return nil, fmt.Errorf("udp route %s: %w", label, err)
	}
	c := &vpnBridgeDNSMuxConn{
		route:   route,
		conn:    upstream,
		untrack: untrack,
		pending: make(map[uint16]*vpnBridgeDNSPending),
		done:    make(chan struct{}),
	}
	if m.closed {
		c.close()
		return nil, errors.New("vpn bridge stopped")
	}
	if existing := m.cur; existing != nil {
		m.detachLocked(existing)
	}
	if !m.b.startWorker(func() { m.readLoop(c) }) {
		c.close()
		return nil, errors.New("vpn bridge stopped")
	}
	m.cur = c
	return c, nil
}

func (m *vpnBridgeDNSMux) readLoop(c *vpnBridgeDNSMuxConn) {
	bufPtr := vpnBridgeUDPBuffers.Get().(*[]byte)
	defer vpnBridgeUDPBuffers.Put(bufPtr)
	buf := *bufPtr
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(vpnBridgeDNSMuxIdleTO))
		n, err := c.conn.Read(buf)
		if err != nil {
			m.mu.Lock()
			if vpnBridgeIsTimeout(err) && len(c.pending) > 0 {
				m.mu.Unlock()
				continue
			}
			m.detachLocked(c)
			m.mu.Unlock()
			return
		}
		if n < vpnBridgeDNSHeaderLen {
			continue
		}
		id := binary.BigEndian.Uint16(buf[:2])
		m.mu.Lock()
		p := c.pending[id]
		if p != nil && !vpnBridgeDNSAnswerMatches(p.question, buf[:n]) {
			// Wrong or forged answer for this ID: keep waiting for the
			// real one.
			p = nil
			m.b.stats.dnsMismatched.Add(1)
		}
		if p != nil {
			delete(c.pending, id)
		}
		m.mu.Unlock()
		if p != nil {
			p.ch <- append([]byte(nil), buf[:n]...)
		}
	}
}

func (m *vpnBridgeDNSMux) detach(c *vpnBridgeDNSMuxConn) {
	m.mu.Lock()
	m.detachLocked(c)
	m.mu.Unlock()
}

func (m *vpnBridgeDNSMux) detachLocked(c *vpnBridgeDNSMuxConn) {
	if m.cur == c {
		m.cur = nil
	}
	c.close()
}

func (m *vpnBridgeDNSMux) close() {
	m.mu.Lock()
	m.closed = true
	if m.cur != nil {
		m.detachLocked(m.cur)
	}
	m.mu.Unlock()
}

// vpnBridgeDNSCache is a bounded LRU of positive DNS answers keyed by the
// question (qname case-insensitively, qtype, qclass). Entries live for the
// minimum RR TTL (capped), TTLs are decremented on the way out, and the
// transaction ID of the asking query is substituted.
type vpnBridgeDNSCache struct {
	mu    sync.Mutex
	ll    *list.List
	items map[string]*list.Element
}

type vpnBridgeDNSCacheEntry struct {
	key        string
	response   []byte
	ttlOffsets []int
	ttls       []uint32
	storedAt   time.Time
	expiresAt  time.Time
}

func (c *vpnBridgeDNSCache) put(query, response []byte, now time.Time) {
	key, ok := vpnBridgeDNSQuestionKey(query)
	if !ok {
		return
	}
	respKey, ok := vpnBridgeDNSQuestionKey(response)
	if !ok || respKey != key {
		return
	}
	offsets, ttls, minTTL, ok := vpnBridgeDNSPositiveTTLs(response)
	if !ok || minTTL == 0 {
		return
	}
	ttl := time.Duration(minTTL) * time.Second
	if ttl > vpnBridgeDNSCacheMaxTTL {
		ttl = vpnBridgeDNSCacheMaxTTL
	}
	entry := &vpnBridgeDNSCacheEntry{
		key:        key,
		response:   append([]byte(nil), response...),
		ttlOffsets: offsets,
		ttls:       ttls,
		storedAt:   now,
		expiresAt:  now.Add(ttl),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = make(map[string]*list.Element)
		c.ll = list.New()
	}
	if el, ok := c.items[key]; ok {
		el.Value = entry
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(entry)
	for c.ll.Len() > vpnBridgeDNSCacheSize {
		oldest := c.ll.Back()
		c.ll.Remove(oldest)
		delete(c.items, oldest.Value.(*vpnBridgeDNSCacheEntry).key)
	}
}

// get returns a cached answer for query. With allowStale, entries up to
// vpnBridgeDNSStaleTTL past expiry are served (with a short TTL) as a last
// resort when every upstream failed.
func (c *vpnBridgeDNSCache) get(query []byte, now time.Time, allowStale bool) ([]byte, bool) {
	key, ok := vpnBridgeDNSQuestionKey(query)
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	entry := el.Value.(*vpnBridgeDNSCacheEntry)
	stale := !now.Before(entry.expiresAt)
	if stale {
		if now.After(entry.expiresAt.Add(vpnBridgeDNSStaleTTL)) {
			c.ll.Remove(el)
			delete(c.items, key)
			return nil, false
		}
		if !allowStale {
			return nil, false
		}
	}
	c.ll.MoveToFront(el)
	response := append([]byte(nil), entry.response...)
	vpnBridgeDNSAdoptQuery(response, query)
	elapsed := uint32(now.Sub(entry.storedAt) / time.Second)
	for i, off := range entry.ttlOffsets {
		ttl := uint32(vpnBridgeDNSStaleServe)
		if !stale {
			ttl = 1
			if entry.ttls[i] > elapsed+1 {
				ttl = entry.ttls[i] - elapsed
			}
		}
		binary.BigEndian.PutUint32(response[off:off+4], ttl)
	}
	return response, true
}

// vpnBridgeDNSAdoptQuery rewrites a cached response for the current query:
// its transaction ID, its question section as sent (0x20 case randomization)
// and its RD and CD flags. Both messages share the same question key, so the
// question sections have the same length.
func vpnBridgeDNSAdoptQuery(response, query []byte) {
	if len(response) < vpnBridgeDNSHeaderLen || len(query) < vpnBridgeDNSHeaderLen {
		return
	}
	copy(response[:2], query[:2])
	const rdCD = 0x0100 | 0x0010
	flags := binary.BigEndian.Uint16(response[2:4])&^rdCD | binary.BigEndian.Uint16(query[2:4])&rdCD
	binary.BigEndian.PutUint16(response[2:4], flags)
	qEnd, okQ := vpnBridgeDNSQuestionEnd(query)
	rEnd, okR := vpnBridgeDNSQuestionEnd(response)
	if okQ && okR && qEnd == rEnd {
		copy(response[vpnBridgeDNSHeaderLen:qEnd], query[vpnBridgeDNSHeaderLen:qEnd])
	}
}

func (c *vpnBridgeDNSCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ll == nil {
		return 0
	}
	return c.ll.Len()
}

// vpnBridgeDNSQuestionKey returns a cache key for a message with exactly one
// question: the lower-cased wire qname followed by qtype and qclass. The
// header (ID, flags) and EDNS options are deliberately not part of the key.
func vpnBridgeDNSQuestionKey(msg []byte) (string, bool) {
	if len(msg) < vpnBridgeDNSHeaderLen || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return "", false
	}
	off := vpnBridgeDNSHeaderLen
	key := make([]byte, 0, 64)
	for {
		if off >= len(msg) {
			return "", false
		}
		l := int(msg[off])
		if l&0xc0 != 0 {
			return "", false
		}
		key = append(key, byte(l))
		off++
		if l == 0 {
			break
		}
		if off+l > len(msg) || len(key)+l > 255 {
			return "", false
		}
		for _, ch := range msg[off : off+l] {
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			key = append(key, ch)
		}
		off += l
	}
	if off+4 > len(msg) {
		return "", false
	}
	key = append(key, msg[off:off+4]...)
	return string(key), true
}

// vpnBridgeDNSPositiveTTLs validates that response is a complete, untruncated
// NOERROR answer with at least one answer RR and returns the offsets and
// values of every RR TTL (OPT excluded) and their minimum.
func vpnBridgeDNSPositiveTTLs(msg []byte) ([]int, []uint32, uint32, bool) {
	if len(msg) < vpnBridgeDNSHeaderLen {
		return nil, nil, 0, false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 || flags&0x0200 != 0 || flags&0x000f != 0 {
		return nil, nil, 0, false
	}
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	nsCount := int(binary.BigEndian.Uint16(msg[8:10]))
	arCount := int(binary.BigEndian.Uint16(msg[10:12]))
	if anCount == 0 {
		return nil, nil, 0, false
	}
	off, ok := vpnBridgeDNSQuestionEnd(msg)
	if !ok {
		return nil, nil, 0, false
	}
	var (
		offsets []int
		ttls    []uint32
		minTTL  uint32
		haveMin bool
	)
	for i := 0; i < anCount+nsCount+arCount; i++ {
		next, ok := vpnBridgeDNSNameEnd(msg, off)
		if !ok || next+10 > len(msg) {
			return nil, nil, 0, false
		}
		rrType := binary.BigEndian.Uint16(msg[next : next+2])
		ttl := binary.BigEndian.Uint32(msg[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		off = next + 10 + rdLen
		if off > len(msg) {
			return nil, nil, 0, false
		}
		if rrType == vpnBridgeDNSTypeOPT {
			continue
		}
		offsets = append(offsets, next+4)
		ttls = append(ttls, ttl)
		if !haveMin || ttl < minTTL {
			minTTL = ttl
			haveMin = true
		}
	}
	return offsets, ttls, minTTL, true
}
