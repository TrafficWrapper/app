package transport

import (
	"bytes"
	"container/list"
	"context"
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
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	vpnBridgeDNSHeaderLen = 12
	vpnBridgeDNSTypeOPT   = 41
)

// handleDNS serves one app-side DNS 5-tuple. Queries are answered
// concurrently (bounded by the bridge-wide dnsSem) so a slow upstream answer
// does not stall later queries from the same socket.
func (b *vpnBridgeInstance) handleDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	untrackConn := b.trackConn(conn)
	defer untrackConn()
	var inflight sync.WaitGroup
	defer inflight.Wait()
	bufPtr := vpnBridgeUDPBuffers.Get().(*[]byte)
	defer vpnBridgeUDPBuffers.Put(bufPtr)
	buf := *bufPtr
	for {
		if b.ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(vpnBridgeDNSIdleTO))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if vpnBridgeIsTimeout(err) || b.ctx.Err() != nil {
				return
			}
			b.stats.dnsFailures.Add(1)
			return
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
		if !b.startWorker(func() {
			defer inflight.Done()
			defer func() { <-b.dnsSem }()
			b.answerDNS(conn, query)
		}) {
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
		log.Printf("transport: vpn bridge dns query failed: %v", err)
		return
	}
	response = vpnBridgeDNSFitUDP(query, response)
	b.stats.dnsBytesDown.Add(uint64(len(response)))
	_ = conn.SetWriteDeadline(time.Now().Add(vpnBridgeDNSQueryTO))
	if _, err := conn.Write(response); err != nil && b.ctx.Err() == nil {
		b.stats.dnsFailures.Add(1)
	}
}

func (b *vpnBridgeInstance) resolveDNS(query []byte) ([]byte, error) {
	if cached, ok := b.dnsCache.get(query, time.Now(), false); ok {
		return cached, nil
	}
	route := vpnBridgeCurrentUDPRoute()
	routeLabel := vpnBridgeRouteLabel(route)
	if route != "" {
		response, err := b.resolveDNSOverUDPRoute(query, route)
		if err == nil {
			b.dnsCache.put(query, response, time.Now())
			return response, nil
		}
		log.Printf("transport: vpn bridge tunnel dns failed route=%s: %v", routeLabel, err)
	}
	response, err := b.resolveDNSOverHTTPS(query)
	if err == nil {
		log.Printf("transport: vpn bridge dns_fallback_used=doh route=%s", routeLabel)
		b.dnsCache.put(query, response, time.Now())
		return response, nil
	}
	if cached, ok := b.dnsCache.get(query, time.Now(), true); ok {
		log.Printf("transport: vpn bridge dns_fallback_used=cache route=%s", routeLabel)
		return cached, nil
	}
	return nil, err
}

func (b *vpnBridgeInstance) resolveDNSOverUDPRoute(query []byte, route string) ([]byte, error) {
	if route == "" {
		return nil, errors.New("udp route disabled")
	}
	target, err := vpnBridgeAddrPortTarget(b.dnsAddr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(b.ctx, vpnBridgeDNSQueryTO)
	defer cancel()
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

func (b *vpnBridgeInstance) resolveDNSOverHTTPS(query []byte) ([]byte, error) {
	if b.doh == nil {
		return nil, errors.New("doh client unavailable")
	}
	ctx, cancel := context.WithTimeout(b.ctx, vpnBridgeDNSQueryTO)
	defer cancel()
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
	if len(body) < 2 {
		return nil, errors.New("empty doh response")
	}
	if len(body) > vpnBridgeMaxDNSUDP {
		return nil, fmt.Errorf("doh response too large: %d", len(body))
	}
	copy(body[:2], query[:2])
	return body, nil
}

// vpnBridgeDNSMux multiplexes DNS queries over one long-lived UDP flow per
// route instead of a fresh UDP ASSOCIATE (or netstack socket) per query.
// Upstream transaction IDs are rewritten so queries from different apps
// cannot collide.
type vpnBridgeDNSMux struct {
	b       *vpnBridgeInstance
	mu      sync.Mutex
	cur     *vpnBridgeDNSMuxConn
	dialing *vpnBridgeDNSMuxDial
	nextID  uint16
	closed  bool
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
	pending   map[uint16]chan []byte
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
	c, err := m.conn(route, target)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if len(c.pending) >= 0xffff {
		m.mu.Unlock()
		return nil, errors.New("too many pending dns queries")
	}
	id := m.nextID
	for {
		id++
		if _, busy := c.pending[id]; !busy {
			break
		}
	}
	m.nextID = id
	ch := make(chan []byte, 1)
	c.pending[id] = ch
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(c.pending, id)
		m.mu.Unlock()
	}()

	out := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(out[:2], id)
	if _, err := c.conn.Write(out); err != nil {
		m.detach(c)
		return nil, err
	}
	select {
	case resp := <-ch:
		copy(resp[:2], query[:2])
		return resp, nil
	case <-c.done:
		return nil, errors.New("dns upstream closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *vpnBridgeDNSMux) conn(route string, target netip.AddrPort) (*vpnBridgeDNSMuxConn, error) {
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
		<-d.done
		return d.conn, d.err
	}
	d := &vpnBridgeDNSMuxDial{route: route, done: make(chan struct{})}
	m.dialing = d
	m.mu.Unlock()
	defer close(d.done)

	d.conn, d.err = m.dial(d, route, target)
	return d.conn, d.err
}

func (m *vpnBridgeDNSMux) dial(d *vpnBridgeDNSMuxDial, route string, target netip.AddrPort) (*vpnBridgeDNSMuxConn, error) {
	upstream, untrack, label, err := m.b.dialUDPRoute(route, target)
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
		pending: make(map[uint16]chan []byte),
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
		ch := c.pending[id]
		delete(c.pending, id)
		m.mu.Unlock()
		if ch != nil {
			ch <- append([]byte(nil), buf[:n]...)
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
	copy(response[:2], query[:2])
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
