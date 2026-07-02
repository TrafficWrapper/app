package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	vpnBridgeSOCKSAddr       = defaultSOCKSListen
	vpnBridgeDefaultDNSAddr  = "1.1.1.1:53"
	vpnBridgeDoHAddr         = "cloudflare-dns.com:443"
	vpnBridgeDoHHost         = "cloudflare-dns.com"
	vpnBridgeDoHPath         = "/dns-query"
	vpnBridgeDefaultMTU      = 1500
	vpnBridgeNICID           = tcpip.NICID(910)
	vpnBridgeTCPConnectTO    = 30 * time.Second
	vpnBridgeTCPIdleTO       = 3 * time.Minute
	vpnBridgeUDPIdleTO       = 3 * time.Minute
	vpnBridgeDNSQueryTO      = 5 * time.Second
	vpnBridgeDNSIdleTO       = 10 * time.Second
	vpnBridgeDNSCacheTTL     = 60 * time.Second
	vpnBridgeShutdownGrace   = 2 * time.Second
	vpnBridgeMaxDNSUDP       = 64 * 1024
	vpnBridgeMaxDNSOverTCP   = 64 * 1024
	vpnBridgeTCPForwarderWnd = 1 << 20
	vpnBridgeMaxInFlight     = 1024

	vpnBridgeSOCKSVersion      = byte(0x05)
	vpnBridgeSOCKSNoAuth       = byte(0x00)
	vpnBridgeSOCKSConnect      = byte(0x01)
	vpnBridgeSOCKSUDPAssociate = byte(0x03)
	vpnBridgeSOCKSIPv4         = byte(0x01)
	vpnBridgeSOCKSDomain       = byte(0x03)
	vpnBridgeSOCKSIPv6         = byte(0x04)
	vpnBridgeSOCKSReplySuccess = byte(0x00)
	vpnBridgeAutoUDPRoute      = "auto"
)

var (
	vpnBridgeMu       sync.Mutex
	vpnBridgeCurrent  *vpnBridgeInstance
	vpnBridgeUDPRoute atomic.Value // stores netstack instance, socks:<label>@host:port descriptor, or auto.
)

type vpnBridgeInstance struct {
	ctx      context.Context
	cancel   context.CancelFunc
	stack    *stack.Stack
	linkEP   stack.LinkEndpoint
	tunFile  *os.File
	tunDupFD int
	dnsAddr  string
	mtu      int
	started  time.Time
	workerMu sync.Mutex
	closing  atomic.Bool
	connMu   sync.Mutex
	conns    map[net.Conn]struct{}
	dnsMu    sync.Mutex
	dnsCache map[string]vpnBridgeDNSCacheEntry
	wg       sync.WaitGroup
	stats    vpnBridgeStats
}

type vpnBridgeDNSCacheEntry struct {
	response  []byte
	expiresAt time.Time
}

type vpnBridgeStats struct {
	tcpConnections atomic.Uint64
	tcpFailures    atomic.Uint64
	tcpBytesUp     atomic.Uint64
	tcpBytesDown   atomic.Uint64
	dnsQueries     atomic.Uint64
	dnsFailures    atomic.Uint64
	dnsBytesUp     atomic.Uint64
	dnsBytesDown   atomic.Uint64
	udpSessions    atomic.Uint64
	udpFailures    atomic.Uint64
	udpBytesUp     atomic.Uint64
	udpBytesDown   atomic.Uint64
	udpDropped     atomic.Uint64
}

type vpnBridgeResult struct {
	OK      bool                   `json:"ok"`
	Error   string                 `json:"error,omitempty"`
	Running bool                   `json:"running,omitempty"`
	Stats   map[string]interface{} `json:"stats,omitempty"`
}

// StartVpnBridge starts the system-TUN bridge used by the optional Android VPN
// mode. TCP and DNS are proxied through the existing front SOCKS router.
func StartVpnBridge(tunFd int, mtu int, dnsAddr string) string {
	vpnBridgeMu.Lock()
	defer vpnBridgeMu.Unlock()

	if vpnBridgeCurrent != nil {
		if tunFd >= 0 {
			_ = syscall.Close(tunFd)
		}
		return vpnBridgeJSON(vpnBridgeResult{OK: true, Running: true, Stats: vpnBridgeCurrent.snapshotLocked()})
	}
	if tunFd < 0 {
		return vpnBridgeJSON(vpnBridgeResult{OK: false, Error: "invalid tun fd"})
	}
	if mtu <= 0 {
		mtu = vpnBridgeDefaultMTU
	}
	dnsAddr = strings.TrimSpace(dnsAddr)
	if dnsAddr == "" {
		dnsAddr = vpnBridgeDefaultDNSAddr
	}
	if err := vpnBridgeValidateTarget(dnsAddr); err != nil {
		_ = syscall.Close(tunFd)
		return vpnBridgeJSON(vpnBridgeResult{OK: false, Error: "invalid dns address: " + err.Error()})
	}

	// Android integration contract for A2: pass a fd obtained with
	// ParcelFileDescriptor.detachFd(), not getFd(). Go owns and closes it.
	tunFile := os.NewFile(uintptr(tunFd), "tw-vpn-tun")
	if tunFile == nil {
		_ = syscall.Close(tunFd)
		return vpnBridgeJSON(vpnBridgeResult{OK: false, Error: "invalid tun fd"})
	}

	ctx, cancel := context.WithCancel(context.Background())
	inst := &vpnBridgeInstance{
		ctx:      ctx,
		cancel:   cancel,
		tunFile:  tunFile,
		tunDupFD: -1,
		dnsAddr:  dnsAddr,
		mtu:      mtu,
		started:  time.Now(),
		dnsCache: make(map[string]vpnBridgeDNSCacheEntry),
	}

	if err := inst.start(); err != nil {
		cancel()
		_ = tunFile.Close()
		return vpnBridgeJSON(vpnBridgeResult{OK: false, Error: err.Error()})
	}
	vpnBridgeCurrent = inst
	log.Printf("transport: vpn bridge started mtu=%d dns=%s socks=%s", mtu, dnsAddr, vpnBridgeSOCKSAddr)
	return vpnBridgeJSON(vpnBridgeResult{OK: true, Running: true, Stats: inst.snapshotLocked()})
}

// StopVpnBridge stops the system-TUN bridge. It is safe to call repeatedly.
func StopVpnBridge() string {
	vpnBridgeMu.Lock()
	inst := vpnBridgeCurrent
	vpnBridgeCurrent = nil
	vpnBridgeMu.Unlock()

	if inst == nil {
		return vpnBridgeJSON(vpnBridgeResult{OK: true})
	}
	inst.stop()
	log.Printf("transport: vpn bridge stopped")
	return vpnBridgeJSON(vpnBridgeResult{OK: true, Stats: inst.snapshotLocked()})
}

// VpnBridgeStat returns diagnostic counters for the optional system-TUN bridge.
func VpnBridgeStat() string {
	vpnBridgeMu.Lock()
	defer vpnBridgeMu.Unlock()
	if vpnBridgeCurrent == nil {
		return vpnBridgeJSON(vpnBridgeResult{OK: true, Running: false})
	}
	return vpnBridgeJSON(vpnBridgeResult{OK: true, Running: true, Stats: vpnBridgeCurrent.snapshotLocked()})
}

// SetVpnBridgeUDPRoute selects the leg used by the optional Android VPN bridge
// for non-DNS UDP. The public app passes route descriptors derived from the
// active endpoint set instead of deployment-specific route names:
//   - auto: use a running native netstack leg if available
//   - netstack:<instance>: use a named native netstack instance
//   - socks:<label>@host:port: use a local SOCKS5 UDP ASSOCIATE endpoint
func SetVpnBridgeUDPRoute(route string) string {
	normalized, err := vpnBridgeNormalizeUDPRoute(route)
	if err != nil {
		return vpnBridgeJSON(vpnBridgeResult{OK: false, Error: err.Error()})
	}
	vpnBridgeUDPRoute.Store(normalized)
	return vpnBridgeJSON(vpnBridgeResult{OK: true, Running: normalized != ""})
}

func (b *vpnBridgeInstance) start() error {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	dupFD, err := syscall.Dup(int(b.tunFile.Fd()))
	if err != nil {
		s.Close()
		return fmt.Errorf("dup tun fd: %w", err)
	}
	b.tunDupFD = dupFD
	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:                []int{dupFD},
		MTU:                uint32(b.mtu),
		EthernetHeader:     false,
		PacketDispatchMode: fdbased.Readv,
		ClosedFunc: func(err tcpip.Error) {
			if err != nil {
				log.Printf("transport: vpn bridge tun closed: %s", err.String())
			}
		},
	})
	if err != nil {
		_ = syscall.Close(dupFD)
		b.tunDupFD = -1
		s.Close()
		return fmt.Errorf("create fdbased endpoint: %w", err)
	}
	b.stack = s
	b.linkEP = linkEP

	if err := s.CreateNIC(vpnBridgeNICID, linkEP); err != nil {
		b.closeTunDup()
		s.Close()
		return fmt.Errorf("create vpn bridge nic: %s", err.String())
	}
	if err := s.SetPromiscuousMode(vpnBridgeNICID, true); err != nil {
		_ = s.RemoveNIC(vpnBridgeNICID)
		b.closeTunDup()
		s.Close()
		return fmt.Errorf("enable vpn bridge promiscuous mode: %s", err.String())
	}
	if err := s.SetSpoofing(vpnBridgeNICID, true); err != nil {
		_ = s.RemoveNIC(vpnBridgeNICID)
		b.closeTunDup()
		s.Close()
		return fmt.Errorf("enable vpn bridge spoofing: %s", err.String())
	}
	protocolAddress := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{10, 111, 0, 1}),
			PrefixLen: 32,
		},
	}
	if err := s.AddProtocolAddress(vpnBridgeNICID, protocolAddress, stack.AddressProperties{}); err != nil {
		_ = s.RemoveNIC(vpnBridgeNICID)
		b.closeTunDup()
		s.Close()
		return fmt.Errorf("add vpn bridge address: %s", err.String())
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         vpnBridgeNICID,
	}})

	tcpForwarder := tcp.NewForwarder(s, vpnBridgeTCPForwarderWnd, vpnBridgeMaxInFlight, b.handleTCP)
	udpForwarder := udp.NewForwarder(s, b.handleUDP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	return nil
}

func (b *vpnBridgeInstance) stop() {
	b.beginStop()
	b.cancel()
	b.closeActiveConns()
	if b.linkEP != nil {
		b.waitWithTimeout("link endpoint detach", func() { b.linkEP.Attach(nil) })
	}
	b.closeTunDup()
	if b.stack != nil {
		b.stack.Close()
	}
	if b.linkEP != nil {
		b.waitWithTimeout("link endpoint", b.linkEP.Wait)
	}
	b.closeTunOriginal()
	b.closeActiveConns()
	b.waitWithTimeout("workers", b.wg.Wait)
}

func (b *vpnBridgeInstance) beginStop() {
	b.workerMu.Lock()
	b.closing.Store(true)
	b.workerMu.Unlock()
}

func (b *vpnBridgeInstance) startWorker(fn func()) bool {
	b.workerMu.Lock()
	defer b.workerMu.Unlock()
	if b.closing.Load() {
		return false
	}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		fn()
	}()
	return true
}

func (b *vpnBridgeInstance) trackConn(conn net.Conn) func() {
	if conn == nil {
		return func() {}
	}
	b.connMu.Lock()
	if b.conns == nil {
		b.conns = make(map[net.Conn]struct{})
	}
	b.conns[conn] = struct{}{}
	closing := b.closing.Load()
	b.connMu.Unlock()
	if closing {
		_ = conn.Close()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			b.connMu.Lock()
			delete(b.conns, conn)
			b.connMu.Unlock()
		})
	}
}

func (b *vpnBridgeInstance) closeActiveConns() {
	b.connMu.Lock()
	conns := make([]net.Conn, 0, len(b.conns))
	for conn := range b.conns {
		conns = append(conns, conn)
	}
	b.connMu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (b *vpnBridgeInstance) closeTunDup() {
	if b.tunDupFD >= 0 {
		_ = syscall.Close(b.tunDupFD)
		b.tunDupFD = -1
	}
}

func (b *vpnBridgeInstance) closeTunOriginal() {
	if b.tunFile != nil {
		_ = b.tunFile.Close()
		b.tunFile = nil
	}
}

func (b *vpnBridgeInstance) waitWithTimeout(name string, wait func()) bool {
	done := make(chan struct{})
	go func() {
		wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(vpnBridgeShutdownGrace):
		log.Printf("transport: vpn bridge %s did not stop within %s", name, vpnBridgeShutdownGrace)
		return false
	}
}

func (b *vpnBridgeInstance) handleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	if id.LocalAddress.Len() != 4 {
		req.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		req.Complete(true)
		b.stats.tcpFailures.Add(1)
		return
	}
	req.Complete(false)
	client := gonet.NewTCPConn(&wq, ep)
	if !b.startWorker(func() {
		b.proxyTCP(client, id)
	}) {
		_ = client.Close()
	}
}

func (b *vpnBridgeInstance) proxyTCP(client *gonet.TCPConn, id stack.TransportEndpointID) {
	defer client.Close()
	untrackClient := b.trackConn(client)
	defer untrackClient()
	target := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	ctx, cancel := context.WithTimeout(b.ctx, vpnBridgeTCPConnectTO)
	defer cancel()
	upstream, untrackUpstream, err := vpnBridgeSOCKS5Connect(ctx, vpnBridgeSOCKSAddr, target, b.trackConn)
	if err != nil {
		b.stats.tcpFailures.Add(1)
		log.Printf("transport: vpn bridge tcp socks connect %s failed: %v", target, err)
		return
	}
	defer upstream.Close()
	defer untrackUpstream()
	b.stats.tcpConnections.Add(1)
	_ = client.SetDeadline(time.Now().Add(vpnBridgeTCPIdleTO))
	_ = upstream.SetDeadline(time.Now().Add(vpnBridgeTCPIdleTO))

	vpnBridgeCopyBoth(client, upstream, &b.stats.tcpBytesDown, &b.stats.tcpBytesUp)
}

func (b *vpnBridgeInstance) handleUDP(req *udp.ForwarderRequest) {
	id := req.ID()
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		b.stats.udpFailures.Add(1)
		return
	}
	conn := gonet.NewUDPConn(&wq, ep)
	if id.LocalAddress.Len() != 4 {
		b.stats.udpDropped.Add(1)
		_ = conn.Close()
		return
	}
	if id.LocalPort == 53 {
		if !b.startWorker(func() {
			b.handleDNS(conn)
		}) {
			_ = conn.Close()
		}
		return
	}
	if !b.startWorker(func() {
		b.proxyUDP(conn, id)
	}) {
		_ = conn.Close()
	}
}

func (b *vpnBridgeInstance) proxyUDP(client *gonet.UDPConn, id stack.TransportEndpointID) {
	defer client.Close()
	untrackClient := b.trackConn(client)
	defer untrackClient()

	target := netip.AddrPortFrom(netip.AddrFrom4(id.LocalAddress.As4()), id.LocalPort)
	upstream, untrackUpstream, route, err := b.dialUDP(target)
	if err != nil {
		b.stats.udpFailures.Add(1)
		b.stats.udpDropped.Add(1)
		log.Printf("transport: vpn bridge udp %s dropped: %v", target, err)
		return
	}
	defer upstream.Close()
	defer untrackUpstream()
	b.stats.udpSessions.Add(1)
	log.Printf("transport: vpn bridge udp route=%s target=%s", route, target)

	errCh := make(chan error, 2)
	go func() {
		errCh <- vpnBridgeCopyUDP(upstream, client, &b.stats.udpBytesUp)
	}()
	go func() {
		errCh <- vpnBridgeCopyUDP(client, upstream, &b.stats.udpBytesDown)
	}()
	firstErr := <-errCh
	_ = client.Close()
	_ = upstream.Close()
	<-errCh
	if firstErr != nil && !vpnBridgeIsTimeout(firstErr) && b.ctx.Err() == nil && !errors.Is(firstErr, net.ErrClosed) {
		log.Printf("transport: vpn bridge udp %s closed: %v", target, firstErr)
	}
}

func (b *vpnBridgeInstance) dialUDP(target netip.AddrPort) (net.Conn, func(), string, error) {
	route := vpnBridgeCurrentUDPRoute()
	if route == "" {
		return nil, nil, "", errors.New("udp route disabled")
	}
	return b.dialUDPRoute(route, target)
}

func (b *vpnBridgeInstance) dialUDPRoute(route string, target netip.AddrPort) (net.Conn, func(), string, error) {
	if route == vpnBridgeAutoUDPRoute {
		selected := vpnBridgeSelectAutoUDPRoute()
		if selected == "" {
			return nil, nil, route, errors.New("no udp-capable route available")
		}
		route = selected
	}
	if label, proxyAddr, ok := vpnBridgeXrayUDPRoute(route); ok {
		upstream, err := vpnBridgeSOCKS5UDPAssociate(b.ctx, proxyAddr, target)
		if err != nil {
			return nil, nil, label, err
		}
		untrack := b.trackConn(upstream)
		return upstream, untrack, label, nil
	}
	singleton.Lock()
	inst := singleton.instances[route]
	singleton.Unlock()
	if inst == nil || inst.net == nil {
		return nil, nil, route, fmt.Errorf("udp route %s not started", route)
	}
	upstream, err := inst.net.DialUDPAddrPort(netip.AddrPort{}, target)
	if err != nil {
		return nil, nil, route, err
	}
	untrack := b.trackConn(upstream)
	return upstream, untrack, route, nil
}

func (b *vpnBridgeInstance) handleDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	untrackConn := b.trackConn(conn)
	defer untrackConn()
	buf := make([]byte, vpnBridgeMaxDNSUDP)
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
		query := buf[:n]
		b.stats.dnsQueries.Add(1)
		b.stats.dnsBytesUp.Add(uint64(len(query)))
		response, err := b.resolveDNS(query)
		if err != nil {
			b.stats.dnsFailures.Add(1)
			log.Printf("transport: vpn bridge dns query failed: %v", err)
			continue
		}
		response = vpnBridgeDNSFitUDP(query, response)
		b.stats.dnsBytesDown.Add(uint64(len(response)))
		_ = conn.SetWriteDeadline(time.Now().Add(vpnBridgeDNSQueryTO))
		if _, err := conn.Write(response); err != nil {
			if b.ctx.Err() != nil {
				return
			}
			b.stats.dnsFailures.Add(1)
			return
		}
	}
}

func (b *vpnBridgeInstance) resolveDNS(query []byte) ([]byte, error) {
	route := vpnBridgeCurrentUDPRoute()
	if route != "" {
		response, err := b.resolveDNSOverUDPRoute(query, route)
		if err == nil {
			b.cacheDNSResponse(query, response)
			return response, nil
		}
		log.Printf("transport: vpn bridge tunnel dns failed route=%s: %v", vpnBridgeRouteLabel(route), err)
		response, err = b.resolveDNSOverHTTPS(query)
		if err == nil {
			log.Printf("transport: vpn bridge dns_fallback_used=doh route=%s", vpnBridgeRouteLabel(route))
			b.cacheDNSResponse(query, response)
			return response, nil
		}
		if cached, ok := b.cachedDNSResponse(query); ok {
			log.Printf("transport: vpn bridge dns_fallback_used=cache route=%s", vpnBridgeRouteLabel(route))
			return cached, nil
		}
		return nil, err
	}
	response, err := b.resolveDNSOverHTTPS(query)
	if err == nil {
		log.Printf("transport: vpn bridge dns_fallback_used=doh route=disabled")
		b.cacheDNSResponse(query, response)
		return response, nil
	}
	if cached, ok := b.cachedDNSResponse(query); ok {
		log.Printf("transport: vpn bridge dns_fallback_used=cache route=disabled")
		return cached, nil
	}
	return nil, err
}

func (b *vpnBridgeInstance) cachedDNSResponse(query []byte) ([]byte, bool) {
	key := vpnBridgeDNSCacheKey(query)
	if key == "" {
		return nil, false
	}
	now := time.Now()
	b.dnsMu.Lock()
	defer b.dnsMu.Unlock()
	entry, ok := b.dnsCache[key]
	if !ok {
		return nil, false
	}
	if now.After(entry.expiresAt) {
		delete(b.dnsCache, key)
		return nil, false
	}
	response := append([]byte(nil), entry.response...)
	if len(response) >= 2 && len(query) >= 2 {
		copy(response[:2], query[:2])
	}
	return response, true
}

func (b *vpnBridgeInstance) cacheDNSResponse(query, response []byte) {
	key := vpnBridgeDNSCacheKey(query)
	if key == "" || len(response) < 2 {
		return
	}
	cached := append([]byte(nil), response...)
	if len(query) >= 2 {
		copy(cached[:2], query[:2])
	}
	b.dnsMu.Lock()
	b.dnsCache[key] = vpnBridgeDNSCacheEntry{
		response:  cached,
		expiresAt: time.Now().Add(vpnBridgeDNSCacheTTL),
	}
	b.dnsMu.Unlock()
}

func (b *vpnBridgeInstance) resolveDNSOverUDP(query []byte) ([]byte, error) {
	return b.resolveDNSOverUDPRoute(query, vpnBridgeCurrentUDPRoute())
}

func (b *vpnBridgeInstance) resolveDNSOverUDPRoute(query []byte, route string) ([]byte, error) {
	if route == "" {
		return nil, errors.New("udp route disabled")
	}
	target, err := vpnBridgeAddrPortTarget(b.dnsAddr)
	if err != nil {
		return nil, err
	}
	upstream, untrackUpstream, route, err := b.dialUDPRoute(route, target)
	if err != nil {
		return nil, fmt.Errorf("udp route %s: %w", route, err)
	}
	defer upstream.Close()
	defer untrackUpstream()
	_ = upstream.SetDeadline(time.Now().Add(vpnBridgeDNSQueryTO))
	if _, err := upstream.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, vpnBridgeMaxDNSUDP)
	n, err := upstream.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func (b *vpnBridgeInstance) resolveDNSOverTCP(query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(b.ctx, vpnBridgeDNSQueryTO)
	defer cancel()
	upstream, untrackUpstream, err := vpnBridgeSOCKS5Connect(ctx, vpnBridgeSOCKSAddr, b.dnsAddr, b.trackConn)
	if err != nil {
		return nil, fmt.Errorf("socks connect: %w", err)
	}
	defer upstream.Close()
	defer untrackUpstream()
	_ = upstream.SetDeadline(time.Now().Add(vpnBridgeDNSQueryTO))
	frame, err := vpnBridgeDNSOverTCPFrame(query)
	if err != nil {
		return nil, err
	}
	if _, err := upstream.Write(frame); err != nil {
		return nil, err
	}
	response, err := vpnBridgeReadDNSOverTCPFrame(upstream, vpnBridgeMaxDNSOverTCP)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (b *vpnBridgeInstance) resolveDNSOverHTTPS(query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(b.ctx, vpnBridgeDNSQueryTO)
	defer cancel()
	upstream, untrackUpstream, err := vpnBridgeSOCKS5Connect(ctx, vpnBridgeSOCKSAddr, vpnBridgeDoHAddr, b.trackConn)
	if err != nil {
		return nil, fmt.Errorf("socks connect: %w", err)
	}
	defer upstream.Close()
	defer untrackUpstream()
	_ = upstream.SetDeadline(time.Now().Add(vpnBridgeDNSQueryTO))
	tlsConn := tls.Client(upstream, &tls.Config{
		ServerName:         vpnBridgeDoHHost,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	defer tlsConn.Close()
	if _, err := fmt.Fprintf(
		tlsConn,
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		vpnBridgeDoHPath,
		vpnBridgeDoHHost,
		len(query),
	); err != nil {
		return nil, err
	}
	if _, err := tlsConn.Write(query); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
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
	if len(body) == 0 {
		return nil, errors.New("empty doh response")
	}
	if len(body) > vpnBridgeMaxDNSUDP {
		return nil, fmt.Errorf("doh response too large: %d", len(body))
	}
	return body, nil
}

func vpnBridgeCopyBoth(left, right net.Conn, leftBytes, rightBytes *atomic.Uint64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		vpnBridgeCopyOne(left, right, leftBytes)
	}()
	go func() {
		defer wg.Done()
		vpnBridgeCopyOne(right, left, rightBytes)
	}()
	wg.Wait()
	_ = left.Close()
	_ = right.Close()
}

func vpnBridgeCopyOne(dst, src net.Conn, counter *atomic.Uint64) {
	buf := make([]byte, 32*1024)
copyLoop:
	for {
		_ = src.SetReadDeadline(time.Now().Add(vpnBridgeTCPIdleTO))
		n, readErr := src.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				_ = dst.SetWriteDeadline(time.Now().Add(vpnBridgeTCPIdleTO))
				m, writeErr := dst.Write(buf[written:n])
				if m > 0 {
					written += m
					if counter != nil {
						counter.Add(uint64(m))
					}
				}
				if writeErr != nil {
					break copyLoop
				}
			}
		}
		if readErr != nil {
			break
		}
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
}

func vpnBridgeCopyUDP(dst, src net.Conn, counter *atomic.Uint64) error {
	buf := make([]byte, 64*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(vpnBridgeUDPIdleTO))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(vpnBridgeUDPIdleTO))
			written, writeErr := dst.Write(buf[:n])
			if written > 0 && counter != nil {
				counter.Add(uint64(written))
			}
			if writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			return err
		}
	}
}

func vpnBridgeSOCKS5Connect(ctx context.Context, proxyAddr, target string, track func(net.Conn) func()) (net.Conn, func(), error) {
	host, port, err := vpnBridgeSplitHostPort(target)
	if err != nil {
		return nil, nil, err
	}
	req, err := vpnBridgeBuildSOCKS5ConnectRequest(host, port)
	if err != nil {
		return nil, nil, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, nil, err
	}
	untrack := func() {}
	if track != nil {
		untrack = track(conn)
	}
	fail := func(err error) (net.Conn, func(), error) {
		untrack()
		_ = conn.Close()
		return nil, nil, err
	}
	deadline := time.Now().Add(vpnBridgeTCPConnectTO)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte{vpnBridgeSOCKSVersion, 0x01, vpnBridgeSOCKSNoAuth}); err != nil {
		return fail(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fail(err)
	}
	if greeting[0] != vpnBridgeSOCKSVersion || greeting[1] != vpnBridgeSOCKSNoAuth {
		return fail(fmt.Errorf("socks auth rejected: %02x %02x", greeting[0], greeting[1]))
	}
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}
	if err := vpnBridgeReadSOCKS5ConnectResponse(conn); err != nil {
		return fail(err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, untrack, nil
}

type vpnBridgeSOCKS5UDPConn struct {
	control net.Conn
	udp     *net.UDPConn
	relay   *net.UDPAddr
	target  netip.AddrPort
}

func vpnBridgeSOCKS5UDPAssociate(ctx context.Context, proxyAddr string, target netip.AddrPort) (net.Conn, error) {
	if !target.Addr().Is4() {
		return nil, errors.New("udp target ipv6 is not supported")
	}
	proxyHost, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return nil, err
	}
	udpConn, local, err := vpnBridgeListenSOCKS5UDP(proxyHost)
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	control, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		_ = udpConn.Close()
		_ = control.Close()
		return nil, err
	}
	deadline := time.Now().Add(vpnBridgeTCPConnectTO)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = control.SetDeadline(deadline)
	if _, err := control.Write([]byte{vpnBridgeSOCKSVersion, 0x01, vpnBridgeSOCKSNoAuth}); err != nil {
		return fail(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(control, greeting[:]); err != nil {
		return fail(err)
	}
	if greeting[0] != vpnBridgeSOCKSVersion || greeting[1] != vpnBridgeSOCKSNoAuth {
		return fail(fmt.Errorf("socks auth rejected: %02x %02x", greeting[0], greeting[1]))
	}
	if _, err := control.Write([]byte{
		vpnBridgeSOCKSVersion,
		vpnBridgeSOCKSUDPAssociate,
		0x00,
		vpnBridgeSOCKSIPv4,
		local.IP[0], local.IP[1], local.IP[2], local.IP[3],
		byte(local.Port >> 8), byte(local.Port),
	}); err != nil {
		return fail(err)
	}
	relay, err := vpnBridgeReadSOCKS5UDPAssociateResponse(control, proxyHost)
	if err != nil {
		return fail(err)
	}
	_ = control.SetDeadline(time.Time{})
	return &vpnBridgeSOCKS5UDPConn{control: control, udp: udpConn, relay: relay, target: target}, nil
}

func vpnBridgeListenSOCKS5UDP(proxyHost string) (*net.UDPConn, *net.UDPAddr, error) {
	ip := net.ParseIP(proxyHost).To4()
	if ip == nil {
		if strings.EqualFold(proxyHost, "localhost") {
			ip = net.IPv4(127, 0, 0, 1)
		} else {
			return nil, nil, fmt.Errorf("socks udp proxy host %q is not IPv4", proxyHost)
		}
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		return nil, nil, err
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() == nil || local.Port <= 0 || local.Port > 0xffff {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("bad socks udp local address %v", conn.LocalAddr())
	}
	return conn, &net.UDPAddr{IP: local.IP.To4(), Port: local.Port}, nil
}

func (c *vpnBridgeSOCKS5UDPConn) Read(p []byte) (int, error) {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			return 0, err
		}
		if !from.IP.Equal(c.relay.IP) || from.Port != c.relay.Port {
			continue
		}
		payload, err := vpnBridgeParseSOCKS5UDPDatagram(buf[:n])
		if err != nil {
			continue
		}
		return copy(p, payload), nil
	}
}

func (c *vpnBridgeSOCKS5UDPConn) Write(p []byte) (int, error) {
	frame, err := vpnBridgeBuildSOCKS5UDPDatagram(c.target, p)
	if err != nil {
		return 0, err
	}
	if _, err := c.udp.WriteToUDP(frame, c.relay); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *vpnBridgeSOCKS5UDPConn) Close() error {
	err1 := c.udp.Close()
	err2 := c.control.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *vpnBridgeSOCKS5UDPConn) LocalAddr() net.Addr {
	return c.udp.LocalAddr()
}

func (c *vpnBridgeSOCKS5UDPConn) RemoteAddr() net.Addr {
	return c.relay
}

func (c *vpnBridgeSOCKS5UDPConn) SetDeadline(t time.Time) error {
	return c.udp.SetDeadline(t)
}

func (c *vpnBridgeSOCKS5UDPConn) SetReadDeadline(t time.Time) error {
	return c.udp.SetReadDeadline(t)
}

func (c *vpnBridgeSOCKS5UDPConn) SetWriteDeadline(t time.Time) error {
	return c.udp.SetWriteDeadline(t)
}

func vpnBridgeReadSOCKS5UDPAssociateResponse(r io.Reader, proxyHost string) (*net.UDPAddr, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	if head[0] != vpnBridgeSOCKSVersion {
		return nil, fmt.Errorf("bad socks version %d", head[0])
	}
	if head[1] != vpnBridgeSOCKSReplySuccess {
		return nil, fmt.Errorf("socks udp associate failed with reply %d", head[1])
	}
	host, err := vpnBridgeReadSOCKS5Address(r, head[3])
	if err != nil {
		return nil, err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = proxyHost
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
}

func vpnBridgeReadSOCKS5Address(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case vpnBridgeSOCKSIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case vpnBridgeSOCKSIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case vpnBridgeSOCKSDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		return string(name), nil
	default:
		return "", fmt.Errorf("unsupported socks address type %d", atyp)
	}
}

func vpnBridgeBuildSOCKS5UDPDatagram(target netip.AddrPort, payload []byte) ([]byte, error) {
	if !target.Addr().Is4() {
		return nil, errors.New("udp target ipv6 is not supported")
	}
	frame := make([]byte, 0, 10+len(payload))
	frame = append(frame, 0x00, 0x00, 0x00, vpnBridgeSOCKSIPv4)
	frame = append(frame, target.Addr().AsSlice()...)
	frame = binary.BigEndian.AppendUint16(frame, target.Port())
	frame = append(frame, payload...)
	return frame, nil
}

func vpnBridgeParseSOCKS5UDPDatagram(frame []byte) ([]byte, error) {
	if len(frame) < 4 {
		return nil, errors.New("short socks udp datagram")
	}
	if frame[0] != 0x00 || frame[1] != 0x00 {
		return nil, errors.New("bad socks udp reserved bytes")
	}
	if frame[2] != 0x00 {
		return nil, errors.New("fragmented socks udp datagram is not supported")
	}
	offset := 4
	switch frame[3] {
	case vpnBridgeSOCKSIPv4:
		offset += 4
	case vpnBridgeSOCKSIPv6:
		offset += 16
	case vpnBridgeSOCKSDomain:
		if len(frame) < offset+1 {
			return nil, errors.New("short socks udp domain")
		}
		offset += 1 + int(frame[offset])
	default:
		return nil, fmt.Errorf("unsupported socks udp address type %d", frame[3])
	}
	offset += 2
	if len(frame) < offset {
		return nil, errors.New("short socks udp address")
	}
	return frame[offset:], nil
}

func vpnBridgeBuildSOCKS5ConnectRequest(host string, port uint16) ([]byte, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, errors.New("empty host")
	}
	req := []byte{vpnBridgeSOCKSVersion, vpnBridgeSOCKSConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, errors.New("ipv6 target is not supported")
		}
		req = append(req, vpnBridgeSOCKSIPv4)
		req = append(req, ip4...)
	} else {
		if len(host) > 255 {
			return nil, errors.New("domain too long")
		}
		req = append(req, vpnBridgeSOCKSDomain, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	return req, nil
}

func vpnBridgeReadSOCKS5ConnectResponse(r io.Reader) error {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	if head[0] != vpnBridgeSOCKSVersion {
		return fmt.Errorf("bad socks version %d", head[0])
	}
	if head[1] != vpnBridgeSOCKSReplySuccess {
		return fmt.Errorf("socks connect failed with reply %d", head[1])
	}
	var skip int
	switch head[3] {
	case vpnBridgeSOCKSIPv4:
		skip = 4
	case vpnBridgeSOCKSIPv6:
		skip = 16
	case vpnBridgeSOCKSDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return fmt.Errorf("unsupported socks reply address type %d", head[3])
	}
	if skip > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(skip)); err != nil {
			return err
		}
	}
	if _, err := io.CopyN(io.Discard, r, 2); err != nil {
		return err
	}
	return nil
}

func vpnBridgeDNSOverTCPFrame(query []byte) ([]byte, error) {
	if len(query) == 0 {
		return nil, errors.New("empty dns query")
	}
	if len(query) > 0xffff {
		return nil, errors.New("dns query too large")
	}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	return frame, nil
}

func vpnBridgeReadDNSOverTCPFrame(r io.Reader, max int) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 {
		return nil, errors.New("empty dns response")
	}
	if max > 0 && n > max {
		return nil, fmt.Errorf("dns response too large: %d", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(r, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func vpnBridgeDNSFitUDP(query, response []byte) []byte {
	limit := vpnBridgeDNSUDPSize(query)
	if len(response) <= limit {
		return response
	}
	return vpnBridgeDNSTruncatedResponse(query)
}

func vpnBridgeNormalizeUDPRoute(route string) (string, error) {
	raw := strings.TrimSpace(route)
	lower := strings.ToLower(raw)
	switch lower {
	case "", "none", "disabled", "off":
		return "", nil
	case vpnBridgeAutoUDPRoute:
		return vpnBridgeAutoUDPRoute, nil
	}
	for _, prefix := range []string{"netstack:", "awg:"} {
		if strings.HasPrefix(lower, prefix) {
			name := strings.TrimSpace(raw[len(prefix):])
			if err := vpnBridgeValidateRouteToken(name); err != nil {
				return "", err
			}
			return name, nil
		}
	}
	if strings.HasPrefix(lower, "socks:") {
		descriptor := strings.TrimSpace(raw[len("socks:"):])
		label, proxyAddr, ok := strings.Cut(descriptor, "@")
		if !ok || label == "" || proxyAddr == "" {
			return "", fmt.Errorf("invalid socks udp route %q", route)
		}
		if err := vpnBridgeValidateRouteToken(label); err != nil {
			return "", err
		}
		if err := vpnBridgeValidateTarget(proxyAddr); err != nil {
			return "", fmt.Errorf("invalid socks udp proxy %q: %w", proxyAddr, err)
		}
		return label + "@" + proxyAddr, nil
	}
	return "", fmt.Errorf("unsupported udp route %q", route)
}

func vpnBridgeRouteLabel(route string) string {
	if label, _, ok := vpnBridgeXrayUDPRoute(route); ok {
		return label
	}
	switch {
	case route == "":
		return "disabled"
	case route == vpnBridgeAutoUDPRoute:
		return "auto"
	default:
		return "netstack:" + route
	}
}

func vpnBridgeValidateRouteToken(value string) error {
	if value == "" {
		return errors.New("empty udp route token")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '.' {
			continue
		}
		return fmt.Errorf("invalid udp route token %q", value)
	}
	return nil
}

func vpnBridgeSelectAutoUDPRoute() string {
	singleton.Lock()
	defer singleton.Unlock()
	if inst := singleton.instances[defaultInstanceName]; inst != nil && inst.net != nil {
		return defaultInstanceName
	}
	for name, inst := range singleton.instances {
		if inst != nil && inst.net != nil {
			return name
		}
	}
	return ""
}

func vpnBridgeDNSCacheKey(query []byte) string {
	if len(query) < 12 {
		return ""
	}
	key := append([]byte(nil), query...)
	key[0], key[1] = 0, 0
	return string(key)
}

func vpnBridgeAddrPortTarget(target string) (netip.AddrPort, error) {
	host, port, err := vpnBridgeSplitHostPort(target)
	if err != nil {
		return netip.AddrPort{}, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("udp target must be an IP address: %w", err)
	}
	if !addr.Is4() {
		return netip.AddrPort{}, errors.New("udp target must be IPv4")
	}
	return netip.AddrPortFrom(addr, port), nil
}

func vpnBridgeXrayUDPRoute(route string) (label string, proxyAddr string, ok bool) {
	label, proxyAddr, ok = strings.Cut(route, "@")
	if !ok || label == "" || proxyAddr == "" {
		return "", "", false
	}
	return label, proxyAddr, true
}

func vpnBridgeCurrentUDPRoute() string {
	route, _ := vpnBridgeUDPRoute.Load().(string)
	return route
}

func vpnBridgeDNSUDPSize(query []byte) int {
	const dnsHeaderLen = 12
	if len(query) < dnsHeaderLen {
		return 512
	}
	qdCount := int(binary.BigEndian.Uint16(query[4:6]))
	arCount := int(binary.BigEndian.Uint16(query[10:12]))
	off := dnsHeaderLen
	for i := 0; i < qdCount; i++ {
		next, ok := vpnBridgeDNSNameEnd(query, off)
		if !ok || next+4 > len(query) {
			return 512
		}
		off = next + 4
	}
	for i := 0; i < arCount; i++ {
		next, ok := vpnBridgeDNSNameEnd(query, off)
		if !ok || next+10 > len(query) {
			return 512
		}
		rrType := binary.BigEndian.Uint16(query[next : next+2])
		rrClass := binary.BigEndian.Uint16(query[next+2 : next+4])
		rdLen := int(binary.BigEndian.Uint16(query[next+8 : next+10]))
		off = next + 10
		if off+rdLen > len(query) {
			return 512
		}
		if rrType == 41 && rrClass > 0 {
			return int(rrClass)
		}
		off += rdLen
	}
	return 512
}

func vpnBridgeDNSTruncatedResponse(query []byte) []byte {
	const dnsHeaderLen = 12
	out := make([]byte, dnsHeaderLen)
	if len(query) >= 2 {
		copy(out[0:2], query[0:2])
	}
	flags := uint16(0x8000 | 0x0200) // QR + TC.
	if len(query) >= 4 {
		flags |= binary.BigEndian.Uint16(query[2:4]) & 0x0100 // RD.
	}
	binary.BigEndian.PutUint16(out[2:4], flags)
	if questionEnd, ok := vpnBridgeDNSQuestionEnd(query); ok {
		copy(out[4:6], query[4:6])
		out = append(out, query[dnsHeaderLen:questionEnd]...)
	}
	return out
}

func vpnBridgeDNSQuestionEnd(msg []byte) (int, bool) {
	const dnsHeaderLen = 12
	if len(msg) < dnsHeaderLen {
		return dnsHeaderLen, false
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	off := dnsHeaderLen
	for i := 0; i < qdCount; i++ {
		next, ok := vpnBridgeDNSNameEnd(msg, off)
		if !ok || next+4 > len(msg) {
			return dnsHeaderLen, false
		}
		off = next + 4
	}
	return off, true
}

func vpnBridgeDNSNameEnd(msg []byte, off int) (int, bool) {
	for i := 0; i < 255; i++ {
		if off >= len(msg) {
			return 0, false
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		case l&0xc0 != 0:
			return 0, false
		default:
			off++
			if off+l > len(msg) {
				return 0, false
			}
			off += l
		}
	}
	return 0, false
}

func vpnBridgeSplitHostPort(target string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return "", 0, err
	}
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port64 == 0 {
		return "", 0, fmt.Errorf("invalid port %q", portText)
	}
	return strings.Trim(host, "[]"), uint16(port64), nil
}

func vpnBridgeValidateTarget(target string) error {
	host, _, err := vpnBridgeSplitHostPort(target)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return errors.New("ipv6 target is not supported")
	}
	return nil
}

func vpnBridgeIsTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (b *vpnBridgeInstance) snapshotLocked() map[string]interface{} {
	return map[string]interface{}{
		"started":         b.started.UTC().Format(time.RFC3339),
		"uptime_seconds":  int64(time.Since(b.started).Seconds()),
		"mtu":             b.mtu,
		"dns":             b.dnsAddr,
		"socks":           vpnBridgeSOCKSAddr,
		"tcp_connections": b.stats.tcpConnections.Load(),
		"tcp_failures":    b.stats.tcpFailures.Load(),
		"tcp_bytes_up":    b.stats.tcpBytesUp.Load(),
		"tcp_bytes_down":  b.stats.tcpBytesDown.Load(),
		"dns_queries":     b.stats.dnsQueries.Load(),
		"dns_failures":    b.stats.dnsFailures.Load(),
		"dns_bytes_up":    b.stats.dnsBytesUp.Load(),
		"dns_bytes_down":  b.stats.dnsBytesDown.Load(),
		"udp_route":       vpnBridgeCurrentUDPRoute(),
		"udp_sessions":    b.stats.udpSessions.Load(),
		"udp_failures":    b.stats.udpFailures.Load(),
		"udp_bytes_up":    b.stats.udpBytesUp.Load(),
		"udp_bytes_down":  b.stats.udpBytesDown.Load(),
		"udp_dropped":     b.stats.udpDropped.Load(),
	}
}

func vpnBridgeJSON(v vpnBridgeResult) string {
	out, err := json.Marshal(v)
	if err != nil {
		return `{"ok":false,"error":"json encode failed"}`
	}
	return string(out)
}
