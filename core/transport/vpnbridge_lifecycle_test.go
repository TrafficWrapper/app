package transport

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// testTunPair returns a SEQPACKET socketpair: the raw fd handed to the
// bridge (which takes ownership) and a peer conn acting as the kernel side.
func testTunPair(t *testing.T) (int, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Skipf("socketpair unavailable: %v", err)
	}
	peerFile := os.NewFile(uintptr(fds[1]), "tun-peer")
	peer, err := net.FileConn(peerFile)
	_ = peerFile.Close()
	if err != nil {
		_ = syscall.Close(fds[0])
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return fds[0], peer.(*net.UnixConn)
}

func startTestBridge(t *testing.T, fd int) {
	t.Helper()
	var res vpnBridgeResult
	if err := json.Unmarshal([]byte(StartVpnBridge(fd, 1500, "1.1.1.1:53")), &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.Running {
		t.Fatalf("start failed: %+v", res)
	}
}

func expectPeerClosed(t *testing.T, peer *net.UnixConn) {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	for {
		n, err := peer.Read(buf)
		if err != nil || n == 0 {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Fatal("tun fd was not closed")
			}
			return
		}
	}
}

func TestStartVpnBridgeReplacesRunningBridgeWithNewFD(t *testing.T) {
	t.Cleanup(func() { StopVpnBridge() })
	oldFD, oldPeer := testTunPair(t)
	startTestBridge(t, oldFD)
	newFD, newPeer := testTunPair(t)
	startTestBridge(t, newFD)

	vpnBridgeMu.Lock()
	current := vpnBridgeCurrent
	vpnBridgeMu.Unlock()
	if current == nil || current.tunFile == nil || int(current.tunFile.Fd()) != newFD {
		t.Fatal("bridge is not running on the new tun fd")
	}
	expectPeerClosed(t, oldPeer)

	StopVpnBridge()
	expectPeerClosed(t, newPeer)
}

// With an unreachable SOCKS upstream the app's SYN must be answered with RST,
// not with a SYN-ACK for a connection that is then dropped.
func TestVpnBridgeTCPResetsWhenUpstreamUnavailable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()
	oldAddr := vpnBridgeSOCKSAddr
	vpnBridgeSOCKSAddr = deadAddr
	t.Cleanup(func() {
		StopVpnBridge()
		vpnBridgeSOCKSAddr = oldAddr
	})

	fd, peer := testTunPair(t)
	startTestBridge(t, fd)

	src := tcpip.AddrFrom4([4]byte{10, 111, 0, 2})
	dst := tcpip.AddrFrom4([4]byte{203, 0, 113, 10})
	pkt := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcpHdr := header.TCP(pkt[header.IPv4MinimumSize:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    40000,
		DstPort:    443,
		SeqNum:     1000,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, header.TCPMinimumSize)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(xsum))
	if _, err := peer.Write(pkt); err != nil {
		t.Fatalf("inject syn: %v", err)
	}

	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	for {
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatalf("no response to SYN: %v", err)
		}
		reply := header.IPv4(buf[:n])
		if !reply.IsValid(n) || reply.TransportProtocol() != header.TCPProtocolNumber {
			continue
		}
		seg := header.TCP(reply.Payload())
		if seg.DestinationPort() != 40000 {
			continue
		}
		flags := seg.Flags()
		if flags.Contains(header.TCPFlagSyn | header.TCPFlagAck) {
			t.Fatal("bridge completed the handshake although the upstream is unavailable")
		}
		if flags.Contains(header.TCPFlagRst) {
			return
		}
	}
}
