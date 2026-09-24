package transport

import (
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	netstacktun "github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"github.com/TrafficWrapper/app/core/internal/provisionclient"
)

func TestVpnBridgeUDPSessionLimitEvictsLeastRecentlyActive(t *testing.T) {
	b := &vpnBridgeInstance{}
	type pair struct{ a, b net.Conn }
	var pairs []pair
	var sessions []*vpnBridgeUDPSession
	for i := 0; i < vpnBridgeMaxUDPSessions; i++ {
		a, c := net.Pipe()
		pairs = append(pairs, pair{a, c})
		sess := &vpnBridgeUDPSession{tracker: newConnIdleTracker(a, c, time.Minute)}
		sess.tracker.lastActivity.Store(int64(i + 1))
		sessions = append(sessions, sess)
		b.registerUDPSession(sess)
	}
	defer func() {
		for _, p := range pairs {
			_ = p.a.Close()
			_ = p.b.Close()
		}
	}()
	// Session 0 has the oldest activity and must be evicted.
	a, c := net.Pipe()
	pairs = append(pairs, pair{a, c})
	unregister := b.registerUDPSession(&vpnBridgeUDPSession{tracker: newConnIdleTracker(a, c, time.Minute)})
	defer unregister()

	b.udpMu.Lock()
	count := len(b.udpSess)
	_, oldestKept := b.udpSess[sessions[0]]
	b.udpMu.Unlock()
	if count != vpnBridgeMaxUDPSessions {
		t.Fatalf("sessions=%d want %d", count, vpnBridgeMaxUDPSessions)
	}
	if oldestKept {
		t.Fatal("oldest session was not evicted")
	}
	if !sessions[0].tracker.expired.Load() {
		t.Fatal("evicted session was not closed")
	}
	if b.stats.udpEvicted.Load() != 1 {
		t.Fatalf("udp_evicted=%d want 1", b.stats.udpEvicted.Load())
	}
	if _, err := pairs[0].b.Write([]byte("x")); err == nil {
		t.Fatal("evicted session conn still writable")
	}
}

func TestStopNamedWaitsForInProgressStart(t *testing.T) {
	const name = "test-starting"
	done := make(chan struct{})
	singleton.Lock()
	if singleton.starting == nil {
		singleton.starting = make(map[string]chan struct{})
	}
	singleton.starting[name] = done
	singleton.Unlock()

	stopped := make(chan string, 1)
	go func() { stopped <- StopNamed(name) }()
	select {
	case <-stopped:
		t.Fatal("StopNamed returned while start was in progress")
	case <-time.After(50 * time.Millisecond):
	}
	// Readers are not blocked by an in-progress start.
	if !strings.Contains(StatNamed(name), `"started":false`) {
		t.Fatal("stat blocked or reported running")
	}
	singleton.Lock()
	delete(singleton.starting, name)
	singleton.Unlock()
	close(done)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("StopNamed did not finish after start completed")
	}
}

func TestNetstackTUNLayoutMatches(t *testing.T) {
	if err := checkNetstackTUNLayout(); err != nil {
		t.Fatalf("netstack tun layout check failed (dependency update?): %v", err)
	}
	tunDev, tnet, err := netstacktun.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.2")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer tunDev.Close()
	if err := tuneNetstack(tnet); err != nil {
		t.Fatalf("tune netstack: %v", err)
	}
}

func TestCheckExpectedServerKeysRejectsMismatchByDefault(t *testing.T) {
	resp := provisionclient.Response{ServerPublicKey: testKey(1)}
	err := checkExpectedServerKeys(deviceEnrollAPIRequest{ExpectedServerAWGKey: testKey(2)}, resp)
	if err == nil || !err.result.AWGKeyMismatch {
		t.Fatalf("awg mismatch accepted without require flag: %v", err)
	}
	if err := checkExpectedServerKeys(deviceEnrollAPIRequest{ExpectedServerAWGKey: testKey(1)}, resp); err != nil {
		t.Fatalf("matching key rejected: %v", err)
	}
	if err := checkExpectedServerKeys(deviceEnrollAPIRequest{}, resp); err != nil {
		t.Fatalf("unpinned key rejected: %v", err)
	}
	resp.AWGRU = &provisionclient.AWGPeerConfig{ServerPublicKey: testKey(3)}
	err = checkExpectedServerKeys(deviceEnrollAPIRequest{ExpectedServerAWGRUKey: testKey(4)}, resp)
	if err == nil || !err.result.AWGRUKeyMismatch {
		t.Fatalf("awg-ru mismatch accepted without require flag: %v", err)
	}
	raw := encodeProvisionResult(provisionAPIResult{OK: false, Error: err.Error(), AWGRUKeyMismatch: true})
	var decoded map[string]any
	if jsonErr := json.Unmarshal([]byte(raw), &decoded); jsonErr != nil || decoded["awgru_key_mismatch"] != true {
		t.Fatalf("mismatch flag not encoded: %s", raw)
	}
}

func TestApplyDiscoveredEndpointsRejectsBundleExpiredOnDeviceClock(t *testing.T) {
	old := discoveryLocalNow
	discoveryLocalNow = func() time.Time { return time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC) }
	defer func() { discoveryLocalNow = old }()

	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	// A replayed mirror Date inside the validity window must not revive it.
	req := signer.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "expired") {
		t.Fatalf("bundle expired on device clock accepted: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsAcceptsSuppliedNowWhenDeviceClockBehind(t *testing.T) {
	old := discoveryLocalNow
	discoveryLocalNow = func() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { discoveryLocalNow = old }()

	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	req := signer.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if !result.OK {
		t.Fatalf("valid bundle rejected with device clock behind: %s", result.Error)
	}
}
