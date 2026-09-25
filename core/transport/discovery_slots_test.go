package transport

import (
	"reflect"
	"testing"

	awgdialect "github.com/TrafficWrapper/app/core/awg/dialect"
)

// Contract tests for slot-aware discovery (X-M6): feed entries are matched to
// the stored AWG_RU (primary) / AWG (secondary) slots and the REALITY slots
// by worker_id, or by egress IP when the feed has no worker_id.

const (
	slotTestNow       = "2026-06-13T12:00:00Z"
	slotWorkerA       = "w-a"
	slotWorkerB       = "w-b"
	slotEgressA       = "203.0.113.10"
	slotEgressB       = "203.0.113.20"
	slotNewEndpointA  = "198.51.100.10:51821"
	slotNewEndpointB  = "198.51.100.20:51821"
	slotRealityEgress = "198.51.100.99"
)

func slotAWGEntry(priority int, workerID, egressIP, endpoint string) map[string]any {
	entry := map[string]any{
		"priority":          priority,
		"endpoint":          endpoint,
		"egress_ip":         egressIP,
		"server_public_key": testDiscoveredServerKey,
		"awg_preset":        awgdialect.Compat(),
	}
	if workerID != "" {
		entry["worker_id"] = workerID
	}
	return entry
}

func slotRealityEntry(priority int, workerID, egressIP string) map[string]any {
	entry := map[string]any{
		"priority":  priority,
		"address":   "tw.example.test",
		"egress_ip": egressIP,
		"port":      443,
	}
	if workerID != "" {
		entry["worker_id"] = workerID
	}
	return entry
}

func slotBundle(t *testing.T, awg []any, reality []any) map[string]any {
	t.Helper()
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	endpoints := bundle["endpoints"].(map[string]any)
	endpoints["awg"] = awg
	endpoints["reality"] = reality
	return bundle
}

// provisionSlots stores slots through ApplyPublicPlatformConfig, as the app
// does, so the stored metadata carries each slot's worker and egress.
func provisionSlots(t *testing.T, awgRU, awg *publicRouteSpec) {
	t.Helper()
	setPendingProvision(t, "", "") // restores the previous state on cleanup
	req := testPublicApplyRequest()
	req.AWGRU, req.AWG = awgRU, awg
	if _, err := applyPublicPlatformConfig(req); err != nil {
		t.Fatal(err)
	}
}

func pendingEndpoints(t *testing.T) (awgRU string, awg string) {
	t.Helper()
	pendingProvision.Lock()
	ruJSON, awgJSON := pendingProvision.awgRUConfigJSON, pendingProvision.configJSON
	pendingProvision.Unlock()
	if ruJSON != "" {
		awgRU = decodeConfig(t, ruJSON).Endpoint
	}
	if awgJSON != "" {
		awg = decodeConfig(t, awgJSON).Endpoint
	}
	return awgRU, awg
}

// One worker: only the primary AWG_RU slot exists. A reduced feed (no
// REALITY) must be merged into it instead of failing on the empty secondary.
func TestDiscoveryReducedFeedOneWorkerMergesPrimarySlot(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	provisionSlots(t, &publicRouteSpec{Endpoint: slotEgressA + ":51821", WorkerID: slotWorkerA, EgressIP: slotEgressA}, nil)
	bundle := slotBundle(t, []any{slotAWGEntry(0, slotWorkerA, "198.51.100.10", slotNewEndpointA)}, []any{})

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.requestWith(t, bundle, "", slotTestNow, map[string]any{
		"reality_slot": map[string]any{"worker_id": slotWorkerA, "egress_ip": slotEgressA},
	})))
	if !result.OK {
		t.Fatalf("reduced feed rejected: %+v", result)
	}
	if !reflect.DeepEqual(result.AWGMergedSlots, []string{"awg_ru"}) {
		t.Fatalf("merged slots=%v, want [awg_ru]", result.AWGMergedSlots)
	}
	if result.Reality != nil || result.EgressIP != "" {
		t.Fatalf("empty reality list must leave the expected egress alone: %+v", result)
	}
	ru, awg := pendingEndpoints(t)
	if ru != slotNewEndpointA || awg != "" {
		t.Fatalf("awg_ru=%q awg=%q", ru, awg)
	}
}

// Full feed with worker_id, two workers: each slot gets its own worker's entry
// regardless of feed priority, and REALITY egress comes only from the slot's
// worker.
func TestDiscoveryFullFeedWithWorkerIDTwoWorkers(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	provisionSlots(t,
		&publicRouteSpec{Endpoint: slotEgressA + ":51821", WorkerID: slotWorkerA, EgressIP: slotEgressA},
		&publicRouteSpec{Endpoint: slotEgressB + ":51821", WorkerID: slotWorkerB, EgressIP: slotEgressB},
	)
	bundle := slotBundle(t,
		[]any{
			// Worker B first by priority: the old code merged it into the
			// secondary slot whatever worker that slot belonged to.
			slotAWGEntry(0, slotWorkerB, "198.51.100.20", slotNewEndpointB),
			slotAWGEntry(1, slotWorkerA, "198.51.100.10", slotNewEndpointA),
		},
		[]any{
			slotRealityEntry(0, slotWorkerB, "198.51.100.200"),
			slotRealityEntry(1, slotWorkerA, slotRealityEgress),
		},
	)
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.requestWith(t, bundle, "", slotTestNow, map[string]any{
		"reality_slot":  map[string]any{"worker_id": slotWorkerA, "egress_ip": slotEgressA},
		"reality2_slot": map[string]any{"worker_id": "w-unknown"},
	})))
	if !result.OK {
		t.Fatalf("apply failed: %+v", result)
	}
	ru, awg := pendingEndpoints(t)
	if ru != slotNewEndpointA || awg != slotNewEndpointB {
		t.Fatalf("awg_ru=%q (want %q) awg=%q (want %q)", ru, slotNewEndpointA, awg, slotNewEndpointB)
	}
	if !reflect.DeepEqual(result.AWGMergedSlots, []string{"awg_ru", "awg"}) {
		t.Fatalf("merged slots=%v", result.AWGMergedSlots)
	}
	if result.Reality == nil || result.EgressIP != slotRealityEgress || result.Reality.WorkerID != slotWorkerA {
		t.Fatalf("reality=%+v egress=%q, want worker %s egress %s", result.Reality, result.EgressIP, slotWorkerA, slotRealityEgress)
	}
	if result.Reality2 != nil {
		t.Fatalf("reality2 matched another worker: %+v", result.Reality2)
	}
}

// Full feed without worker_id (older orchestrator), two workers: entries are
// matched by egress IP only; a REALITY entry of another worker never replaces
// the slot's expected egress.
func TestDiscoveryFullFeedWithoutWorkerIDMatchesByEgress(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	provisionSlots(t,
		&publicRouteSpec{Endpoint: slotEgressA + ":51821", WorkerID: slotWorkerA, EgressIP: slotEgressA},
		&publicRouteSpec{Endpoint: slotEgressB + ":51821", WorkerID: slotWorkerB, EgressIP: slotEgressB},
	)
	bundle := slotBundle(t,
		[]any{
			slotAWGEntry(0, "", "198.51.100.77", "198.51.100.77:51821"), // unknown worker
			slotAWGEntry(1, "", slotEgressB, slotEgressB+":51999"),      // worker B, new port
		},
		[]any{slotRealityEntry(0, "", "198.51.100.77")},
	)
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.requestWith(t, bundle, "", slotTestNow, map[string]any{
		"reality_slot": map[string]any{"worker_id": slotWorkerA, "egress_ip": slotEgressA},
	})))
	if !result.OK {
		t.Fatalf("apply failed: %+v", result)
	}
	ru, awg := pendingEndpoints(t)
	if ru != slotEgressA+":51821" {
		t.Fatalf("awg_ru overwritten by another worker: %q", ru)
	}
	if awg != slotEgressB+":51999" {
		t.Fatalf("awg=%q, want worker B entry", awg)
	}
	if result.Reality != nil || result.EgressIP != "" {
		t.Fatalf("reality egress of another worker returned: %+v", result)
	}

	// The same REALITY entry is accepted when its egress is the slot's own.
	bundle = slotBundle(t, []any{slotAWGEntry(0, "", slotEgressA, slotEgressA+":51821")}, []any{slotRealityEntry(0, "", slotEgressA)})
	bundle["seq"] = 11
	result = decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.requestWith(t, bundle, "", slotTestNow, map[string]any{
		"reality_slot": map[string]any{"egress_ip": slotEgressA},
	})))
	if !result.OK || result.EgressIP != slotEgressA {
		t.Fatalf("own egress entry not matched: %+v", result)
	}
}

// A feed that names no stored worker leaves every slot untouched but is still
// accepted (seq and next_sinks advance); slots without identity never merge.
func TestDiscoveryFeedWithoutMatchingWorkerLeavesSlots(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	provisionSlots(t,
		&publicRouteSpec{Endpoint: slotEgressA + ":51821", WorkerID: slotWorkerA, EgressIP: slotEgressA},
		&publicRouteSpec{Endpoint: slotEgressB + ":51821"}, // no identity at all
	)
	bundle := slotBundle(t, []any{slotAWGEntry(0, "w-other", slotEgressB, "198.51.100.30:51821")}, []any{slotRealityEntry(0, "w-other", "198.51.100.30")})
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.requestWith(t, bundle, "", slotTestNow, map[string]any{
		"reality_slot": map[string]any{"worker_id": slotWorkerA},
	})))
	if !result.OK || result.Seq != 10 {
		t.Fatalf("apply failed: %+v", result)
	}
	if len(result.AWGMergedSlots) != 0 || result.Reality != nil || result.EgressIP != "" {
		t.Fatalf("unrelated worker applied: %+v", result)
	}
	ru, awg := pendingEndpoints(t)
	if ru != slotEgressA+":51821" || awg != slotEgressB+":51821" {
		t.Fatalf("slots changed: awg_ru=%q awg=%q", ru, awg)
	}
}

// Without reality_slot in the request no REALITY entry is returned at all.
func TestDiscoveryWithoutRealitySlotReturnsNoRealityEgress(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, bundle, testBaseConfig(t), 0, slotTestNow)))
	if !result.OK || result.Reality != nil || result.EgressIP != "" {
		t.Fatalf("result=%+v", result)
	}
}

// base_slot scopes the caller-supplied base config to its worker as well.
func TestDiscoveryCallerBaseSlotMatchesWorker(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	base := testBaseConfig(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.requestWith(t, bundle, base, slotTestNow, map[string]any{
		"base_slot": map[string]any{"worker_id": "w-other"},
	})))
	if !result.OK || !result.AWGMergeSkipped || result.ConfigJSON != base {
		t.Fatalf("other worker merged into caller base: %+v", result)
	}
	bundle["seq"] = 11
	result = decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.requestWith(t, bundle, base, slotTestNow, map[string]any{
		"base_slot": map[string]any{"worker_id": testWorkerID},
	})))
	if !result.OK || result.AWGMergeSkipped || decodeConfig(t, result.ConfigJSON).Endpoint != "198.51.100.50:51821" {
		t.Fatalf("own worker not merged: %+v", result)
	}
}
