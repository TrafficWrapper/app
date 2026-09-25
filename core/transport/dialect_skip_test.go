package transport

import (
	"encoding/json"
	"fmt"
	"testing"

	awgdialect "github.com/TrafficWrapper/app/core/awg/dialect"
	"github.com/TrafficWrapper/app/core/internal/provisionclient"
)

func TestStoreApprovedEnrollmentSkipsNonProductionDialect(t *testing.T) {
	setPendingProvision(t, "stored-default", "")
	resp := provisionclient.Response{
		Status:          "approved",
		InternalIP:      "10.13.13.42/32",
		Endpoint:        "203.0.113.10:51821",
		ServerPublicKey: testKey(2),
		PSK2:            testKey(3),
		// No awg_preset: plain WireGuard, which no production worker speaks.
		AWGRU: &provisionclient.AWGPeerConfig{
			InternalIP:      "10.14.0.2/32",
			Endpoint:        "203.0.113.11:51821",
			ServerPublicKey: testKey(4),
			PSK2:            testKey(5),
			AWGPreset:       testBasePreset(),
		},
	}
	req := deviceEnrollAPIRequest{SOCKSListen: defaultSOCKSListen, AWGRUSOCKSListen: defaultAWGRUSOCKSListen, MTU: defaultMTU}
	result, err := storeApprovedEnrollment(req, resp, provisionAPIResult{OK: true}, testKey(1), testKey(6))
	if err != nil {
		t.Fatalf("enrollment failed: %v", err)
	}
	if result.ConfigStored || !result.AWGRUConfigStored {
		t.Fatalf("result=%+v", result)
	}
	if len(result.AWGRejected) != 1 || result.AWGRejected[0].Route != "awg" {
		t.Fatalf("awg_rejected=%+v", result.AWGRejected)
	}
	pendingProvision.Lock()
	defer pendingProvision.Unlock()
	if pendingProvision.configJSON != "stored-default" {
		t.Fatal("stored awg config overwritten")
	}
}

// The pre-dialect legacy apply JSON (AWG route without awg_preset) must not
// fail the whole apply: that route is skipped and reported, its stored
// config is kept, and the other AWG slot is still applied.
func TestApplyPublicPlatformConfigSkipsRouteWithoutDialect(t *testing.T) {
	setPendingProvision(t, "stored-default", "stored-awg-ru")
	raw := `{"awg_private_key":"` + testKey(1) + `","internal_ip":"10.13.13.42/32","psk2":"` + testKey(3) +
		`","server_awg_public":"` + testKey(2) + `","dns_servers":["9.9.9.9"],` +
		`"awg":{"type":"awg","address":"203.0.113.10","port":51821,"public_key":"` + testKey(2) + `"},` +
		`"awg_ru":{"endpoint":"203.0.113.11:51821","awg_preset":` + string(testBasePresetRaw()) + `}}`
	var result publicApplyAPIResult
	if err := json.Unmarshal([]byte(ApplyPublicPlatformConfig(raw)), &result); err != nil || !result.OK {
		t.Fatalf("apply failed: %+v %v", result, err)
	}
	if result.ConfigStored || !result.AWGRUConfigStored {
		t.Fatalf("result=%+v", result)
	}
	if len(result.AWGRejected) != 1 || result.AWGRejected[0].Route != "awg" || result.AWGRejected[0].Reason == "" {
		t.Fatalf("awg_rejected=%+v", result.AWGRejected)
	}
	pendingProvision.Lock()
	stored, storedRU := pendingProvision.configJSON, pendingProvision.awgRUConfigJSON
	pendingProvision.Unlock()
	if stored != "stored-default" {
		t.Fatal("stored awg config was overwritten by a rejected route")
	}
	if decodeConfig(t, storedRU).Endpoint != "203.0.113.11:51821" {
		t.Fatalf("awg_ru not applied: %s", storedRU)
	}
}

func TestApplyPublicPlatformConfigSkipsCompatRoute(t *testing.T) {
	setPendingProvision(t, "", "stored-awg-ru")
	req := testPublicApplyRequest()
	compat, _ := json.Marshal(awgdialect.Compat())
	req.AWGRU = &publicRouteSpec{Endpoint: "203.0.113.11:51821", AWGPreset: compat}
	result, err := applyPublicPlatformConfig(req)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ConfigStored || result.AWGRUConfigStored {
		t.Fatalf("result=%+v", result)
	}
	if len(result.AWGRejected) != 1 || result.AWGRejected[0].Route != "awg_ru" {
		t.Fatalf("awg_rejected=%+v", result.AWGRejected)
	}
	pendingProvision.Lock()
	defer pendingProvision.Unlock()
	if pendingProvision.awgRUConfigJSON != "stored-awg-ru" {
		t.Fatal("stored awg_ru config was overwritten")
	}
}

func TestApplyPublicPlatformConfigMalformedDialectStillFails(t *testing.T) {
	setPendingProvision(t, "stored", "")
	req := testPublicApplyRequest()
	req.AWG.AWGPreset = json.RawMessage(`"not-an-object"`)
	if _, err := applyPublicPlatformConfig(req); err == nil {
		t.Fatal("malformed dialect accepted")
	}
}

func testBundleWithAWGPresets(t *testing.T, presets ...any) map[string]any {
	t.Helper()
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	endpoints := bundle["endpoints"].(map[string]any)
	template := endpoints["awg"].([]any)[0].(map[string]any)
	var awg []any
	for i, p := range presets {
		entry := map[string]any{}
		for k, v := range template {
			entry[k] = v
		}
		entry["priority"] = i
		entry["endpoint"] = fmt.Sprintf("198.51.100.%d:51821", 50+i)
		delete(entry, "egress_ip")
		if p == nil {
			delete(entry, "awg_preset")
		} else {
			entry["awg_preset"] = p
		}
		awg = append(awg, entry)
	}
	endpoints["awg"] = awg
	return bundle
}

func TestApplyDiscoveredEndpointsSkipsNonProductionAWGEntry(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	bundle := testBundleWithAWGPresets(t, awgdialect.Compat(), testWidePreset())
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")))
	if !result.OK {
		t.Fatalf("feed rejected: %s", result.Error)
	}
	var merged config
	if err := json.Unmarshal([]byte(result.ConfigJSON), &merged); err != nil {
		t.Fatal(err)
	}
	if merged.Endpoint != "198.51.100.51:51821" || merged.AWGPreset != testWidePreset() {
		t.Fatalf("merged endpoint=%q preset=%+v", merged.Endpoint, merged.AWGPreset)
	}
	if len(result.AWGRejected) != 1 || result.AWGRejected[0].Route != "awg[0]" {
		t.Fatalf("awg_rejected=%+v", result.AWGRejected)
	}
}

func TestApplyDiscoveredEndpointsWithoutUsableAWGKeepsConfig(t *testing.T) {
	signer := newTestSigner(t)
	pinTestSigner(t, signer)
	base := testBaseConfig(t)
	bundle := testBundleWithAWGPresets(t, nil, awgdialect.Compat())
	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(signer.request(t, bundle, base, 9, "2026-06-13T12:00:00Z")))
	if !result.OK {
		t.Fatalf("feed rejected: %s", result.Error)
	}
	if result.ConfigJSON != base || !result.AWGMergeSkipped {
		t.Fatalf("stored config changed: skipped=%t", result.AWGMergeSkipped)
	}
	if len(result.AWGRejected) != 2 {
		t.Fatalf("awg_rejected=%+v", result.AWGRejected)
	}
	if result.Reality == nil || result.EgressIP != "203.0.113.77" {
		t.Fatal("reality part of the feed was not applied")
	}
}
