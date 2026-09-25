package dialect

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn"

	"github.com/TrafficWrapper/app/core/awg/device"
)

type dialectFixture struct {
	Name    string  `json:"name"`
	Dialect Dialect `json:"dialect"`
}

// loadWideDialectFixtures returns static dialects on the edges of the
// worker generator (Jc 3..16, Jmin 8..64, Jmax Jmin+32..Jmin+200, S and H at
// their production limits) plus one from the legacy generator.
func loadWideDialectFixtures(t testing.TB) []dialectFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/wide_dialects.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []dialectFixture
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 9 {
		t.Fatalf("expected at least 9 fixtures, got %d", len(fixtures))
	}
	return fixtures
}

func TestWideDialectFixturesPassProductionValidation(t *testing.T) {
	for _, fx := range loadWideDialectFixtures(t) {
		t.Run(fx.Name, func(t *testing.T) {
			if err := ValidateProduction(fx.Dialect, DefaultMTU); err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if _, err := EffectiveMTU(DefaultMTU, fx.Dialect); err != nil {
				t.Fatalf("effective mtu: %v", err)
			}
			dev := device.NewDevice(newFakeTUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "test: "))
			defer dev.Close()
			if err := dev.IpcSetOperation(strings.NewReader(strings.Join(UAPILines(fx.Dialect), "\n") + "\n")); err != nil {
				t.Fatalf("device rejected: %v", err)
			}
		})
	}
}

func TestValidateProductionRejectsCompat(t *testing.T) {
	if err := ValidateProduction(Compat(), DefaultMTU); err == nil {
		t.Fatal("compat dialect accepted as production")
	}
}

func TestGeneratedHeadersAreNotFixedWindows(t *testing.T) {
	oldWindows := [][2]uint32{
		{100_000_000, 450_000_000},
		{600_000_000, 950_000_000},
		{1_100_000_000, 1_450_000_000},
		{1_600_000_000, 2_050_000_000},
	}
	outside := 0
	for i := 0; i < 200; i++ {
		d, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateProduction(d, DefaultMTU); err != nil {
			t.Fatalf("generated invalid dialect %s: %v", Summary(d), err)
		}
		if paddedSizesCollide(d.S1, d.S2, d.S3, d.S4) {
			t.Fatalf("generated colliding padded sizes: %s", Summary(d))
		}
		h, err := HeaderRanges(d)
		if err != nil {
			t.Fatal(err)
		}
		for slot, r := range h {
			w := oldWindows[slot]
			if r.Start < w[0] || r.End > w[1] {
				outside++
			}
			if width := r.End - r.Start; width < minHeaderSpan || width > maxHeaderSpan {
				t.Fatalf("h%d width %d outside [%d,%d]", slot+1, width, minHeaderSpan, maxHeaderSpan)
			}
		}
	}
	if outside == 0 {
		t.Fatal("all generated headers fell into the fixed per-slot windows")
	}
}

func TestPaddedSizesCollide(t *testing.T) {
	if !paddedSizesCollide(20, 76, 0, 0) { // 148+20 == 92+76
		t.Fatal("init/response collision not detected")
	}
	if !paddedSizesCollide(20, 30, 58, 0) { // 92+30 == 64+58
		t.Fatal("response/cookie collision not detected")
	}
	if !paddedSizesCollide(20, 30, 0, 32) { // 64+0 == 32+32
		t.Fatal("cookie/transport collision not detected")
	}
	if paddedSizesCollide(20, 30, 10, 16) {
		t.Fatal("false positive")
	}
}

func FuzzParseHeaderRange(f *testing.F) {
	for _, seed := range []string{"5", "5-10", "0-4294967295", "10-5", "", "-", "1-", " 1", "1\n2", "4294967296"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		r, err := ParseHeaderRange(spec)
		if err != nil {
			return
		}
		if r.Start > r.End {
			t.Fatalf("inverted range from %q", spec)
		}
		back, err := ParseHeaderRange(r.String())
		if err != nil || back != r {
			t.Fatalf("round trip %q -> %s failed: %v", spec, r, err)
		}
	})
}
