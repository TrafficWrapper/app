package device

import (
	"encoding/binary"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

type paramsTestTUN struct {
	events chan tun.Event
	once   sync.Once
}

func (t *paramsTestTUN) File() *os.File                               { return nil }
func (t *paramsTestTUN) Read(_ [][]byte, _ []int, _ int) (int, error) { return 0, io.ErrClosedPipe }
func (t *paramsTestTUN) Write(bufs [][]byte, _ int) (int, error)      { return len(bufs), nil }
func (t *paramsTestTUN) MTU() (int, error)                            { return 1420, nil }
func (t *paramsTestTUN) Name() (string, error)                        { return "fake0", nil }
func (t *paramsTestTUN) Events() <-chan tun.Event                     { return t.events }
func (t *paramsTestTUN) BatchSize() int                               { return 1 }
func (t *paramsTestTUN) Close() error {
	t.once.Do(func() { close(t.events) })
	return nil
}

func newParamsTestDevice(t testing.TB) *Device {
	t.Helper()
	dev := NewDevice(&paramsTestTUN{events: make(chan tun.Event)}, conn.NewDefaultBind(), NewLogger(LogLevelSilent, "test: "))
	t.Cleanup(dev.Close)
	return dev
}

const validAWGUAPI = "jc=4\njmin=8\njmax=80\ns1=20\ns2=30\ns3=10\ns4=16\n" +
	"h1=100000000-110000000\nh2=600000000-610000000\nh3=1100000000-1110000000\nh4=1600000000-1610000000\n"

func TestIpcSetRejectedOperationLeavesDeviceUntouched(t *testing.T) {
	dev := newParamsTestDevice(t)
	if err := dev.IpcSet(validAWGUAPI); err != nil {
		t.Fatal(err)
	}
	before := dev.awgParams()
	beforeKey := dev.staticIdentity.privateKey

	// h1 is valid on its own, but overlaps h2 of the final set; the private
	// key and s1 precede the failing header and must not be applied either.
	bad := "private_key=" + strings.Repeat("11", 32) + "\ns1=99\nh1=600000005-600000010\n"
	if err := dev.IpcSet(bad); err == nil {
		t.Fatal("overlapping headers accepted")
	}
	if dev.awgParams() != before {
		t.Fatal("awg parameters changed by a rejected operation")
	}
	if dev.staticIdentity.privateKey != beforeKey {
		t.Fatal("private key applied by a rejected operation")
	}
}

func TestIpcSetRejectsValuesThatWouldPanic(t *testing.T) {
	cases := map[string]string{
		"huge s4":             "s4=70000\n",
		"s4 over mtu budget":  "s4=65000\n",
		"huge s1":             "s1=1000000000\n",
		"inverted junk":       "jc=4\njmin=100\njmax=50\n",
		"jmin without jmax":   "jc=4\njmin=100\n",
		"huge jc":             "jc=100000000\njmin=8\njmax=40\n",
		"huge jmax":           "jc=1\njmin=8\njmax=1000000000\n",
		"inverted header":     "h1=10-5\n",
		"line without equals": "jc\n",
	}
	for name, uapi := range cases {
		t.Run(name, func(t *testing.T) {
			dev := newParamsTestDevice(t)
			before := dev.awgParams()
			if err := dev.IpcSet(uapi); err == nil {
				t.Fatalf("accepted %q", uapi)
			}
			if dev.awgParams() != before {
				t.Fatal("parameters changed")
			}
		})
	}
}

func TestMagicHeaderGenerateFullRangeDoesNotPanic(t *testing.T) {
	h := &magicHeader{start: 0, end: ^uint32(0)}
	for i := 0; i < 100; i++ {
		_ = h.Generate()
	}
	dev := newParamsTestDevice(t)
	// A full-range header cannot coexist with the default ones, so replace
	// all four.
	if err := dev.IpcSet("h1=0-4294967291\nh2=4294967292\nh3=4294967293\nh4=4294967294-4294967295\n"); err != nil {
		t.Fatal(err)
	}
	_ = dev.awgParams().initHeader.Generate()
}

// Existing worker dialects (and the generator bounds Jc 3..16, Jmin 8..64,
// Jmax Jmin+32..Jmin+200) must keep applying.
func TestIpcSetAcceptsWideWorkerDialects(t *testing.T) {
	for _, uapi := range []string{
		"jc=3\njmin=8\njmax=40\ns1=15\ns2=15\ns3=0\ns4=0\n",
		"jc=16\njmin=64\njmax=264\ns1=150\ns2=150\ns3=64\ns4=32\n",
		"jc=16\njmin=64\njmax=96\n",
	} {
		dev := newParamsTestDevice(t)
		if err := dev.IpcSet(uapi); err != nil {
			t.Fatalf("rejected %q: %v", uapi, err)
		}
	}
}

func TestAWGParamsConcurrentSetAndRead(t *testing.T) {
	dev := newParamsTestDevice(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		packet := make([]byte, MessageInitiationSize+20)
		binary.LittleEndian.PutUint32(packet[20:], 100000001)
		for {
			select {
			case <-stop:
				return
			default:
			}
			dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
			_ = dev.awgParams().transportHeader.Generate()
		}
	}()
	for i := 0; i < 200; i++ {
		if err := dev.IpcSet(validAWGUAPI); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if typ, pad := dev.DeterminePacketTypeAndPadding(func() []byte {
		p := make([]byte, MessageInitiationSize+20)
		binary.LittleEndian.PutUint32(p[20:], 100000001)
		return p
	}(), MessageUnknownType); typ != MessageInitiationType || pad != 20 {
		t.Fatalf("type=%d padding=%d", typ, pad)
	}
}

func FuzzIpcSetOperation(f *testing.F) {
	f.Add(validAWGUAPI)
	f.Add("h1=0-4294967295\n")
	f.Add("s4=70000\n")
	f.Add("jc=4\njmin=100\njmax=50\n")
	f.Add("i1=<b 0xdeadbeef><r 16>\n")
	f.Add("replace_peers=true\njc=3\n")
	f.Fuzz(func(t *testing.T, uapi string) {
		dev := newParamsTestDevice(t)
		_ = dev.IpcSet(uapi)
		p := dev.awgParams()
		if err := p.validate(int(dev.tun.mtu.Load())); err != nil {
			t.Fatalf("device holds invalid parameters after %q: %v", uapi, err)
		}
		_ = p.initHeader.Generate()
		_ = p.transportHeader.Generate()
		dev.DeterminePacketTypeAndPadding(make([]byte, 200), MessageUnknownType)
	})
}
