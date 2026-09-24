package transport

import (
	"fmt"
	"log"
	"reflect"
	"strings"
	"sync"
	"unsafe"

	netstacktun "github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	tcpBufferMin     = 64 * 1024
	tcpBufferDefault = 4 * 1024 * 1024
	tcpBufferMax     = 16 * 1024 * 1024
)

// netstackTUNView mirrors the leading fields of the unexported netTun struct
// behind netstacktun.Net. The unsafe cast is only performed after
// checkNetstackTUNLayout confirmed that names, types and offsets still match.
type netstackTUNView struct {
	ep    *channel.Endpoint
	stack *stack.Stack
}

var netstackTUNLayout = sync.OnceValue(checkNetstackTUNLayout)

func checkNetstackTUNLayout() error {
	netType := reflect.TypeOf(netstacktun.Net{})
	viewType := reflect.TypeOf(netstackTUNView{})
	if netType.Kind() != reflect.Struct || netType.NumField() < viewType.NumField() {
		return fmt.Errorf("netstack tun layout changed: %s has %d fields", netType, netType.NumField())
	}
	for i := 0; i < viewType.NumField(); i++ {
		want, got := viewType.Field(i), netType.Field(i)
		if got.Name != want.Name || got.Type != want.Type || got.Offset != want.Offset {
			return fmt.Errorf("netstack tun layout changed: field %d is %s %s@%d, want %s %s@%d",
				i, got.Name, got.Type, got.Offset, want.Name, want.Type, want.Offset)
		}
	}
	return nil
}

func tuneNetstack(tnet *netstacktun.Net) error {
	if tnet == nil {
		return nil
	}
	if err := netstackTUNLayout(); err != nil {
		log.Printf("transport: netstack tuning skipped: %v", err)
		return nil
	}
	st := (*netstackTUNView)(unsafe.Pointer(tnet)).stack
	if st == nil {
		return fmt.Errorf("netstack stack is nil")
	}
	var errs []string
	send := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcpBufferMin,
		Default: tcpBufferDefault,
		Max:     tcpBufferMax,
	}
	if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		errs = append(errs, fmt.Sprintf("send_buffer=%s", err))
	}
	receive := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcpBufferMin,
		Default: tcpBufferDefault,
		Max:     tcpBufferMax,
	}
	if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil {
		errs = append(errs, fmt.Sprintf("receive_buffer=%s", err))
	}
	moderateReceive := tcpip.TCPModerateReceiveBufferOption(true)
	if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, &moderateReceive); err != nil {
		errs = append(errs, fmt.Sprintf("moderate_receive=%s", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("tune netstack tcp: %s", strings.Join(errs, "; "))
	}
	return nil
}
