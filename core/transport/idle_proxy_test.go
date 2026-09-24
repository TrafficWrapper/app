package transport

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type deadlineCountingConn struct {
	net.Conn
	calls *atomic.Int64
}

func (c deadlineCountingConn) SetDeadline(t time.Time) error {
	c.calls.Add(1)
	return c.Conn.SetDeadline(t)
}

func (c deadlineCountingConn) SetReadDeadline(t time.Time) error {
	c.calls.Add(1)
	return c.Conn.SetReadDeadline(t)
}

func (c deadlineCountingConn) SetWriteDeadline(t time.Time) error {
	c.calls.Add(1)
	return c.Conn.SetWriteDeadline(t)
}

func (c deadlineCountingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// A long one-way transfer must not trip the idle timeout of the silent
// direction: the reverse path stays usable afterwards.
func TestProxyPairActivityInOneDirectionKeepsBothAlive(t *testing.T) {
	const idle = 150 * time.Millisecond
	leftClient, leftProxy := tcpPair(t)
	rightClient, rightProxy := tcpPair(t)
	defer leftClient.Close()
	defer rightClient.Close()

	var down, up atomic.Uint64
	done := make(chan error, 1)
	go func() { done <- proxyPair(leftProxy, rightProxy, idle, &down, &up) }()

	received := make(chan int, 1)
	go func() {
		n, _ := io.CopyN(io.Discard, rightClient, 4096*50)
		received <- int(n)
	}()
	chunk := bytes.Repeat([]byte{'x'}, 4096)
	deadline := time.Now().Add(4 * idle)
	sent := 0
	for time.Now().Before(deadline) && sent < 50 {
		if _, err := leftClient.Write(chunk); err != nil {
			t.Fatalf("upload write: %v", err)
		}
		sent++
		time.Sleep(idle / 10)
	}
	for ; sent < 50; sent++ {
		if _, err := leftClient.Write(chunk); err != nil {
			t.Fatalf("upload write: %v", err)
		}
	}
	if n := <-received; n != 4096*50 {
		t.Fatalf("received %d bytes", n)
	}
	// The download direction was silent for > idle; it must still work.
	if _, err := rightClient.Write([]byte("reply")); err != nil {
		t.Fatalf("reply write: %v", err)
	}
	_ = leftClient.SetReadDeadline(time.Now().Add(time.Second))
	reply := make([]byte, 5)
	if _, err := io.ReadFull(leftClient, reply); err != nil || string(reply) != "reply" {
		t.Fatalf("reply read: %q %v", reply, err)
	}
	select {
	case <-done:
	case <-time.After(5 * idle):
		t.Fatal("idle pair was not closed")
	}
	// Counters are bumped after each write returns, so the peer can observe
	// the bytes first; they are only settled once proxyPair has returned.
	if up.Load() != 4096*50 || down.Load() != 5 {
		t.Fatalf("byte counters up=%d down=%d", up.Load(), down.Load())
	}
	// Idle expiry closes the connection instead of half-closing it as EOF.
	_ = leftClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := leftClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("left side still open after idle expiry")
	}
}

func TestProxyPairExtendsDeadlinesLazily(t *testing.T) {
	leftClient, leftProxy := tcpPair(t)
	rightClient, rightProxy := tcpPair(t)
	defer leftClient.Close()
	defer rightClient.Close()
	var calls atomic.Int64
	left := deadlineCountingConn{Conn: leftProxy, calls: &calls}
	right := deadlineCountingConn{Conn: rightProxy, calls: &calls}
	done := make(chan error, 1)
	go func() { done <- proxyPair(left, right, time.Minute, nil, nil) }()

	const chunks = 500
	go func() {
		for i := 0; i < chunks; i++ {
			if _, err := leftClient.Write([]byte("0123456789")); err != nil {
				return
			}
		}
		_ = leftClient.CloseWrite()
	}()
	if _, err := io.CopyN(io.Discard, rightClient, chunks*10); err != nil {
		t.Fatalf("copy: %v", err)
	}
	_ = rightClient.CloseWrite()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not finish")
	}
	if got := calls.Load(); got > 10 {
		t.Fatalf("deadline calls=%d, want a handful for %d chunks", got, chunks)
	}
}
