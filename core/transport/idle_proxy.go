package transport

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const proxyCopyBufferLen = 32 * 1024

var proxyCopyBuffers = sync.Pool{
	New: func() any {
		buf := make([]byte, proxyCopyBufferLen)
		return &buf
	},
}

var errProxyIdleTimeout = errors.New("proxy idle timeout")

// connIdleTracker enforces a single idle timeout for a pair of connections.
// Activity in either direction keeps both directions alive. Deadlines are
// extended lazily (at most once per idle/4) instead of before every read and
// write; a deadline that fires while the connection pair was recently active
// is re-armed and never surfaces as EOF.
type connIdleTracker struct {
	conns        [2]net.Conn
	idle         time.Duration
	lastActivity atomic.Int64
	lastExtend   atomic.Int64
	expired      atomic.Bool
	closeOnce    sync.Once
}

func newConnIdleTracker(left, right net.Conn, idle time.Duration) *connIdleTracker {
	t := &connIdleTracker{conns: [2]net.Conn{left, right}, idle: idle}
	now := time.Now()
	t.lastActivity.Store(now.UnixNano())
	t.lastExtend.Store(now.UnixNano())
	t.setDeadlines(now.Add(idle))
	return t
}

func (t *connIdleTracker) setDeadlines(deadline time.Time) {
	if t.idle <= 0 {
		return
	}
	for _, conn := range t.conns {
		_ = conn.SetDeadline(deadline)
	}
}

func (t *connIdleTracker) touch() {
	if t.idle <= 0 {
		return
	}
	now := time.Now().UnixNano()
	t.lastActivity.Store(now)
	last := t.lastExtend.Load()
	if time.Duration(now-last) < t.idle/4 {
		return
	}
	if t.lastExtend.CompareAndSwap(last, now) {
		t.setDeadlines(time.Unix(0, now).Add(t.idle))
	}
}

// handleTimeout decides whether a deadline error is a real idle expiry. It
// returns true when the caller should retry the I/O.
func (t *connIdleTracker) handleTimeout() bool {
	if t.idle <= 0 || t.expired.Load() {
		return false
	}
	last := time.Unix(0, t.lastActivity.Load())
	if time.Since(last) < t.idle {
		t.lastExtend.Store(time.Now().UnixNano())
		t.setDeadlines(last.Add(t.idle))
		return true
	}
	t.expire()
	return false
}

func (t *connIdleTracker) expire() {
	t.expired.Store(true)
	t.closeAll()
}

func (t *connIdleTracker) closeAll() {
	t.closeOnce.Do(func() {
		for _, conn := range t.conns {
			_ = conn.Close()
		}
	})
}

// proxyPair copies data in both directions between left and right with a
// shared idle timeout. A clean EOF half-closes the opposite side; errors and
// idle expiry close the whole pair. leftBytes counts bytes written to left,
// rightBytes counts bytes written to right; both may be nil.
func proxyPair(left, right net.Conn, idle time.Duration, leftBytes, rightBytes *atomic.Uint64) error {
	tracker := newConnIdleTracker(left, right, idle)
	type copyResult struct {
		dst net.Conn
		err error
	}
	results := make(chan copyResult, 2)
	go func() {
		results <- copyResult{dst: left, err: copyWithTracker(left, right, tracker, leftBytes)}
	}()
	go func() {
		results <- copyResult{dst: right, err: copyWithTracker(right, left, tracker, rightBytes)}
	}()
	var firstErr error
	for i := 0; i < 2; i++ {
		result := <-results
		switch {
		case result.err == nil:
			closeWriteOrClose(result.dst)
		case errors.Is(result.err, errProxyIdleTimeout):
			tracker.closeAll()
		default:
			if firstErr == nil && !isExpectedProxyClose(result.err) {
				firstErr = result.err
			}
			tracker.closeAll()
		}
	}
	tracker.closeAll()
	return firstErr
}

// copyWithTracker copies src to dst until EOF (returns nil), an error, or idle
// expiry (returns errProxyIdleTimeout).
func copyWithTracker(dst, src net.Conn, tracker *connIdleTracker, counter *atomic.Uint64) error {
	bufPtr := proxyCopyBuffers.Get().(*[]byte)
	defer proxyCopyBuffers.Put(bufPtr)
	buf := *bufPtr
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			tracker.touch()
			if err := writeWithTracker(dst, buf[:n], tracker, counter); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if isTimeoutError(readErr) {
				if tracker.handleTimeout() {
					continue
				}
				return errProxyIdleTimeout
			}
			if tracker.expired.Load() {
				return errProxyIdleTimeout
			}
			return readErr
		}
	}
}

func writeWithTracker(dst net.Conn, data []byte, tracker *connIdleTracker, counter *atomic.Uint64) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if n > 0 {
			data = data[n:]
			tracker.touch()
			if counter != nil {
				counter.Add(uint64(n))
			}
		}
		if err != nil {
			if isTimeoutError(err) {
				if tracker.handleTimeout() {
					continue
				}
				return errProxyIdleTimeout
			}
			if tracker.expired.Load() {
				return errProxyIdleTimeout
			}
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func closeWriteOrClose(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
