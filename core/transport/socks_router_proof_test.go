package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func testInternalPassword(t *testing.T) string {
	t.Helper()
	_, password, err := localSOCKSCredentials()
	if err != nil {
		t.Fatal(err)
	}
	return password
}

// testSOCKSServerRouterProof is the listener side of the router proof, as the
// Android router implements it; methods is the already consumed method list.
func testSOCKSServerRouterProof(rw io.ReadWriter, methods []byte, password string) error {
	if !bytes.Contains(methods, []byte{socksMethodRouterProof}) {
		_, _ = rw.Write([]byte{socksVersion5, socksMethodNoAcceptable})
		return errors.New("no router proof offered")
	}
	if _, err := rw.Write([]byte{socksVersion5, socksMethodRouterProof}); err != nil {
		return err
	}
	req := make([]byte, 1+socksRouterNonceBytes)
	if _, err := io.ReadFull(rw, req); err != nil {
		return err
	}
	nonceC := req[1:]
	nonceS := make([]byte, socksRouterNonceBytes)
	_, _ = rand.Read(nonceS)
	reply := append([]byte{socksRouterProofVersion}, nonceS...)
	reply = append(reply, socksRouterProofMAC(password, socksRouterServerLabel, nonceC, nonceS)...)
	if _, err := rw.Write(reply); err != nil {
		return err
	}
	clientMAC := make([]byte, sha256.Size)
	if _, err := io.ReadFull(rw, clientMAC); err != nil {
		return err
	}
	if !bytes.Equal(clientMAC, socksRouterProofMAC(password, socksRouterClientLabel, nonceC, nonceS)) {
		_, _ = rw.Write([]byte{socksRouterProofVersion, 0x01})
		return errors.New("bad client proof")
	}
	_, err := rw.Write([]byte{socksRouterProofVersion, 0x00})
	return err
}

// foreignListener accepts one connection, plays the given server script and
// records every byte the client sent.
func foreignListener(t *testing.T, script func(net.Conn)) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	received := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		rec := &recordingConn{Conn: conn}
		script(rec)
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, _ = io.Copy(io.Discard, rec)
		received <- rec.buf.Bytes()
	}()
	return ln.Addr().String(), received
}

type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.buf.Write(p[:n])
	return n, err
}

func TestVpnBridgeNeverSendsCredentialsToForeignRouterListener(t *testing.T) {
	password := testInternalPassword(t)
	scripts := map[string]func(net.Conn){
		// A foreign listener that asks for RFC 1929 user/pass.
		"userpass": func(c net.Conn) {
			head := make([]byte, 3)
			_, _ = io.ReadFull(c, head)
			_, _ = c.Write([]byte{socksVersion5, socksMethodUserPass})
		},
		// A foreign listener that echoes the private method and fakes a proof.
		"fake-proof": func(c net.Conn) {
			head := make([]byte, 3)
			_, _ = io.ReadFull(c, head)
			_, _ = c.Write([]byte{socksVersion5, socksMethodRouterProof})
			req := make([]byte, 1+socksRouterNonceBytes)
			_, _ = io.ReadFull(c, req)
			fake := make([]byte, 1+socksRouterNonceBytes+sha256.Size)
			fake[0] = socksRouterProofVersion
			_, _ = rand.Read(fake[1:])
			_, _ = c.Write(fake)
		},
		// A foreign listener that accepts no-auth.
		"noauth": func(c net.Conn) {
			head := make([]byte, 3)
			_, _ = io.ReadFull(c, head)
			_, _ = c.Write([]byte{socksVersion5, socksNoAuth})
		},
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			addr, received := foreignListener(t, script)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, _, err := vpnBridgeSOCKS5Connect(ctx, addr, "example.com:443", nil)
			if err == nil {
				_ = conn.Close()
				t.Fatal("connect through a foreign listener must fail")
			}
			if !errors.Is(err, errUntrustedSOCKSRouter) {
				t.Fatalf("err=%v want errUntrustedSOCKSRouter", err)
			}
			got := <-received
			if bytes.Contains(got, []byte(password)) {
				t.Fatal("internal password was sent to a foreign listener")
			}
			if bytes.Contains(got, []byte("example.com")) {
				t.Fatal("connect target was sent to a foreign listener")
			}
		})
	}
}

func TestRouterProofRejectsWrongServerKey(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		head := make([]byte, 3)
		if _, err := io.ReadFull(server, head); err != nil {
			return
		}
		_ = testSOCKSServerRouterProof(server, head[2:], "not-the-internal-password")
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	err := socksClientAuthenticateRouter(client)
	if !errors.Is(err, errUntrustedSOCKSRouter) {
		t.Fatalf("err=%v want errUntrustedSOCKSRouter", err)
	}
}

func TestRouterProofSucceedsWithInternalKey(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		head := make([]byte, 3)
		if _, err := io.ReadFull(server, head); err != nil {
			done <- err
			return
		}
		done <- testSOCKSServerRouterProof(server, head[2:], testInternalPassword(t))
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if err := socksClientAuthenticateRouter(client); err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// TestRouterProofVector pins the MAC construction shared with the Android
// router (LocalSocksAuthTest uses the same vector).
func TestRouterProofVector(t *testing.T) {
	nonceC := bytes.Repeat([]byte{0x11}, socksRouterNonceBytes)
	nonceS := bytes.Repeat([]byte{0x22}, socksRouterNonceBytes)
	got := socksRouterProofMAC("secret", socksRouterServerLabel, nonceC, nonceS)
	const want = "faf99d5f76e82e76ab65ae9b978c5e722c5308c0b55a88db38e9eff53717c38d"
	if hexString(got) != want {
		t.Fatalf("server mac=%s", hexString(got))
	}
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0f])
	}
	return string(out)
}
