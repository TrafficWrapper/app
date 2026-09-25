package transport

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalSOCKSAuthIsStableRandomHex(t *testing.T) {
	var first, second struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal([]byte(LocalSOCKSAuth()), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(LocalSOCKSAuth()), &second); err != nil {
		t.Fatal(err)
	}
	if first.Error != "" {
		t.Fatalf("unexpected error: %s", first.Error)
	}
	if first.Username != localSOCKSUsername {
		t.Fatalf("username=%q", first.Username)
	}
	if len(first.Password) != 32 {
		t.Fatalf("password length=%d want 32", len(first.Password))
	}
	if _, err := hex.DecodeString(first.Password); err != nil {
		t.Fatalf("password is not hex: %v", err)
	}
	if first != second {
		t.Fatal("credentials changed between calls")
	}
}

func socksHandshakeReply(t *testing.T, write func(net.Conn), replyLen int) []byte {
	t.Helper()
	client, serverConn := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- (&socksServer{}).handle(context.Background(), serverConn) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	write(client)
	reply := make([]byte, replyLen)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("handler accepted unauthenticated client")
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not finish")
	}
	return reply
}

func TestSOCKSServerRejectsNoAuth(t *testing.T) {
	reply := socksHandshakeReply(t, func(c net.Conn) {
		_, _ = c.Write([]byte{socksVersion5, 0x01, socksNoAuth})
	}, 2)
	if reply[0] != socksVersion5 || reply[1] != socksMethodNoAcceptable {
		t.Fatalf("reply=%x want 05ff", reply)
	}
}

func TestSOCKSServerRejectsWrongPassword(t *testing.T) {
	reply := socksHandshakeReply(t, func(c net.Conn) {
		_, _ = c.Write([]byte{socksVersion5, 0x02, socksNoAuth, socksMethodUserPass})
		greeting := make([]byte, 2)
		_, _ = io.ReadFull(c, greeting)
		user, pass := []byte(localSOCKSUsername), []byte("00000000000000000000000000000000")
		msg := append([]byte{socksUserPassVersion, byte(len(user))}, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		_, _ = c.Write(msg)
	}, 2)
	if reply[0] != socksUserPassVersion || reply[1] == 0x00 {
		t.Fatalf("auth reply=%x want failure", reply)
	}
}

func TestVpnBridgeSOCKS5ConnectAuthenticates(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var authed atomic.Bool
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		head := make([]byte, 2)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		methods := make([]byte, head[1])
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		if err := testSOCKSServerRouterProof(conn, methods, testInternalPassword(t)); err != nil {
			return
		}
		authed.Store(true)
		if _, err := readSOCKSConnect(conn); err != nil {
			return
		}
		_ = writeSOCKSReply(conn, 0x00)
		_, _ = conn.Write([]byte("hi"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, untrack, err := vpnBridgeSOCKS5Connect(ctx, ln.Addr().String(), "example.com:443", nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer untrack()
	defer conn.Close()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("read after connect: %q %v", buf, err)
	}
	if !authed.Load() {
		t.Fatal("client did not authenticate")
	}
}
