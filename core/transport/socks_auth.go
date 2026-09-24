package transport

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	socksMethodUserPass     = 0x02
	socksMethodNoAcceptable = 0xff
	socksUserPassVersion    = 0x01
	localSOCKSUsername      = "twi"
	localSOCKSPasswordBytes = 16
)

var localSOCKSCreds struct {
	once     sync.Once
	username string
	password string
	err      error
}

// localSOCKSCredentials returns the per-process credentials that guard every
// loopback SOCKS5 listener started by this package. They are generated once
// with crypto/rand and never persisted.
func localSOCKSCredentials() (string, string, error) {
	localSOCKSCreds.once.Do(func() {
		raw := make([]byte, localSOCKSPasswordBytes)
		if _, err := rand.Read(raw); err != nil {
			localSOCKSCreds.err = fmt.Errorf("generate local socks password: %w", err)
			return
		}
		localSOCKSCreds.username = localSOCKSUsername
		localSOCKSCreds.password = hex.EncodeToString(raw)
	})
	return localSOCKSCreds.username, localSOCKSCreds.password, localSOCKSCreds.err
}

// LocalSOCKSAuth returns {"username":"...","password":"..."} with the internal
// RFC 1929 credentials required by the loopback SOCKS5 listeners, or
// {"error":"..."} when they could not be generated.
func LocalSOCKSAuth() string {
	username, password, err := localSOCKSCredentials()
	var out []byte
	if err != nil {
		out, _ = json.Marshal(map[string]string{"error": err.Error()})
	} else {
		out, _ = json.Marshal(map[string]string{"username": username, "password": password})
	}
	return string(out)
}

// socksServerAuthenticate performs RFC 1928 method negotiation and RFC 1929
// username/password verification. No-auth clients are rejected with 0xFF.
func socksServerAuthenticate(rw io.ReadWriter, methods []byte) error {
	offered := false
	for _, method := range methods {
		if method == socksMethodUserPass {
			offered = true
			break
		}
	}
	if !offered {
		_, _ = rw.Write([]byte{socksVersion5, socksMethodNoAcceptable})
		return errors.New("socks client did not offer username/password auth")
	}
	if _, err := rw.Write([]byte{socksVersion5, socksMethodUserPass}); err != nil {
		return err
	}
	var head [2]byte
	if _, err := io.ReadFull(rw, head[:]); err != nil {
		return err
	}
	if head[0] != socksUserPassVersion {
		_, _ = rw.Write([]byte{socksUserPassVersion, 0x01})
		return fmt.Errorf("unsupported socks auth version %d", head[0])
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(rw, user); err != nil {
		return err
	}
	var plen [1]byte
	if _, err := io.ReadFull(rw, plen[:]); err != nil {
		return err
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(rw, pass); err != nil {
		return err
	}
	wantUser, wantPass, err := localSOCKSCredentials()
	ok := err == nil &&
		subtle.ConstantTimeCompare(user, []byte(wantUser))&subtle.ConstantTimeCompare(pass, []byte(wantPass)) == 1
	if !ok {
		_, _ = rw.Write([]byte{socksUserPassVersion, 0x01})
		if err != nil {
			return err
		}
		return errors.New("socks authentication failed")
	}
	_, err = rw.Write([]byte{socksUserPassVersion, 0x00})
	return err
}

// socksClientAuthenticate negotiates RFC 1929 auth with the internal
// credentials against a loopback SOCKS5 server.
func socksClientAuthenticate(rw io.ReadWriter) error {
	username, password, err := localSOCKSCredentials()
	if err != nil {
		return err
	}
	if len(username) == 0 || len(username) > 255 || len(password) == 0 || len(password) > 255 {
		return errors.New("local socks credentials length is invalid")
	}
	if _, err := rw.Write([]byte{socksVersion5, 0x01, socksMethodUserPass}); err != nil {
		return err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(rw, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != socksVersion5 || greeting[1] != socksMethodUserPass {
		return fmt.Errorf("socks auth rejected: %02x %02x", greeting[0], greeting[1])
	}
	msg := make([]byte, 0, 3+len(username)+len(password))
	msg = append(msg, socksUserPassVersion, byte(len(username)))
	msg = append(msg, username...)
	msg = append(msg, byte(len(password)))
	msg = append(msg, password...)
	if _, err := rw.Write(msg); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(rw, reply[:]); err != nil {
		return err
	}
	if reply[0] != socksUserPassVersion || reply[1] != 0x00 {
		return fmt.Errorf("socks authentication failed: %02x %02x", reply[0], reply[1])
	}
	return nil
}
