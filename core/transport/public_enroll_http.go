package transport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// publicEnrollTransportOptions describe how the enrollment HTTP carrier reaches
// the orchestrator. The zero value is the legacy carrier: direct connection,
// no certificate verification (Noise authenticates the orchestrator).
type publicEnrollTransportOptions struct {
	// socksProxy is the app's loopback SOCKS5 router ("127.0.0.1:port"). When
	// set, every connection goes through the running tunnel and the host name
	// is resolved on the far side; the router proof authenticates both ends.
	socksProxy string
	// spkiPins are SHA-256 digests of the orchestrator TLS SubjectPublicKeyInfo
	// from the bootstrap (orch_tls_spki_sha256). Without pins the carrier keeps
	// the legacy "no certificate verification" behaviour.
	spkiPins [][]byte
	// reEnroll selects the re-enrollment rule when pins are known: system roots
	// (a rotated CA-issued certificate keeps working) or one of the pins
	// (self-signed deployments). A first enrollment accepts only the pins.
	reEnroll bool
}

const (
	maxPublicTLSPins = 8
	// publicEnrollPadMaxBytes bounds the random padding added to enrollment
	// JSON bodies so that request sizes do not identify the protocol.
	publicEnrollPadMaxBytes = 192
)

var errPublicTLSPinMismatch = errors.New("orchestrator tls certificate does not match the bootstrap pin")

// parsePublicTLSPins accepts hex or base64 (std/url, padded or not) SHA-256
// digests. Invalid entries are an error: a malformed pin list must not silently
// fall back to "no verification".
func parsePublicTLSPins(values []string) ([][]byte, error) {
	var out [][]byte
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		value = strings.TrimPrefix(strings.TrimPrefix(value, "sha256/"), "sha256:")
		digest, err := decodePublicTLSPin(value)
		if err != nil {
			return nil, err
		}
		out = append(out, digest)
		if len(out) > maxPublicTLSPins {
			return nil, errors.New("too many orch_tls_spki_sha256 pins")
		}
	}
	return out, nil
}

func decodePublicTLSPin(value string) ([]byte, error) {
	if len(value) == sha256.Size*2 {
		if digest, err := hex.DecodeString(value); err == nil {
			return digest, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if digest, err := enc.DecodeString(value); err == nil && len(digest) == sha256.Size {
			return digest, nil
		}
	}
	return nil, fmt.Errorf("orch_tls_spki_sha256 %q is not a sha256 digest", value)
}

func publicSPKIMatches(cert *x509.Certificate, pins [][]byte) bool {
	if cert == nil {
		return false
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	for _, pin := range pins {
		if subtle.ConstantTimeCompare(sum[:], pin) == 1 {
			return true
		}
	}
	return false
}

// publicTLSConfig builds the carrier TLS config. ALPN offers h2 and http/1.1
// like a regular HTTPS client; the server picks what it supports.
func publicTLSConfig(opts publicEnrollTransportOptions) *tls.Config {
	cfg := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
	if len(opts.spkiPins) == 0 {
		// Legacy deployments serve a self-signed certificate by default and the
		// bootstrap carries no pin: Noise pins the orchestrator static key.
		cfg.InsecureSkipVerify = true
		return cfg
	}
	pins := opts.spkiPins
	reEnroll := opts.reEnroll
	// Verification is done in VerifyConnection so that a pin can replace the
	// chain check; InsecureSkipVerify only disables the built-in check.
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errPublicTLSPinMismatch
		}
		leaf := cs.PeerCertificates[0]
		if publicSPKIMatches(leaf, pins) {
			return nil
		}
		if !reEnroll {
			return errPublicTLSPinMismatch
		}
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName:       cs.ServerName,
			Intermediates: intermediates,
		}); err != nil {
			return fmt.Errorf("orchestrator tls certificate: %w", err)
		}
		return nil
	}
	return cfg
}

// validatePublicSOCKSProxy accepts only a loopback host:port: the router
// SOCKS listener of this app.
func validatePublicSOCKSProxy(value string) (string, error) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(value))
	if err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 {
		return "", fmt.Errorf("socks_proxy %q must be a loopback ip:port", value)
	}
	return ap.String(), nil
}

// publicHTTPClientWith deliberately has no http.Client.Timeout: the overall
// deadline comes from the request context (timeout_seconds).
func publicHTTPClientWith(opts publicEnrollTransportOptions) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig:     publicTLSConfig(opts),
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     publicEnrollIdleConnTimeout,
		MaxIdleConnsPerHost: 1,
		Proxy:               nil,
	}
	if opts.socksProxy != "" {
		proxyAddr, err := validatePublicSOCKSProxy(opts.socksProxy)
		if err != nil {
			return nil, err
		}
		// The router authenticates with the router proof (the internal
		// credentials never reach a listener that cannot prove itself) and
		// receives the host name, so DNS is resolved on the far side too.
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, _, err := vpnBridgeSOCKS5Connect(ctx, proxyAddr, addr, nil)
			return conn, err
		}
	} else {
		// Direct path: never pick up a system/env proxy.
		transport.DialContext = (&net.Dialer{}).DialContext
	}
	return &http.Client{Transport: transport}, nil
}

// publicEnrollPad returns random-length filler for the optional "pad" JSON
// field. The orchestrator decodes these bodies with encoding/json and ignores
// unknown fields, so the field only varies the request size.
func publicEnrollPad() string {
	n, err := rand.Int(rand.Reader, big.NewInt(publicEnrollPadMaxBytes+1))
	if err != nil {
		return ""
	}
	size := int(n.Int64())
	if size == 0 {
		return ""
	}
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return base64.RawStdEncoding.EncodeToString(raw)[:size]
}
