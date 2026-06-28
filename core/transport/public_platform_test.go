package transport

import (
	"errors"
	"testing"
)

func TestPublicEnrollAWGKeyPairReplaysStoredKeys(t *testing.T) {
	called := false
	privateKey, publicKey, err := publicEnrollAWGKeyPair(
		publicDeviceEnrollAPIRequest{
			AWGPrivateKey: "stored-private",
			AWGPublicKey:  "stored-public",
		},
		func() (string, string, error) {
			called = true
			return "", "", nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("generator called despite stored awg keypair")
	}
	if privateKey != "stored-private" || publicKey != "stored-public" {
		t.Fatalf("unexpected stored keypair: private=%q public=%q", privateKey, publicKey)
	}
}

func TestPublicEnrollAWGKeyPairGeneratesFallbackWhenMissing(t *testing.T) {
	privateKey, publicKey, err := publicEnrollAWGKeyPair(
		publicDeviceEnrollAPIRequest{},
		func() (string, string, error) {
			return "generated-private", "generated-public", nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if privateKey != "generated-private" || publicKey != "generated-public" {
		t.Fatalf("unexpected generated keypair: private=%q public=%q", privateKey, publicKey)
	}
}

func TestPublicEnrollAWGKeyPairRejectsPartialStoredKeypair(t *testing.T) {
	if _, _, err := publicEnrollAWGKeyPair(
		publicDeviceEnrollAPIRequest{AWGPublicKey: "stored-public"},
		func() (string, string, error) {
			return "generated-private", "generated-public", nil
		},
	); err == nil {
		t.Fatal("partial stored keypair accepted")
	}
	if _, _, err := publicEnrollAWGKeyPair(
		publicDeviceEnrollAPIRequest{},
		func() (string, string, error) {
			return "", "", errors.New("boom")
		},
	); err == nil {
		t.Fatal("generator error ignored")
	}
}
