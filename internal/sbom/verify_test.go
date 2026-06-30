package sbom

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// The embedded DHI key must parse as ECDSA — guards against a corrupted/rotated
// keys/dhi.pub landing in the binary.
func TestEmbeddedDHIKeyParses(t *testing.T) {
	if _, err := parseECDSAKey(dhiKeyPEM); err != nil {
		t.Fatalf("embedded DHI key does not parse: %v", err)
	}
}

func TestParseECDSAKeyRejectsJunk(t *testing.T) {
	if _, err := parseECDSAKey([]byte("not a key")); err == nil {
		t.Error("expected error parsing non-PEM input")
	}
	// A valid PEM block that isn't an ECDSA key should also be rejected.
	rsaish := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")})
	if _, err := parseECDSAKey(rsaish); err == nil {
		t.Error("expected error parsing non-ECDSA PEM")
	}
}

// makePayload builds a cosign simplesigning payload binding the given digest.
func makePayload(digest string) []byte {
	type img struct {
		Digest string `json:"docker-manifest-digest"`
	}
	type crit struct {
		Image img    `json:"image"`
		Type  string `json:"type"`
	}
	b, _ := json.Marshal(struct {
		Critical crit `json:"critical"`
	}{Critical: crit{Image: img{Digest: digest}, Type: "cosign container image signature"}})
	return b
}

func sign(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// verifyPayloadSig mirrors verifyCosignSig's trust checks (binding + signature)
// without the registry I/O, so the security-critical logic is tested hermetically.
func verifyPayloadSig(payload, sig []byte, wantDigest string, key *ecdsa.PublicKey) error {
	var ss struct {
		Critical struct {
			Image struct {
				Digest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
	}
	if err := json.Unmarshal(payload, &ss); err != nil {
		return err
	}
	if ss.Critical.Image.Digest != wantDigest {
		return errBinding
	}
	h := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(key, h[:], sig) {
		return errSig
	}
	return nil
}

var (
	errBinding = &verifyErr{"binding mismatch"}
	errSig     = &verifyErr{"bad signature"}
)

type verifyErr struct{ s string }

func (e *verifyErr) Error() string { return e.s }

func TestVerifyPayloadSig(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:aaaa"
	payload := makePayload(want)
	sig := sign(t, key, payload)

	t.Run("valid", func(t *testing.T) {
		if err := verifyPayloadSig(payload, sig, want, &key.PublicKey); err != nil {
			t.Errorf("valid signature rejected: %v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		if err := verifyPayloadSig(payload, sig, want, &other.PublicKey); err != errSig {
			t.Errorf("got %v, want errSig", err)
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		bad := append([]byte{}, payload...)
		bad[5] ^= 0xff
		if err := verifyPayloadSig(bad, sig, want, &key.PublicKey); err == nil {
			t.Error("tampered payload accepted")
		}
	})
	t.Run("wrong bound digest", func(t *testing.T) {
		// A signature legitimately made over a *different* artifact must not be
		// accepted for this attestation (replay protection).
		otherPayload := makePayload("sha256:bbbb")
		otherSig := sign(t, key, otherPayload)
		if err := verifyPayloadSig(otherPayload, otherSig, want, &key.PublicKey); err != errBinding {
			t.Errorf("got %v, want errBinding", err)
		}
	})
}

// TestRoundTripPKIX confirms a generated key survives PEM encode -> parseECDSAKey,
// the same path the embedded/override key takes.
func TestRoundTripPKIX(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	got, err := parseECDSAKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(&key.PublicKey) {
		t.Error("round-tripped key does not match original")
	}
}
