package sbom

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// dhiTestImage is a public Docker Hardened Image used to validate end-to-end
// signature verification against a real, signed SPDX attestation.
const dhiTestImage = "dhi.io/redis:8"

// resolveSPDXAttestation finds the SPDX attestation digest for ref.
func resolveSPDXAttestation(t *testing.T, ref string, opts []remote.Option) name.Digest {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	imgDigest, err := platformDigest(r, opts)
	if err != nil {
		t.Skipf("cannot reach %s (%v); skipping", ref, err)
	}
	idx, err := remote.Referrers(imgDigest, opts...)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range im.Manifests {
		if m.Annotations[predicateTypeAnnotation] == spdxPredicateType {
			return r.Context().Digest(m.Digest.String())
		}
	}
	t.Fatalf("no SPDX attestation on %s", ref)
	return name.Digest{}
}

// TestVerifyAttestationDHI verifies the live DHI SPDX attestation against the
// embedded key, and confirms an unrelated key is rejected. Network-dependent;
// skipped under -short.
func TestVerifyAttestationDHI(t *testing.T) {
	if testing.Short() {
		t.Skip("network test; skipped in -short")
	}
	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	att := resolveSPDXAttestation(t, dhiTestImage, opts)

	key, err := parseECDSAKey(dhiKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAttestation(att, key, opts); err != nil {
		t.Errorf("DHI attestation failed to verify against embedded key: %v", err)
	}

	// A different key must be rejected as unverified.
	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifyAttestation(att, &wrong.PublicKey, opts); !errors.Is(err, ErrUnverified) {
		t.Errorf("wrong key: got %v, want ErrUnverified", err)
	}
}

// TestFilePathsDHIVerified exercises the full FilePaths path against the live
// image: default (verified) succeeds and returns file paths. Skipped under -short.
func TestFilePathsDHIVerified(t *testing.T) {
	if testing.Short() {
		t.Skip("network test; skipped in -short")
	}
	paths, err := FilePaths(dhiTestImage, Options{})
	if errors.Is(err, ErrUnverified) {
		t.Fatalf("verified fetch unexpectedly failed: %v", err)
	}
	if err != nil {
		t.Skipf("cannot reach %s (%v); skipping", dhiTestImage, err)
	}
	if len(paths) == 0 {
		t.Error("expected file paths from verified DHI SBOM")
	}

	// A bogus override key should make the verified path fail closed.
	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&wrong.PublicKey)
	wrongPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := FilePaths(dhiTestImage, Options{KeyPEM: wrongPEM}); !errors.Is(err, ErrUnverified) {
		t.Errorf("wrong key: got %v, want ErrUnverified", err)
	}
}
