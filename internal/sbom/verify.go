package sbom

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ErrUnverified means an SBOM attestation could not be cryptographically tied to
// a trusted key. Callers should refuse to trust the SBOM (skip reclassifying
// files) rather than abort the whole scan.
var ErrUnverified = errors.New("SBOM attestation signature could not be verified")

// dhiKeyPEM is Docker's published Docker Hardened Images signing key, embedded
// for offline, reproducible verification. It is used consistently across all DHI
// images. Override with --sbom-key. Source:
// https://registry.scout.docker.com/keyring/dhi/latest.pub
//
//go:embed keys/dhi.pub
var dhiKeyPEM []byte

const (
	// cosignSigArtifactType marks a referrer that is a cosign signature.
	cosignSigArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"
	// cosignSigAnnotation holds the base64 signature on the simplesigning layer.
	cosignSigAnnotation = "dev.cosignproject.cosign/signature"
	// maxPayloadSize caps the simplesigning payload we read; real ones are ~500 B.
	maxPayloadSize = 1 << 20
)

// parseECDSAKey parses a PEM-encoded PKIX ECDSA public key.
func parseECDSAKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want ECDSA", pub)
	}
	return key, nil
}

// verifyAttestation returns nil iff some cosign signature referrer of att carries
// a valid simplesigning signature, made by key, that binds to att's own digest.
//
// The Rekor transparency log is intentionally ignored: DHI does not always
// publish entries (doing so would leak customer namespaces), which matches
// `cosign verify --insecure-ignore-tlog=true` from Docker's documentation.
func verifyAttestation(att name.Digest, key *ecdsa.PublicKey, opts []remote.Option) error {
	idx, err := remote.Referrers(att, opts...)
	if err != nil {
		return fmt.Errorf("%w: listing signature referrers: %v", ErrUnverified, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return fmt.Errorf("%w: reading signature referrers: %v", ErrUnverified, err)
	}
	var lastErr error
	for _, m := range im.Manifests {
		if m.ArtifactType != cosignSigArtifactType {
			continue
		}
		if err := verifyCosignSig(att.Context().Digest(m.Digest.String()), att.DigestStr(), key, opts); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("%w: %v", ErrUnverified, lastErr)
	}
	return fmt.Errorf("%w: no cosign signature found for %s", ErrUnverified, att)
}

// verifyCosignSig checks a single cosign signature manifest: its simplesigning
// payload must be signed by key and bind docker-manifest-digest to wantDigest.
func verifyCosignSig(sig name.Digest, wantDigest string, key *ecdsa.PublicKey, opts []remote.Option) error {
	desc, err := remote.Get(sig, opts...)
	if err != nil {
		return err
	}
	var mf struct {
		Layers []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(desc.Manifest, &mf); err != nil {
		return err
	}
	if len(mf.Layers) == 0 {
		return errors.New("signature manifest has no layers")
	}
	layer := mf.Layers[0]

	sigBytes, err := base64.StdEncoding.DecodeString(layer.Annotations[cosignSigAnnotation])
	if err != nil {
		return fmt.Errorf("decoding signature annotation: %w", err)
	}

	payload, err := readPayload(sig.Context().Digest(layer.Digest), opts)
	if err != nil {
		return err
	}

	var ss struct {
		Critical struct {
			Image struct {
				Digest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
	}
	if err := json.Unmarshal(payload, &ss); err != nil {
		return fmt.Errorf("parsing simplesigning payload: %w", err)
	}
	// Bind the signature to the attestation we actually consumed, so a valid
	// signature over some *other* artifact cannot be replayed onto this one.
	if ss.Critical.Image.Digest != wantDigest {
		return fmt.Errorf("signature binds %s, want %s", ss.Critical.Image.Digest, wantDigest)
	}

	h := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(key, h[:], sigBytes) {
		return errors.New("signature does not verify against key")
	}
	return nil
}

// readPayload fetches a (small, uncompressed) signature payload blob.
func readPayload(blob name.Digest, opts []remote.Option) ([]byte, error) {
	l, err := remote.Layer(blob, opts...)
	if err != nil {
		return nil, err
	}
	rc, err := l.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, maxPayloadSize))
}
