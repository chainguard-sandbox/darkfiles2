// Package sbom fetches an image's SPDX SBOM — published by DHI (Docker Hardened
// Images) and similar builders as an in-toto attestation attached via the OCI
// referrers API — and extracts the file paths it records, so they can be
// cross-referenced against the dark-file set.
package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// predicateTypeAnnotation identifies an attestation's predicate; DHI sets it on
// each referrer manifest descriptor.
const predicateTypeAnnotation = "in-toto.io/predicate-type"

// spdxPredicateType is the in-toto predicate type for an SPDX document.
const spdxPredicateType = "https://spdx.dev/Document"

// maxSBOMFileSize bounds a local --sbom-file we read into memory before parsing.
// An SBOM may come from an untrusted source (a downloaded artifact, a CI output),
// and parsePaths buffers and json.Unmarshals the whole document, so an oversized
// file could otherwise consume unbounded memory. Real SPDX SBOMs are far smaller.
const maxSBOMFileSize = 512 << 20 // 512 MiB

// readCappedFile reads up to max bytes from path, erroring if the file is larger
// rather than buffering it whole.
func readCappedFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("SBOM file %s exceeds %d byte limit", path, max)
	}
	return data, nil
}

// FilePaths returns the set of absolute file paths recorded in the image's SPDX
// SBOM. When sbomFile is non-empty it parses that local file (an in-toto
// statement or a bare SPDX document); otherwise it fetches the SPDX attestation
// from the registry via the OCI referrers API.
func FilePaths(ref, sbomFile string) (map[string]struct{}, error) {
	var data []byte
	var err error
	if sbomFile != "" {
		if data, err = readCappedFile(sbomFile, maxSBOMFileSize); err != nil {
			return nil, err
		}
	} else {
		if data, err = fetchSPDX(ref); err != nil {
			return nil, err
		}
	}
	return parsePaths(data)
}

// fetchSPDX resolves the image to its host-platform manifest, queries the OCI
// referrers API for an SPDX attestation, and returns the raw in-toto statement.
func fetchSPDX(ref string) ([]byte, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parsing reference %q: %w", ref, err)
	}
	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}

	imgDigest, err := platformDigest(r, opts)
	if err != nil {
		return nil, err
	}

	idx, err := remote.Referrers(imgDigest, opts...)
	if err != nil {
		return nil, fmt.Errorf("listing referrers for %s: %w", imgDigest, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("reading referrers index: %w", err)
	}

	for _, m := range im.Manifests {
		if m.Annotations[predicateTypeAnnotation] != spdxPredicateType {
			continue
		}
		return readAttestation(r.Context().Digest(m.Digest.String()), opts)
	}
	return nil, fmt.Errorf("no SPDX SBOM attestation found for %s (predicate-type %s)", imgDigest, spdxPredicateType)
}

// platformDigest returns the digest of the manifest matching the host platform,
// resolving a multi-platform index when necessary.
func platformDigest(r name.Reference, opts []remote.Option) (name.Digest, error) {
	desc, err := remote.Get(r, opts...)
	if err != nil {
		return name.Digest{}, fmt.Errorf("fetching %s: %w", r, err)
	}
	if !desc.MediaType.IsIndex() {
		return r.Context().Digest(desc.Digest.String()), nil
	}

	idx, err := desc.ImageIndex()
	if err != nil {
		return name.Digest{}, fmt.Errorf("reading image index: %w", err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return name.Digest{}, fmt.Errorf("reading index manifest: %w", err)
	}
	// Container images are linux; match the host architecture (as crane does
	// when pulling the image filesystem).
	want := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	for _, m := range im.Manifests {
		if m.Platform != nil && m.Platform.Satisfies(want) {
			return r.Context().Digest(m.Digest.String()), nil
		}
	}
	return name.Digest{}, fmt.Errorf("no manifest for platform %s/%s in %s", want.OS, want.Architecture, r)
}

// readAttestation pulls a referrer manifest and returns its first layer — the
// in-toto statement blob.
func readAttestation(d name.Digest, opts []remote.Option) ([]byte, error) {
	img, err := remote.Image(d, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation %s: %w", d, err)
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("reading attestation layers: %w", err)
	}
	if len(layers) == 0 {
		return nil, fmt.Errorf("attestation %s has no layers", d)
	}
	rc, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("opening attestation layer: %w", err)
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// parsePaths extracts file paths from data, which may be an in-toto statement
// wrapping an SPDX document or a bare SPDX document.
func parsePaths(data []byte) (map[string]struct{}, error) {
	doc := data
	var env struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(data, &env); err == nil && len(env.Predicate) > 0 {
		doc = env.Predicate
	}

	var spdx struct {
		Files []struct {
			FileName string `json:"fileName"`
		} `json:"files"`
	}
	if err := json.Unmarshal(doc, &spdx); err != nil {
		return nil, fmt.Errorf("parsing SPDX document: %w", err)
	}

	out := make(map[string]struct{}, len(spdx.Files))
	for _, f := range spdx.Files {
		if f.FileName == "" {
			continue
		}
		out[normalize(f.FileName)] = struct{}{}
	}
	return out, nil
}

// normalize turns an SPDX fileName (recorded relative, e.g. "usr/bin/vault" or
// "./usr/bin/vault") into the absolute, clean form used by the image filesystem.
func normalize(p string) string {
	p = strings.TrimPrefix(p, "./")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return filepath.Clean(p)
}
