package cmd

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// pushWithSBOM pushes a random image to tag and attaches an SPDX attestation,
// via the OCI referrers API, whose only file entry is sbomPath.
func pushWithSBOM(t *testing.T, tag name.Tag, sbomPath string) {
	t.Helper()
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	subject, err := partial.Descriptor(img)
	if err != nil {
		t.Fatal(err)
	}

	stmt, err := json.Marshal(map[string]any{
		"predicateType": "https://spdx.dev/Document",
		"predicate": map[string]any{
			"files": []map[string]string{{"fileName": sbomPath}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	att, err := mutate.Append(mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		mutate.Addendum{Layer: static.NewLayer(stmt, "application/vnd.in-toto+json")})
	if err != nil {
		t.Fatal(err)
	}
	att = mutate.Subject(mutate.Annotations(att, map[string]string{
		"in-toto.io/predicate-type": "https://spdx.dev/Document",
	}).(v1.Image), *subject).(v1.Image)
	d, err := att.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(tag.Context().Digest(d.String()), att); err != nil {
		t.Fatal(err)
	}
}

// TestLoadSBOMPinnedToScannedDigest moves the tag to a different image after the
// filesystem is loaded and checks loadSBOM still returns the SBOM of the image
// that was scanned, not the one the tag now points at.
func TestLoadSBOMPinnedToScannedDigest(t *testing.T) {
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	defer srv.Close()
	tag, err := name.NewTag(strings.TrimPrefix(srv.URL, "http://") + "/test:latest")
	if err != nil {
		t.Fatal(err)
	}

	pushWithSBOM(t, tag, "usr/bin/scanned")
	fs, err := image.Load(tag.String())
	if err != nil {
		t.Fatal(err)
	}
	pushWithSBOM(t, tag, "usr/bin/retagged")

	got, err := loadSBOM([]string{tag.String()}, fs, "", "", "", true)
	if err != nil {
		t.Fatalf("loadSBOM: %v", err)
	}
	if _, ok := got["/usr/bin/scanned"]; !ok || len(got) != 1 {
		t.Errorf("loadSBOM = %v, want only /usr/bin/scanned from the scanned image", got)
	}
}
