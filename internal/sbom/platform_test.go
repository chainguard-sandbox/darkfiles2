package sbom

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// TestPlatformDigestMatchesPull pushes a multi-platform index whose arm64 entry
// is listed first and checks that platformDigest picks the same manifest that
// crane.Pull (used to scan the filesystem) does, regardless of host arch.
func TestPlatformDigestMatchesPull(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	var idx v1.ImageIndex = empty.Index
	for _, arch := range []string{"arm64", "amd64"} {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        img,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}},
		})
	}
	ref, err := name.ParseReference(host + "/test:multi")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}

	pulled, err := crane.Pull(ref.String())
	if err != nil {
		t.Fatal(err)
	}
	want, err := pulled.Digest()
	if err != nil {
		t.Fatal(err)
	}

	got, err := platformDigest(ref, nil)
	if err != nil {
		t.Fatalf("platformDigest: %v", err)
	}
	if got.DigestStr() != want.String() {
		t.Errorf("platformDigest = %s, want pulled manifest %s", got.DigestStr(), want)
	}

	// A digest reference to a platform manifest is used as-is.
	pinned := ref.Context().Digest(want.String())
	got, err = platformDigest(pinned, nil)
	if err != nil {
		t.Fatalf("platformDigest(pinned): %v", err)
	}
	if got.String() != pinned.String() {
		t.Errorf("platformDigest(pinned) = %s, want %s", got, pinned)
	}
}
