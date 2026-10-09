package cmd

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestValidateFlags(t *testing.T) {
	tests := []struct {
		name    string
		set     func()
		wantErr string // "" means valid
	}{
		{"defaults", func() {}, ""},
		{"detect-go", func() { scanFlags.detectGo = true }, ""},
		{"set go with detect-go", func() { scanFlags.set = "go"; scanFlags.detectGo = true }, ""},
		{"set go without detect-go", func() { scanFlags.set = "go" }, "--set go requires --detect-go"},
		{"set in-sbom without sbom", func() { scanFlags.set = "in-sbom" }, "requires --sbom"},
		{"set in-sbom with sbom-file", func() { scanFlags.set = "in-sbom"; scanFlags.sbomFile = "x.json" }, ""},
		{"detailed and paths", func() { scanFlags.detailed = true; scanFlags.paths = true }, "mutually exclusive"},
		{"bad set", func() { scanFlags.set = "bogus" }, "invalid --set"},
	}
	saved := scanFlags
	t.Cleanup(func() { scanFlags = saved })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanFlags = saved
			scanFlags.set = "unknown"
			tt.set()
			err := validateFlags()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("validateFlags() = %v, want nil", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("validateFlags() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestApplyGoBinariesFromImage runs Go detection end to end over a real image
// tarball: content is re-read from the layers and only files with Go build
// info (and symlinks to them) leave the dark set.
func TestApplyGoBinariesFromImage(t *testing.T) {
	// The running test binary is a real Go binary with build info.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	goBin, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	notGo := append([]byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00"), make([]byte, 64)...)

	tarPath := writeImageTar(t, []tarEntry{
		{name: "app/server", mode: 0o755, body: goBin},
		{name: "usr/bin/server", link: "/app/server"},
		{name: "app/other", mode: 0o755, body: notGo},
		{name: "app/run.sh", mode: 0o755, body: []byte("#!/bin/sh\n")},
	})
	fs, err := image.LoadFromTar(tarPath)
	if err != nil {
		t.Fatalf("LoadFromTar: %v", err)
	}
	r, _, _ := analyzeImage(tarPath, fs) // no package db: everything starts dark

	if err := applyGoBinaries(r, fs); err != nil {
		t.Fatalf("applyGoBinaries: %v", err)
	}
	if !r.GoChecked {
		t.Error("GoChecked should be true")
	}
	if got, want := paths(r.GoFiles), []string{"/app/server", "/usr/bin/server"}; !equalUnordered(got, want) {
		t.Errorf("GoFiles = %v, want %v", got, want)
	}
	if got, want := paths(r.DarkFiles), []string{"/app/other", "/app/run.sh"}; !equalUnordered(got, want) {
		t.Errorf("DarkFiles = %v, want %v", got, want)
	}
}

// TestApplyGoBinariesSBOMTargetSymlink covers a Go binary documented by the
// SBOM with an undocumented symlink to it: the binary stays in the SBOM bucket
// and the symlink is accounted for as a Go binary instead of staying dark.
func TestApplyGoBinariesSBOMTargetSymlink(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	goBin, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	tarPath := writeImageTar(t, []tarEntry{
		{name: "app/server", mode: 0o755, body: goBin},
		{name: "usr/bin/server", link: "/app/server"},
		{name: "app/run.sh", mode: 0o755, body: []byte("#!/bin/sh\n")},
	})
	fs, err := image.LoadFromTar(tarPath)
	if err != nil {
		t.Fatalf("LoadFromTar: %v", err)
	}
	r, _, _ := analyzeImage(tarPath, fs)
	r.ApplySBOM(map[string]struct{}{"/app/server": {}}) // as runScan does, before Go detection

	if err := applyGoBinaries(r, fs); err != nil {
		t.Fatalf("applyGoBinaries: %v", err)
	}
	if got, want := paths(r.SBOMFiles), []string{"/app/server"}; !equalUnordered(got, want) {
		t.Errorf("SBOMFiles = %v, want %v", got, want)
	}
	if got, want := paths(r.GoFiles), []string{"/usr/bin/server"}; !equalUnordered(got, want) {
		t.Errorf("GoFiles = %v, want %v", got, want)
	}
	if got, want := paths(r.DarkFiles), []string{"/app/run.sh"}; !equalUnordered(got, want) {
		t.Errorf("DarkFiles = %v, want %v", got, want)
	}
}

type tarEntry struct {
	name string
	mode int64
	body []byte
	link string // symlink target; body is ignored when set
}

// writeImageTar builds a single-layer image from entries and saves it as a
// docker-style tarball, returning its path.
func writeImageTar(t *testing.T, entries []tarEntry) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: e.mode, Typeflag: tar.TypeReg, Size: int64(len(e.body))}
		if e.link != "" {
			hdr = &tar.Header{Name: e.name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: e.link}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.link == "" {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	layerBytes := buf.Bytes()
	layer, err := tarball.LayerFromReader(bytes.NewReader(layerBytes))
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag("darkfiles.test/gobin:latest")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(path, tag, img); err != nil {
		t.Fatal(err)
	}
	return path
}
