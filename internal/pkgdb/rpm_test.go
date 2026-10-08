package pkgdb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

// loadFixture reads the trimmed SQLite rpmdb fixture. It is a real rpm database
// (SQLite format, the default since rpm 4.16 / RHEL 9 / Fedora 33) containing a
// handful of small packages extracted from rockylinux:9-minimal, so it
// exercises the full go-rpmdb parse path while staying tiny.
func loadFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rpmdb.sqlite"))
	if err != nil {
		t.Fatalf("reading rpmdb fixture: %v", err)
	}
	return data
}

func TestScanRPM(t *testing.T) {
	fs := &image.ImageFS{
		FileContent: map[string][]byte{
			"/var/lib/rpm/rpmdb.sqlite": loadFixture(t),
		},
	}

	tracked, err := scanRPM(fs)
	if err != nil {
		t.Fatalf("scanRPM: %v", err)
	}
	if len(tracked) == 0 {
		t.Fatal("scanRPM returned no tracked files")
	}

	// Paths known to be owned by packages in the fixture.
	want := []string{
		"/usr/lib64/libbz2.so.1.0.8",
		"/usr/lib64/liblz4.so.1.9.3",
		"/usr/lib64/libnghttp2.so.14.20.1",
		"/usr/share/publicsuffix/public_suffix_list.dafsa",
	}
	for _, p := range want {
		if _, ok := tracked[p]; !ok {
			t.Errorf("expected %q to be tracked", p)
		}
	}

	// Every tracked path must be absolute.
	for p := range tracked {
		if !filepath.IsAbs(p) {
			t.Errorf("tracked path %q is not absolute", p)
		}
	}
}

// TestScanRPMViaTrackedFiles checks the full dispatch path: a Fedora-style
// os-release routes through detect() to scanRPM, and the database located at
// the newer /usr/lib/sysimage/rpm path is found.
func TestScanRPMViaTrackedFiles(t *testing.T) {
	fs := &image.ImageFS{
		OsRelease: map[string]string{"ID": "fedora"},
		FileContent: map[string][]byte{
			"/usr/lib/sysimage/rpm/rpmdb.sqlite": loadFixture(t),
		},
	}

	tracked, distro, err := TrackedFiles(fs)
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	if distro != "rpm" {
		t.Errorf("distro = %q, want rpm", distro)
	}
	if _, ok := tracked["/usr/lib64/libbz2.so.1.0.8"]; !ok {
		t.Error("expected libbz2 to be tracked via sysimage rpmdb path")
	}
}

func TestScanRPMNoDatabase(t *testing.T) {
	fs := &image.ImageFS{FileContent: map[string][]byte{}}
	tracked, err := scanRPM(fs)
	if err != nil {
		t.Fatalf("scanRPM with no database should not error: %v", err)
	}
	if len(tracked) != 0 {
		t.Errorf("expected empty set, got %d entries", len(tracked))
	}
}

func TestScanRPMEmptyFileIgnored(t *testing.T) {
	// A zero-length database file (e.g. a placeholder) must be treated as "no
	// database", not passed to the parser.
	fs := &image.ImageFS{FileContent: map[string][]byte{
		"/var/lib/rpm/rpmdb.sqlite": {},
	}}
	tracked, err := scanRPM(fs)
	if err != nil {
		t.Fatalf("scanRPM: %v", err)
	}
	if len(tracked) != 0 {
		t.Errorf("expected empty set, got %d entries", len(tracked))
	}
}

func TestScanRPMMalformedDatabase(t *testing.T) {
	// Non-rpm bytes under a database path must surface as an error rather than
	// silently returning nothing.
	fs := &image.ImageFS{FileContent: map[string][]byte{
		"/var/lib/rpm/Packages": []byte("this is not an rpm database"),
	}}
	if _, err := scanRPM(fs); err == nil {
		t.Error("expected an error for a malformed rpm database, got nil")
	}
}
