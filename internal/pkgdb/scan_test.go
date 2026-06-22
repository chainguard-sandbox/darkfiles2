package pkgdb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/darkfiles2/internal/image"
)

func hasAll(t *testing.T, got map[string]struct{}, want ...string) {
	t.Helper()
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("missing tracked path %q; got %v", w, keys(got))
		}
	}
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestScanAPK(t *testing.T) {
	db := "" +
		"C:Q1abc\n" +
		"P:curl\n" +
		"F:usr/bin\n" +
		"R:curl\n" +
		"R:curl-config\n" +
		"\n" +
		"P:rootpkg\n" +
		"F:\n" + // empty dir => root
		"R:init\n"
	fs := &image.ImageFS{
		FileContent: map[string][]byte{
			"/usr/lib/apk/db/installed": []byte(db),
		},
	}
	got, err := scanAPK(fs)
	if err != nil {
		t.Fatalf("scanAPK: %v", err)
	}
	hasAll(t, got, "/usr/bin/curl", "/usr/bin/curl-config", "/init")
	if len(got) != 3 {
		t.Errorf("got %d tracked paths, want 3: %v", len(got), keys(got))
	}
}

func TestScanAPKNoDB(t *testing.T) {
	got, err := scanAPK(&image.ImageFS{FileContent: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty set with no db, got %v", keys(got))
	}
}

func TestScanDpkg(t *testing.T) {
	status := "" +
		"Package: bash\n" +
		"Status: install ok installed\n" +
		"\n" +
		"Package: ghost\n" +
		"Status: deinstall ok config-files\n"
	fs := &image.ImageFS{
		FileContent: map[string][]byte{
			"/var/lib/dpkg/status": []byte(status),
			"/var/lib/dpkg/info/bash.list": []byte(
				"/\n/bin\n/bin/bash\n/usr/share/doc/bash/README\n"),
			// ghost is not installed -> its files must be ignored.
			"/var/lib/dpkg/info/ghost.list": []byte("/usr/bin/ghost\n"),
		},
	}
	got, err := scanDpkg(fs)
	if err != nil {
		t.Fatalf("scanDpkg: %v", err)
	}
	hasAll(t, got, "/bin", "/bin/bash", "/usr/share/doc/bash/README")
	if _, ok := got["/usr/bin/ghost"]; ok {
		t.Error("ghost package is not installed; its files should be excluded")
	}
	if _, ok := got["/"]; ok {
		t.Error("root path \"/\" should be skipped")
	}
}

func TestScanDpkgArchSuffix(t *testing.T) {
	// Package name in status has no arch; .list filename carries :amd64.
	status := "Package: zlib1g\nStatus: install ok installed\n"
	fs := &image.ImageFS{
		FileContent: map[string][]byte{
			"/var/lib/dpkg/status":                 []byte(status),
			"/var/lib/dpkg/info/zlib1g:amd64.list": []byte("/usr/lib/libz.so.1\n"),
		},
	}
	got, err := scanDpkg(fs)
	if err != nil {
		t.Fatal(err)
	}
	hasAll(t, got, "/usr/lib/libz.so.1")
}

func TestScanSBOM(t *testing.T) {
	spdx := `{
		"packages": [{"name": "mytool", "versionInfo": "1.0"}],
		"files": [
			{"fileName": "/usr/local/bin/mytool"},
			{"fileName": "./etc/mytool/config"},
			{"fileName": "relative/thing"}
		]
	}`
	fs := &image.ImageFS{
		FileContent: map[string][]byte{
			"/var/lib/db/sbom/mytool.spdx.json": []byte(spdx),
		},
	}
	got, err := scanSBOM(fs)
	if err != nil {
		t.Fatalf("scanSBOM: %v", err)
	}
	// Absolute kept; "./" and bare-relative normalized to absolute.
	hasAll(t, got, "/usr/local/bin/mytool", "/etc/mytool/config", "/relative/thing")
}

func TestScanSBOMMalformedSkipped(t *testing.T) {
	fs := &image.ImageFS{
		FileContent: map[string][]byte{
			"/var/lib/db/sbom/bad.spdx.json":  []byte("{not json"),
			"/var/lib/db/sbom/good.spdx.json": []byte(`{"files":[{"fileName":"/ok"}]}`),
		},
	}
	got, err := scanSBOM(fs)
	if err != nil {
		t.Fatalf("scanSBOM should not error on malformed input: %v", err)
	}
	hasAll(t, got, "/ok")
}

func TestScanRPMEmpty(t *testing.T) {
	got, err := scanRPM(&image.ImageFS{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("scanRPM is a stub; want empty set, got %v", keys(got))
	}
}

// wolfiWithSBOM builds a Wolfi image fixture carrying both an APK db and an
// apko SBOM, each tracking a distinct file, so tests can confirm which source
// a given mode consults.
func wolfiWithSBOM() *image.ImageFS {
	return &image.ImageFS{
		OsRelease: map[string]string{"ID": "wolfi"},
		FileContent: map[string][]byte{
			"/usr/lib/apk/db/installed":       []byte("P:base\nF:usr/bin\nR:sh\n"),
			"/var/lib/db/sbom/base.spdx.json": []byte(`{"files":[{"fileName":"/usr/local/extra"}]}`),
		},
	}
}

func TestTrackedFilesDefaultIgnoresSBOM(t *testing.T) {
	// Default mode uses only the package database; the SBOM-only file is ignored.
	tracked, distro, err := TrackedFiles(wolfiWithSBOM(), Options{})
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	if distro != "wolfi" {
		t.Errorf("distro = %q, want wolfi", distro)
	}
	hasAll(t, tracked, "/usr/bin/sh")
	if _, ok := tracked["/usr/local/extra"]; ok {
		t.Errorf("default mode tracked SBOM-only file /usr/local/extra; want it ignored")
	}
}

func TestTrackedFilesSBOMModeIgnoresPkgDB(t *testing.T) {
	// SBOM mode uses only the embedded SBOM; the APK-only file is ignored.
	tracked, distro, err := TrackedFiles(wolfiWithSBOM(), Options{SBOM: true})
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	if distro != "wolfi" {
		t.Errorf("distro = %q, want wolfi", distro)
	}
	hasAll(t, tracked, "/usr/local/extra")
	if _, ok := tracked["/usr/bin/sh"]; ok {
		t.Errorf("SBOM mode tracked APK-only file /usr/bin/sh; want it ignored")
	}
}

func TestTrackedFilesSBOMFile(t *testing.T) {
	// An external SBOM file takes precedence over in-image sources and implies
	// SBOM mode (no SBOM bool set).
	dir := t.TempDir()
	path := filepath.Join(dir, "ext.spdx.json")
	if err := os.WriteFile(path, []byte(`{"files":[{"fileName":"/opt/from-file"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	tracked, _, err := TrackedFiles(wolfiWithSBOM(), Options{SBOMFile: path})
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	hasAll(t, tracked, "/opt/from-file")
	for _, p := range []string{"/usr/bin/sh", "/usr/local/extra"} {
		if _, ok := tracked[p]; ok {
			t.Errorf("external SBOM file mode tracked in-image file %s; want it ignored", p)
		}
	}
}

func TestTrackedFilesSBOMFileMalformed(t *testing.T) {
	// Unlike embedded discovery, a bad external file is a hard error.
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.spdx.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := TrackedFiles(wolfiWithSBOM(), Options{SBOMFile: path}); err == nil {
		t.Errorf("TrackedFiles with malformed --sbom-file: want error, got nil")
	}
}
