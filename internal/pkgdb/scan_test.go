package pkgdb

import (
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

func TestScanRPMEmpty(t *testing.T) {
	got, err := scanRPM(&image.ImageFS{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("scanRPM is a stub; want empty set, got %v", keys(got))
	}
}

func TestTrackedFilesPkgDB(t *testing.T) {
	// TrackedFiles uses the package database and reports the detected distro.
	fs := &image.ImageFS{
		OsRelease: map[string]string{"ID": "wolfi"},
		FileContent: map[string][]byte{
			"/usr/lib/apk/db/installed": []byte("P:base\nF:usr/bin\nR:sh\n"),
		},
	}
	tracked, distro, err := TrackedFiles(fs)
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	if distro != "wolfi" {
		t.Errorf("distro = %q, want wolfi", distro)
	}
	hasAll(t, tracked, "/usr/bin/sh")
}
