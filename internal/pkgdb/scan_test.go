package pkgdb

import (
	"errors"
	"strings"
	"testing"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
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

func TestScanDpkgHalfInstalled(t *testing.T) {
	// Packages in "half-installed" or "half-configured" states must NOT be
	// treated as fully installed; only "install ok installed" qualifies.
	status := "" +
		"Package: broken\n" +
		"Status: install ok half-installed\n" +
		"\n" +
		"Package: partial\n" +
		"Status: install ok half-configured\n" +
		"\n" +
		"Package: good\n" +
		"Status: install ok installed\n"
	fs := &image.ImageFS{
		FileContent: map[string][]byte{
			"/var/lib/dpkg/status":            []byte(status),
			"/var/lib/dpkg/info/broken.list":  []byte("/usr/bin/broken\n"),
			"/var/lib/dpkg/info/partial.list": []byte("/usr/bin/partial\n"),
			"/var/lib/dpkg/info/good.list":    []byte("/usr/bin/good\n"),
		},
	}
	got, err := scanDpkg(fs)
	if err != nil {
		t.Fatalf("scanDpkg: %v", err)
	}
	hasAll(t, got, "/usr/bin/good")
	if _, ok := got["/usr/bin/broken"]; ok {
		t.Error("half-installed package files should not be tracked")
	}
	if _, ok := got["/usr/bin/partial"]; ok {
		t.Error("half-configured package files should not be tracked")
	}
}

func TestScanRPMEmpty(t *testing.T) {
	got, err := scanRPM(&image.ImageFS{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("no rpm database present; want empty set, got %v", keys(got))
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

func TestScanAPKLongLine(t *testing.T) {
	// A single record longer than bufio.Scanner's default 64 KiB token limit
	// (real-world: a huge D:/p: dependency line) must not abort the scan.
	long := "D:" + strings.Repeat("so:libfoo.so.1 ", 10000) // ~150 KiB
	db := "" +
		"P:big\n" +
		long + "\n" +
		"F:usr/bin\n" +
		"R:big\n" +
		"\n" +
		"P:after\n" +
		"F:usr/lib\n" +
		"R:libafter.so\n"
	fs := &image.ImageFS{
		FileContent: map[string][]byte{
			"/usr/lib/apk/db/installed": []byte(db),
		},
	}
	got, err := scanAPK(fs)
	if err != nil {
		t.Fatalf("scanAPK: %v", err)
	}
	hasAll(t, got, "/usr/bin/big", "/usr/lib/libafter.so")
}

func TestScanDpkgStatusD(t *testing.T) {
	// Distroless-style layout: no /var/lib/dpkg/status and no info/*.list.
	// Each package has a control stanza at status.d/<pkg> and its file list
	// (relative paths, md5sum format) at status.d/<pkg>.md5sums.
	fs := &image.ImageFS{
		FileContent: map[string][]byte{
			"/var/lib/dpkg/status.d/libc6": []byte(
				"Package: libc6\nVersion: 2.36-9\nArchitecture: amd64\n"),
			"/var/lib/dpkg/status.d/libc6.md5sums": []byte(
				"108877c29ef6a482337ddc42ea8b0985  lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\n" +
					"d6536c875ddb48f13c5229718bd8094a  usr/share/doc/libc6/copy right\n"),
			"/var/lib/dpkg/status.d/tzdata": []byte(
				"Package: tzdata\nVersion: 2024a\nArchitecture: all\n"),
			"/var/lib/dpkg/status.d/tzdata.md5sums": []byte(
				"0123456789abcdef0123456789abcdef  usr/share/zoneinfo/UTC\n"),
		},
	}
	got, err := scanDpkg(fs)
	if err != nil {
		t.Fatalf("scanDpkg: %v", err)
	}
	hasAll(t, got,
		"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
		"/usr/share/doc/libc6/copy right",
		"/usr/share/zoneinfo/UTC",
	)
	if len(got) != 3 {
		t.Errorf("got %d tracked paths, want 3: %v", len(got), keys(got))
	}
}

func TestTrackedFilesEmptyDBIsError(t *testing.T) {
	// A package database that is present but yields zero tracked files means
	// the scan failed; reporting the image as 100% dark would be wrong.
	tests := []struct {
		name string
		fs   *image.ImageFS
	}{
		{"apk without files", &image.ImageFS{
			OsRelease:   map[string]string{"ID": "wolfi"},
			FileContent: map[string][]byte{"/usr/lib/apk/db/installed": []byte("P:base\nV:1\n")},
		}},
		{"dpkg status without file lists", &image.ImageFS{
			OsRelease: map[string]string{"ID": "debian"},
			FileContent: map[string][]byte{
				"/var/lib/dpkg/status": []byte("Package: bash\nStatus: install ok installed\n"),
			},
		}},
		{"dpkg status.d without md5sums", &image.ImageFS{
			OsRelease: map[string]string{"ID": "debian"},
			FileContent: map[string][]byte{
				"/var/lib/dpkg/status.d/libc6": []byte("Package: libc6\n"),
			},
		}},
		{"unknown distro with apk db", &image.ImageFS{
			OsRelease:   map[string]string{},
			FileContent: map[string][]byte{"/lib/apk/db/installed": []byte("P:base\n")},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := TrackedFiles(tt.fs)
			if !errors.Is(err, ErrNoTrackedFiles) {
				t.Errorf("TrackedFiles() error = %v, want ErrNoTrackedFiles", err)
			}
		})
	}
}

func TestTrackedFilesNoDBIsNotError(t *testing.T) {
	// Images with no package database at all (scratch, static) are legitimately
	// fully untracked.
	tracked, _, err := TrackedFiles(&image.ImageFS{
		OsRelease:   map[string]string{"ID": "wolfi"},
		FileContent: map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	if len(tracked) != 0 {
		t.Errorf("want empty tracked set, got %v", keys(tracked))
	}
}
