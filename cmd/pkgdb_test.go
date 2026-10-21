package cmd

import (
	"strings"
	"testing"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

// TestAnalyzeImageAPKLongRecord reproduces images (e.g. large Wolfi images)
// whose APK database holds a record longer than 64 KiB: the package scan must
// still succeed and track the packaged files rather than reporting 100% dark.
func TestAnalyzeImageAPKLongRecord(t *testing.T) {
	db := "P:big\n" +
		"D:" + strings.Repeat("so:libfoo.so.1 ", 10000) + "\n" +
		"F:usr/bin\n" +
		"R:big\n"
	tarPath := writeImageTar(t, []tarEntry{
		{name: "etc/os-release", mode: 0o644, body: []byte("ID=wolfi\n")},
		{name: "usr/lib/apk/db/installed", mode: 0o644, body: []byte(db)},
		{name: "usr/bin/big", mode: 0o755, body: []byte("#!/bin/sh\n")},
		{name: "usr/bin/stray", mode: 0o755, body: []byte("#!/bin/sh\n")},
	})
	fs, err := image.LoadFromTar(tarPath)
	if err != nil {
		t.Fatalf("LoadFromTar: %v", err)
	}
	r, _, err := analyzeImage(tarPath, fs)
	if err != nil {
		t.Fatalf("analyzeImage: %v", err)
	}
	if r.TrackedFiles == 0 {
		t.Fatalf("TrackedFiles = 0; package db scan silently failed")
	}
	for _, f := range r.DarkFiles {
		if f.Path == "/usr/bin/big" {
			t.Errorf("/usr/bin/big is owned by a package but reported dark")
		}
	}
}

// TestRunScanFailsOnUnreadablePkgDB checks that a package database which is
// present but yields nothing aborts the scan instead of reporting 100% dark.
func TestRunScanFailsOnUnreadablePkgDB(t *testing.T) {
	tarPath := writeImageTar(t, []tarEntry{
		{name: "etc/os-release", mode: 0o644, body: []byte("ID=debian\n")},
		{name: "var/lib/dpkg/status", mode: 0o644, body: []byte("Package: bash\nStatus: install ok installed\n")},
		{name: "bin/bash", mode: 0o755, body: []byte("#!/bin/sh\n")},
	})
	saved := scanFlags
	t.Cleanup(func() { scanFlags = saved })
	scanFlags.set = "unknown"
	scanFlags.tar = tarPath

	err := runScan(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "package db") {
		t.Fatalf("runScan() = %v, want package db scan error", err)
	}
}
