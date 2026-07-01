package image

import (
	"archive/tar"
	"bytes"
	"testing"
)

// tarEntry describes a single file to write into a synthetic layer tar.
type tarEntry struct {
	name     string
	typeflag byte
	mode     int64
	linkname string
	body     string
}

// buildTar serializes entries into an uncompressed tar stream.
func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		flag := e.typeflag
		if flag == 0 {
			flag = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: flag,
			Mode:     e.mode,
			Linkname: e.linkname,
			Size:     int64(len(e.body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", e.name, err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatalf("Write(%q): %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	return buf.Bytes()
}

// newScanState returns a fresh fs and the overlay maps scanLayerTar mutates.
func newScanState() (*ImageFS, map[string]int, map[string]File) {
	fs := &ImageFS{
		OsRelease:   map[string]string{},
		FileContent: map[string][]byte{},
		Symlinks:    map[string]string{},
	}
	return fs, map[string]int{}, map[string]File{}
}

func TestScanLayerTarBasic(t *testing.T) {
	fs, origin, info := newScanState()
	layer := buildTar(t, []tarEntry{
		{name: "etc/os-release", body: "ID=alpine\nVERSION_ID=3.19\n"},
		{name: "usr/bin/", typeflag: tar.TypeDir},
		{name: "usr/bin/curl", mode: 0o755, body: "ELF..."},
		{name: "usr/lib/apk/db/installed", body: "C:Q1\nP:curl\nF:usr/bin\nR:curl\n"},
		{name: "bin", typeflag: tar.TypeSymlink, linkname: "usr/bin"},
	})

	if err := scanLayerTar(bytes.NewReader(layer), 0, fs, origin, info); err != nil {
		t.Fatalf("scanLayerTar: %v", err)
	}

	// os-release parsed.
	if fs.OsRelease["ID"] != "alpine" {
		t.Errorf("OsRelease[ID] = %q, want alpine", fs.OsRelease["ID"])
	}
	// Package DB content captured, not added as a regular file.
	if _, ok := fs.FileContent["/usr/lib/apk/db/installed"]; !ok {
		t.Error("apk db content not captured in FileContent")
	}
	if _, ok := info["/usr/lib/apk/db/installed"]; ok {
		t.Error("apk db should not be tracked as a regular file")
	}
	// Directory entries are not files.
	if _, ok := info["/usr/bin"]; ok {
		t.Error("directory entry should not appear in fileInfo")
	}
	// Regular file recorded with correct metadata and layer origin.
	f, ok := info["/usr/bin/curl"]
	if !ok {
		t.Fatal("/usr/bin/curl not recorded")
	}
	if f.Size != int64(len("ELF...")) {
		t.Errorf("curl Size = %d, want %d", f.Size, len("ELF..."))
	}
	if origin["/usr/bin/curl"] != 0 {
		t.Errorf("curl origin = %d, want 0", origin["/usr/bin/curl"])
	}
	// Symlink recorded both in fileInfo and the Symlinks map.
	sl, ok := info["/bin"]
	if !ok || !sl.IsSymlink || sl.LinkTarget != "usr/bin" {
		t.Errorf("/bin symlink not recorded correctly: %+v", sl)
	}
	if fs.Symlinks["/bin"] != "usr/bin" {
		t.Errorf("Symlinks[/bin] = %q, want usr/bin", fs.Symlinks["/bin"])
	}
}

func TestScanLayerTarLastWriterWins(t *testing.T) {
	fs, origin, info := newScanState()
	l0 := buildTar(t, []tarEntry{{name: "app/config", body: "v1"}})
	l1 := buildTar(t, []tarEntry{{name: "app/config", body: "version-two"}})

	if err := scanLayerTar(bytes.NewReader(l0), 0, fs, origin, info); err != nil {
		t.Fatal(err)
	}
	if err := scanLayerTar(bytes.NewReader(l1), 1, fs, origin, info); err != nil {
		t.Fatal(err)
	}

	f := info["/app/config"]
	if f.Size != int64(len("version-two")) {
		t.Errorf("config Size = %d, want %d (later layer should win)", f.Size, len("version-two"))
	}
	if origin["/app/config"] != 1 {
		t.Errorf("config origin = %d, want 1 (later layer)", origin["/app/config"])
	}
}

func TestScanLayerTarWhiteout(t *testing.T) {
	fs, origin, info := newScanState()
	l0 := buildTar(t, []tarEntry{
		{name: "app/keep", body: "x"},
		{name: "app/remove-me", body: "y"},
	})
	l1 := buildTar(t, []tarEntry{
		{name: "app/.wh.remove-me"}, // whiteout deletes app/remove-me
	})

	if err := scanLayerTar(bytes.NewReader(l0), 0, fs, origin, info); err != nil {
		t.Fatal(err)
	}
	if err := scanLayerTar(bytes.NewReader(l1), 1, fs, origin, info); err != nil {
		t.Fatal(err)
	}

	if _, ok := info["/app/remove-me"]; ok {
		t.Error("/app/remove-me should have been whited out")
	}
	if _, ok := info["/app/keep"]; !ok {
		t.Error("/app/keep should survive the whiteout")
	}
	// The whiteout marker itself is not a real file.
	if _, ok := info["/app/.wh.remove-me"]; ok {
		t.Error("whiteout marker should not be recorded as a file")
	}
}

func TestScanLayerTarOpaqueWhiteout(t *testing.T) {
	fs, origin, info := newScanState()
	l0 := buildTar(t, []tarEntry{
		{name: "data/a", body: "1"},
		{name: "data/sub/b", body: "2"},
		{name: "other/c", body: "3"},
	})
	l1 := buildTar(t, []tarEntry{
		{name: "data/.wh..wh..opq"}, // clears everything previously under data/
		{name: "data/fresh", body: "new"},
	})

	if err := scanLayerTar(bytes.NewReader(l0), 0, fs, origin, info); err != nil {
		t.Fatal(err)
	}
	if err := scanLayerTar(bytes.NewReader(l1), 1, fs, origin, info); err != nil {
		t.Fatal(err)
	}

	for _, gone := range []string{"/data/a", "/data/sub/b"} {
		if _, ok := info[gone]; ok {
			t.Errorf("%s should be cleared by opaque whiteout", gone)
		}
	}
	if _, ok := info["/data/fresh"]; !ok {
		t.Error("/data/fresh added in the opaque layer should remain")
	}
	if _, ok := info["/other/c"]; !ok {
		t.Error("/other/c outside the opaque dir should be untouched")
	}
}

func TestScanLayerTarWhiteoutClearsPkgDB(t *testing.T) {
	fs, origin, info := newScanState()
	l0 := buildTar(t, []tarEntry{
		{name: "usr/lib/apk/db/installed", body: "C:Q1\nP:curl\nF:usr/bin\nR:curl\n"},
		{name: "usr/bin/curl", mode: 0o755, body: "ELF..."},
	})
	// A later layer removes the package db (e.g. image slimming) while leaving
	// the installed files in place.
	l1 := buildTar(t, []tarEntry{
		{name: "usr/lib/apk/db/.wh.installed"},
	})

	if err := scanLayerTar(bytes.NewReader(l0), 0, fs, origin, info); err != nil {
		t.Fatal(err)
	}
	if err := scanLayerTar(bytes.NewReader(l1), 1, fs, origin, info); err != nil {
		t.Fatal(err)
	}

	if _, ok := fs.FileContent["/usr/lib/apk/db/installed"]; ok {
		t.Error("apk db content should be cleared after its whiteout")
	}
	// The installed file itself still exists; it just isn't tracked anymore.
	if _, ok := info["/usr/bin/curl"]; !ok {
		t.Error("/usr/bin/curl should survive the db whiteout")
	}
}

func TestScanLayerTarWhiteoutPrunesSymlink(t *testing.T) {
	fs, origin, info := newScanState()
	l0 := buildTar(t, []tarEntry{
		{name: "usr/lib64", typeflag: tar.TypeSymlink, linkname: "lib"},
	})
	l1 := buildTar(t, []tarEntry{
		{name: "usr/.wh.lib64"}, // whiteout deletes the /usr/lib64 symlink
	})

	if err := scanLayerTar(bytes.NewReader(l0), 0, fs, origin, info); err != nil {
		t.Fatal(err)
	}
	if _, ok := fs.Symlinks["/usr/lib64"]; !ok {
		t.Fatal("precondition: symlink should be recorded after layer 0")
	}
	if err := scanLayerTar(bytes.NewReader(l1), 1, fs, origin, info); err != nil {
		t.Fatal(err)
	}

	// The deleted alias must not linger in Symlinks, else ResolveSymlink would
	// still rewrite /usr/lib64/... paths after the symlink is gone.
	if _, ok := fs.Symlinks["/usr/lib64"]; ok {
		t.Error("whiteout should prune /usr/lib64 from fs.Symlinks")
	}
	if got := fs.ResolveSymlink("/usr/lib64/libc.so"); got != "/usr/lib64/libc.so" {
		t.Errorf("ResolveSymlink after whiteout = %q, want unchanged path", got)
	}
}

func TestScanLayerTarOpaqueWhiteoutPrunesSymlink(t *testing.T) {
	fs, origin, info := newScanState()
	l0 := buildTar(t, []tarEntry{
		{name: "usr/lib64", typeflag: tar.TypeSymlink, linkname: "lib"},
		{name: "usr/keep", body: "x"},
	})
	l1 := buildTar(t, []tarEntry{
		{name: "usr/.wh..wh..opq"}, // clears everything previously under usr/
	})

	if err := scanLayerTar(bytes.NewReader(l0), 0, fs, origin, info); err != nil {
		t.Fatal(err)
	}
	if err := scanLayerTar(bytes.NewReader(l1), 1, fs, origin, info); err != nil {
		t.Fatal(err)
	}

	if _, ok := fs.Symlinks["/usr/lib64"]; ok {
		t.Error("opaque whiteout should prune /usr/lib64 from fs.Symlinks")
	}
}

func TestScanLayerTarOverwriteSymlinkPrunesAlias(t *testing.T) {
	// A later layer replacing a symlink with a real file (or a directory) must
	// drop the stale alias so ResolveSymlink no longer follows it.
	cases := []struct {
		name  string
		entry tarEntry
	}{
		{"regular file", tarEntry{name: "opt/tool", body: "ELF..."}},
		{"directory", tarEntry{name: "opt/tool", typeflag: tar.TypeDir}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, origin, info := newScanState()
			l0 := buildTar(t, []tarEntry{
				{name: "opt/tool", typeflag: tar.TypeSymlink, linkname: "../real/tool"},
			})
			l1 := buildTar(t, []tarEntry{tc.entry})

			if err := scanLayerTar(bytes.NewReader(l0), 0, fs, origin, info); err != nil {
				t.Fatal(err)
			}
			if err := scanLayerTar(bytes.NewReader(l1), 1, fs, origin, info); err != nil {
				t.Fatal(err)
			}

			if _, ok := fs.Symlinks["/opt/tool"]; ok {
				t.Errorf("overwriting the symlink with a %s should prune it from fs.Symlinks", tc.name)
			}
		})
	}
}

func TestScanLayerTarWhiteoutClearsOsRelease(t *testing.T) {
	fs, origin, info := newScanState()
	l0 := buildTar(t, []tarEntry{
		{name: "etc/os-release", body: "ID=alpine\n"},
	})
	l1 := buildTar(t, []tarEntry{
		{name: "etc/.wh.os-release"},
	})

	if err := scanLayerTar(bytes.NewReader(l0), 0, fs, origin, info); err != nil {
		t.Fatal(err)
	}
	if err := scanLayerTar(bytes.NewReader(l1), 1, fs, origin, info); err != nil {
		t.Fatal(err)
	}

	if id := fs.OsRelease["ID"]; id != "" {
		t.Errorf("OsRelease[ID] = %q, want empty after os-release whiteout", id)
	}
}

func TestScanLayerTarOpaqueWhiteoutClearsCache(t *testing.T) {
	fs, origin, info := newScanState()
	l0 := buildTar(t, []tarEntry{
		{name: "var/lib/dpkg/status", body: "Package: curl\nStatus: install ok installed\n"},
		{name: "var/lib/dpkg/info/curl.list", body: "/usr/bin/curl\n"},
	})
	// Opaque whiteout on the dpkg dir wipes the whole tree.
	l1 := buildTar(t, []tarEntry{
		{name: "var/lib/dpkg/.wh..wh..opq"},
	})

	if err := scanLayerTar(bytes.NewReader(l0), 0, fs, origin, info); err != nil {
		t.Fatal(err)
	}
	if err := scanLayerTar(bytes.NewReader(l1), 1, fs, origin, info); err != nil {
		t.Fatal(err)
	}

	for _, gone := range []string{"/var/lib/dpkg/status", "/var/lib/dpkg/info/curl.list"} {
		if _, ok := fs.FileContent[gone]; ok {
			t.Errorf("%s should be cleared by opaque whiteout", gone)
		}
	}
}

func TestScanLayerTarOsReleaseLastWriterWins(t *testing.T) {
	// A later layer replacing /etc/os-release must take precedence (last-writer-wins),
	// consistent with overlay FS semantics.
	fs, origin, info := newScanState()
	l0 := buildTar(t, []tarEntry{
		{name: "etc/os-release", body: "ID=alpine\n"},
	})
	l1 := buildTar(t, []tarEntry{
		{name: "etc/os-release", body: "ID=wolfi\n"},
	})

	if err := scanLayerTar(bytes.NewReader(l0), 0, fs, origin, info); err != nil {
		t.Fatal(err)
	}
	if err := scanLayerTar(bytes.NewReader(l1), 1, fs, origin, info); err != nil {
		t.Fatal(err)
	}

	if got := fs.OsRelease["ID"]; got != "wolfi" {
		t.Errorf("OsRelease[ID] = %q, want wolfi (later layer should win)", got)
	}
}

func TestScanLayerTarHardLink(t *testing.T) {
	// A hard link (TypeLink) must NOT be recorded as a symlink and must NOT be
	// added to the Symlinks map; it is a distinct file entry.
	fs, origin, info := newScanState()
	layer := buildTar(t, []tarEntry{
		{name: "usr/bin/busybox", mode: 0o755, body: "ELF"},
		{name: "usr/bin/sh", typeflag: tar.TypeLink, linkname: "usr/bin/busybox"},
	})

	if err := scanLayerTar(bytes.NewReader(layer), 0, fs, origin, info); err != nil {
		t.Fatalf("scanLayerTar: %v", err)
	}

	f, ok := info["/usr/bin/sh"]
	if !ok {
		t.Fatal("/usr/bin/sh hard link not recorded in fileInfo")
	}
	if f.IsSymlink {
		t.Error("/usr/bin/sh hard link incorrectly marked IsSymlink=true")
	}
	if _, inSymlinks := fs.Symlinks["/usr/bin/sh"]; inSymlinks {
		t.Error("/usr/bin/sh hard link incorrectly added to Symlinks map")
	}
	if origin["/usr/bin/sh"] != 0 {
		t.Errorf("/usr/bin/sh origin = %d, want 0", origin["/usr/bin/sh"])
	}
}
