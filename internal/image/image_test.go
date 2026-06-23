package image

import (
	"reflect"
	"testing"
)

func TestCleanPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already absolute", "/etc/passwd", "/etc/passwd"},
		{"relative", "etc/passwd", "/etc/passwd"},
		{"leading dot-slash", "./etc/passwd", "/etc/passwd"},
		{"trailing slash", "/etc/", "/etc"},
		{"dot-dot collapsed", "/usr/../etc/passwd", "/etc/passwd"},
		{"double slash", "//etc//passwd", "/etc/passwd"},
		{"root", "/", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanPath(tt.in); got != tt.want {
				t.Errorf("cleanPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseOsRelease(t *testing.T) {
	content := `
# this is a comment
ID=alpine
VERSION_ID="3.19.1"
PRETTY_NAME='Alpine Linux v3.19'

malformed line without equals
ID_LIKE=wolfi
`
	got := parseOsRelease(content)
	want := map[string]string{
		"ID":          "alpine",
		"VERSION_ID":  "3.19.1",
		"PRETTY_NAME": "Alpine Linux v3.19",
		"ID_LIKE":     "wolfi",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseOsRelease() = %#v, want %#v", got, want)
	}
}

func TestParseOsReleaseEmpty(t *testing.T) {
	got := parseOsRelease("")
	if len(got) != 0 {
		t.Errorf("parseOsRelease(\"\") = %#v, want empty", got)
	}
}

func TestLayerCommand(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "nop strips prefix",
			in:   "/bin/sh -c #(nop) COPY file:abc in /app",
			want: "COPY file:abc in /app",
		},
		{
			name: "sh -c stripped",
			in:   "/bin/sh -c apk add --no-cache curl",
			want: "apk add --no-cache curl",
		},
		{
			name: "bash -c stripped",
			in:   "/bin/bash -c echo hi",
			want: "echo hi",
		},
		{
			name: "plain command untouched",
			in:   "apko build",
			want: "apko build",
		},
		{
			name: "long command truncated",
			in:   "/bin/sh -c " + repeat("x", 200),
			want: repeat("x", 120) + "…",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := Layer{CreatedBy: tt.in}
			if got := l.Command(); got != tt.want {
				t.Errorf("Command() = %q, want %q", got, tt.want)
			}
		})
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestWhiteoutDetection(t *testing.T) {
	tests := []struct {
		path      string
		whiteout  bool
		opaque    bool
		wantTgt   string
	}{
		{"/app/.wh.foo", true, false, "/app/foo"},
		{"/app/.wh..wh..opq", false, true, ""},
		{"/app/normal", false, false, ""},
		// Root-level whiteouts resolve to a single clean leading slash.
		{"/.wh.toplevel", true, false, "/toplevel"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isWhiteout(tt.path); got != tt.whiteout {
				t.Errorf("isWhiteout(%q) = %v, want %v", tt.path, got, tt.whiteout)
			}
			if got := isOpaqueWhiteout(tt.path); got != tt.opaque {
				t.Errorf("isOpaqueWhiteout(%q) = %v, want %v", tt.path, got, tt.opaque)
			}
			if tt.whiteout {
				if got := whiteoutTarget(tt.path); got != tt.wantTgt {
					t.Errorf("whiteoutTarget(%q) = %q, want %q", tt.path, got, tt.wantTgt)
				}
			}
		})
	}
}

func TestIsPkgDBPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/lib/apk/db/installed", true},
		{"/usr/lib/apk/db/installed", true},
		{"/var/lib/dpkg/status", true},
		{"/var/lib/dpkg/info/bash.list", true},
		{"/var/lib/dpkg/info/bash.md5sums", false},
		{"/var/lib/rpm/Packages", true},
		{"/var/lib/db/sbom/foo.spdx.json", false},
		{"/etc/passwd", false},
		{"/usr/bin/curl", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isPkgDBPath(tt.path); got != tt.want {
				t.Errorf("isPkgDBPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestJoinSymlink(t *testing.T) {
	tests := []struct {
		name        string
		symlinkPath string
		target      string
		want        string
	}{
		{"absolute target", "/bin", "/usr/bin", "/usr/bin"},
		// "../bin" is resolved relative to the symlink's dir (/usr), climbing to / then into bin.
		{"relative target climbs out", "/usr/sbin", "../bin", "/bin"},
		{"relative same dir", "/etc/foo", "bar", "/etc/bar"},
		{"relative with dotdot to root", "/a/b/c", "../../x", "/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := joinSymlink(tt.symlinkPath, tt.target); got != tt.want {
				t.Errorf("joinSymlink(%q, %q) = %q, want %q", tt.symlinkPath, tt.target, got, tt.want)
			}
		})
	}
}

func elfHeader(etype byte) []byte {
	// \x7fELF, 64-bit, little-endian, then padding to offset 16, then e_type.
	h := make([]byte, 18)
	copy(h, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	h[16] = etype // e_type low byte (little-endian)
	return h
}

func TestClassifyKind(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		mode  int64
		magic []byte
		want  FileKind
	}{
		{"elf exec", "/app/server", 0o755, elfHeader(2), KindExecutable},
		{"elf shared lib by name", "/usr/lib/libfoo.so.1", 0o644, elfHeader(3), KindSharedLibrary},
		{"elf dyn .so exact", "/usr/lib/libc.so", 0o644, elfHeader(3), KindSharedLibrary},
		{"elf pie exec in bindir", "/usr/bin/tool", 0o755, elfHeader(3), KindExecutable},
		{"elf dyn no hints -> lib", "/opt/blob", 0o644, elfHeader(3), KindSharedLibrary},
		{"shebang script", "/app/run.sh", 0o755, []byte("#!/bin/sh\n"), KindScript},
		{"ar static lib", "/usr/lib/libx.a", 0o644, []byte("!<arch>\n........"), KindStaticLibrary},
		{"pe binary", "/app/win.exe", 0o755, []byte("MZ\x90\x00"), KindExecutable},
		{"wasm", "/app/mod.wasm", 0o644, []byte{0x00, 'a', 's', 'm', 1, 0, 0, 0}, KindExecutable},
		{"plain text", "/app/config", 0o644, []byte("hello world\n"), KindOther},
		{"empty file", "/app/empty", 0o644, []byte{}, KindOther},
		{"too short for elf etype", "/app/x", 0o755, []byte{0x7f, 'E', 'L', 'F'}, KindExecutable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyKind(tt.path, tt.mode, tt.magic); got != tt.want {
				t.Errorf("classifyKind(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestLooksLikeLibrary(t *testing.T) {
	yes := []string{"/usr/lib/libc.so", "/usr/lib/libc.so.6", "/x/libz.so.1.2.3", "/a/foo.dylib", "/a/bar.a"}
	no := []string{"/usr/bin/sh", "/etc/sofa", "/a/something.solib", "/a/notes.txt"}
	for _, p := range yes {
		if !looksLikeLibrary(p) {
			t.Errorf("looksLikeLibrary(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if looksLikeLibrary(p) {
			t.Errorf("looksLikeLibrary(%q) = true, want false", p)
		}
	}
}

func TestResolveSymlink(t *testing.T) {
	fs := &ImageFS{
		Symlinks: map[string]string{
			"/bin":       "/usr/bin",       // merged-usr directory symlink
			"/usr/bin/sh": "busybox",       // relative symlink in same dir
			"/a":         "/b",
			"/b":         "/c",             // chain
			"/loop1":     "/loop2",
			"/loop2":     "/loop1",         // cycle
		},
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"direct dir symlink", "/bin", "/usr/bin"},
		{"prefix rewrite through dir symlink", "/bin/sh", "/usr/bin/busybox"},
		{"relative file symlink", "/usr/bin/sh", "/usr/bin/busybox"},
		{"multi-hop chain", "/a", "/c"},
		{"no symlink", "/etc/passwd", "/etc/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fs.ResolveSymlink(tt.in); got != tt.want {
				t.Errorf("ResolveSymlink(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	// A symlink cycle must terminate (maxDepth) rather than loop forever.
	t.Run("cycle terminates", func(t *testing.T) {
		_ = fs.ResolveSymlink("/loop1")
	})
}
