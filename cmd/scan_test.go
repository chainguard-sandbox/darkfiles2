package cmd

import (
	"sort"
	"testing"

	"github.com/chainguard-dev/darkfiles2/internal/image"
	"github.com/chainguard-dev/darkfiles2/internal/report"
)

func TestValidSet(t *testing.T) {
	for _, s := range []string{"unknown", "dark", "tracked", "all", "in-sbom"} {
		if !validSet(s) {
			t.Errorf("validSet(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "Dark", "untracked", "foo"} {
		if validSet(s) {
			t.Errorf("validSet(%q) = true, want false", s)
		}
	}
}

func TestSelectFiles(t *testing.T) {
	// Image: 4 files. /app/x is unknown-dark, /etc/passwd is expected-dark,
	// /usr/bin/curl and /usr/lib/libc.so are tracked.
	fs := &image.ImageFS{
		Files: []image.File{
			{Path: "/app/x"},
			{Path: "/etc/passwd"},
			{Path: "/usr/bin/curl"},
			{Path: "/usr/lib/libc.so"},
		},
	}
	r := &report.Result{
		DarkFiles: []report.CategorizedFile{
			{File: image.File{Path: "/app/x"}, Cat: report.CategoryUnknown},
			{File: image.File{Path: "/etc/passwd"}, Cat: report.CategoryRuntimeGenerated},
		},
	}

	tests := []struct {
		set  string
		want []string
	}{
		{"unknown", []string{"/app/x"}},
		{"dark", []string{"/app/x", "/etc/passwd"}},
		{"tracked", []string{"/usr/bin/curl", "/usr/lib/libc.so"}},
		{"all", []string{"/app/x", "/etc/passwd", "/usr/bin/curl", "/usr/lib/libc.so"}},
	}
	for _, tt := range tests {
		t.Run(tt.set, func(t *testing.T) {
			got := paths(selectFiles(r, fs, tt.set, false))
			if !equalUnordered(got, tt.want) {
				t.Errorf("selectFiles(set=%q) = %v, want %v", tt.set, got, tt.want)
			}
		})
	}
}

func TestSelectFilesCodeOnly(t *testing.T) {
	fs := &image.ImageFS{
		Files: []image.File{
			{Path: "/app/server", Kind: image.KindExecutable},
			{Path: "/usr/lib/libfoo.so.1", Kind: image.KindSharedLibrary},
			{Path: "/app/config.yaml", Kind: image.KindOther},
		},
	}
	r := &report.Result{
		DarkFiles: []report.CategorizedFile{
			{File: fs.Files[0], Cat: report.CategoryUnknown},
			{File: fs.Files[1], Cat: report.CategoryUnknown},
			{File: fs.Files[2], Cat: report.CategoryUnknown},
		},
	}
	got := paths(selectFiles(r, fs, "dark", true))
	want := []string{"/app/server", "/usr/lib/libfoo.so.1"}
	if !equalUnordered(got, want) {
		t.Errorf("selectFiles(dark, codeOnly) = %v, want %v", got, want)
	}
}

func paths(files []report.CategorizedFile) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Path
	}
	return out
}

func equalUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
