package cmd

import (
	"sort"
	"testing"

	"github.com/chainguard-dev/darkfiles2/internal/image"
	"github.com/chainguard-dev/darkfiles2/internal/report"
)

func TestValidSet(t *testing.T) {
	for _, s := range []string{"unknown", "dark", "tracked", "all"} {
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
			got := paths(selectFiles(r, fs, tt.set))
			if !equalUnordered(got, tt.want) {
				t.Errorf("selectFiles(set=%q) = %v, want %v", tt.set, got, tt.want)
			}
		})
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
