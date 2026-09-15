package image

import (
	"archive/tar"
	"bytes"
	"testing"
)

func TestExtractLayerContentsBasic(t *testing.T) {
	layer := buildTar(t, []tarEntry{
		{name: "usr/bin/curl", mode: 0o755, body: "curl-bytes"},
		{name: "usr/bin/wget", mode: 0o755, body: "wget-bytes"},
		{name: "etc/config", body: "cfg"},
	})
	want := map[string]bool{"/usr/bin/curl": true, "/etc/config": true}
	out := map[string][]byte{}
	if err := extractLayerContents(bytes.NewReader(layer), want, out); err != nil {
		t.Fatalf("extractLayerContents: %v", err)
	}

	if got := string(out["/usr/bin/curl"]); got != "curl-bytes" {
		t.Errorf("curl content = %q, want curl-bytes", got)
	}
	if got := string(out["/etc/config"]); got != "cfg" {
		t.Errorf("config content = %q, want cfg", got)
	}
	// Unwanted paths must not be buffered.
	if _, ok := out["/usr/bin/wget"]; ok {
		t.Error("unwanted /usr/bin/wget should not be captured")
	}
}

func TestExtractLayerContentsLastWriterWins(t *testing.T) {
	want := map[string]bool{"/app/bin": true}
	out := map[string][]byte{}
	l0 := buildTar(t, []tarEntry{{name: "app/bin", body: "old"}})
	l1 := buildTar(t, []tarEntry{{name: "app/bin", body: "new-content"}})

	if err := extractLayerContents(bytes.NewReader(l0), want, out); err != nil {
		t.Fatal(err)
	}
	if err := extractLayerContents(bytes.NewReader(l1), want, out); err != nil {
		t.Fatal(err)
	}
	if got := string(out["/app/bin"]); got != "new-content" {
		t.Errorf("content = %q, want new-content (later layer wins)", got)
	}
}

func TestExtractLayerContentsWhiteout(t *testing.T) {
	want := map[string]bool{"/app/bin": true}
	out := map[string][]byte{}
	l0 := buildTar(t, []tarEntry{{name: "app/bin", body: "data"}})
	l1 := buildTar(t, []tarEntry{{name: "app/.wh.bin"}})

	if err := extractLayerContents(bytes.NewReader(l0), want, out); err != nil {
		t.Fatal(err)
	}
	if err := extractLayerContents(bytes.NewReader(l1), want, out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["/app/bin"]; ok {
		t.Error("whiteout should have dropped /app/bin content")
	}
}

func TestExtractLayerContentsOpaqueWhiteout(t *testing.T) {
	want := map[string]bool{"/app/a": true, "/app/b": true}
	out := map[string][]byte{}
	l0 := buildTar(t, []tarEntry{
		{name: "app/a", body: "aa"},
		{name: "app/b", body: "bb"},
	})
	l1 := buildTar(t, []tarEntry{{name: "app/.wh..wh..opq"}})

	if err := extractLayerContents(bytes.NewReader(l0), want, out); err != nil {
		t.Fatal(err)
	}
	if err := extractLayerContents(bytes.NewReader(l1), want, out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("opaque whiteout should have cleared all /app/* content, got %v", out)
	}
}

func TestExtractLayerContentsSymlinkReplacesContent(t *testing.T) {
	// A wanted path re-appearing as a symlink in a later layer drops the earlier
	// regular-file content, since symlinks have no body to read.
	want := map[string]bool{"/app/bin": true}
	out := map[string][]byte{}
	l0 := buildTar(t, []tarEntry{{name: "app/bin", body: "data"}})
	l1 := buildTar(t, []tarEntry{{name: "app/bin", typeflag: tar.TypeSymlink, linkname: "elsewhere"}})

	if err := extractLayerContents(bytes.NewReader(l0), want, out); err != nil {
		t.Fatal(err)
	}
	if err := extractLayerContents(bytes.NewReader(l1), want, out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["/app/bin"]; ok {
		t.Error("symlink in later layer should drop earlier content")
	}
}

func TestExtractContentsNilImage(t *testing.T) {
	fs := &ImageFS{}
	// No image source: extraction of any wanted path should error, but an empty
	// request should short-circuit successfully.
	if _, err := fs.ExtractContents(map[string]bool{}); err != nil {
		t.Errorf("empty want should not error, got %v", err)
	}
	if _, err := fs.ExtractContents(map[string]bool{"/x": true}); err == nil {
		t.Error("expected error when image source is unavailable")
	}
}
