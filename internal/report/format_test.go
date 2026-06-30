package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

func layerFiles() (layers []image.Layer, files []CategorizedFile) {
	layers = []image.Layer{{Index: 0, CreatedBy: "apko build"}}
	files = []CategorizedFile{
		{File: image.File{Path: "/opt/bin", Size: 100, Mode: 0o755, Kind: image.KindExecutable}, Cat: CategoryUnknown},
		{File: image.File{Path: "/etc/cfg", Size: 10, Mode: 0o644, Kind: image.KindOther}, Cat: CategoryUnknown},
	}
	return layers, files
}

func TestPrintStatsShowsZeroUnknown(t *testing.T) {
	// Dark files exist, but all are expected (pkg-manager state) — none unknown.
	// The breakdown should still state "Unknown: 0 files" rather than omit it.
	r := &Result{
		ImageRef:   "example:latest",
		Distro:     "wolfi",
		TotalFiles: 10,
		DarkFiles: []CategorizedFile{
			{File: image.File{Path: "/var/lib/apk/db/installed", Size: 100}, Cat: CategoryPkgManagerState},
		},
	}
	var buf bytes.Buffer
	PrintStats(&buf, r)
	out := buf.String()

	// tabwriter expands the tab to a variable number of spaces, so check the
	// label and the count on the same line independently.
	var unknownLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Unknown:") {
			unknownLine = line
			break
		}
	}
	if unknownLine == "" {
		t.Fatalf("expected an Unknown line in the breakdown, got:\n%s", out)
	}
	if !strings.Contains(unknownLine, "0 files") {
		t.Errorf("expected Unknown to report 0 files, got line: %q", unknownLine)
	}
}

func TestPrintByLayerKindTagAndNoColor(t *testing.T) {
	layers, files := layerFiles()
	var buf bytes.Buffer
	PrintByLayer(&buf, layers, files, false, false)
	out := buf.String()

	if !strings.Contains(out, "[executable]") {
		t.Errorf("expected [executable] tag, got:\n%s", out)
	}
	// Without color: no ANSI sequences and no raw tabwriter escape bytes.
	if strings.Contains(out, "\033[") {
		t.Errorf("color disabled but ANSI escape present:\n%q", out)
	}
	if strings.ContainsRune(out, '\xff') {
		t.Errorf("raw tabwriter escape byte leaked into output:\n%q", out)
	}
}

func TestPrintByLayerColorEscaping(t *testing.T) {
	layers, files := layerFiles()
	var buf bytes.Buffer
	PrintByLayer(&buf, layers, files, false, true)
	out := buf.String()

	// Color enabled: the code file is wrapped in ANSI, escape bytes are stripped.
	if !strings.Contains(out, codeColor) {
		t.Errorf("color enabled but no ANSI colour code emitted:\n%q", out)
	}
	if !strings.Contains(out, ansiReset) {
		t.Errorf("color enabled but no ANSI reset emitted:\n%q", out)
	}
	if strings.ContainsRune(out, '\xff') {
		t.Errorf("tabwriter escape byte (0xff) leaked into output:\n%q", out)
	}
	// The non-code file should not be coloured: the only colour codes belong to
	// the executable's row, so there should be exactly one reset per coloured
	// cell (path, size, mode, tag) and none around /etc/cfg.
	if strings.Count(out, codeColor) != strings.Count(out, ansiReset) {
		t.Errorf("unbalanced colour/reset sequences:\n%q", out)
	}
}

func TestSanitize(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "/usr/bin/vault", "/usr/bin/vault"},
		{"unicode kept", "/usr/share/café", "/usr/share/café"},
		{"esc", "/bin/\x1b[31mevil", `/bin/\x1b[31mevil`},
		{"newline", "a\nb", `a\x0ab`},
		{"carriage return", "a\rb", `a\x0db`},
		{"tab", "a\tb", `a\x09b`},
		{"del", "a\x7fb", `a\x7fb`},
		{"c1 rune", "a\u009bb", `a\x9bb`},
		{"invalid utf8", "a\x9bb", `a\ufffdb`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitize(c.in); got != c.want {
				t.Errorf("sanitize(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestPrintByLayerSanitizesUntrustedStrings(t *testing.T) {
	// A malicious image embeds ANSI escapes and newlines in the layer command,
	// a file path, and a symlink target. None should reach the output verbatim.
	layers := []image.Layer{{Index: 0, CreatedBy: "RUN \033[2Jevil"}}
	files := []CategorizedFile{
		{File: image.File{Path: "/x\033[31m/p", Size: 1, Mode: 0o644}, Cat: CategoryUnknown},
		{File: image.File{Path: "/link", Size: 0, Mode: 0o777, IsSymlink: true, LinkTarget: "/target\nFAKE"}, Cat: CategoryUnknown},
	}
	var buf bytes.Buffer
	PrintByLayer(&buf, layers, files, false, false)
	out := buf.String()

	if strings.Contains(out, "\033") {
		t.Errorf("raw ESC leaked into output:\n%q", out)
	}
	// The injected newline in the symlink target must be escaped, not literal.
	if strings.Contains(out, "/target\nFAKE") {
		t.Errorf("raw newline leaked from symlink target:\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Errorf("expected escaped ESC sequence in output:\n%q", out)
	}
}
