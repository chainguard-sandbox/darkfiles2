package sbom

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParsePathsInToto(t *testing.T) {
	// An in-toto statement wrapping an SPDX document, as published by DHI.
	data := []byte(`{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://spdx.dev/Document",
		"predicate": {
			"spdxVersion": "SPDX-2.3",
			"files": [
				{"fileName": "usr/local/bin/vault"},
				{"fileName": "./opt/docker/sbom/vault.json"},
				{"fileName": "/already/absolute"},
				{"fileName": ""}
			]
		}
	}`)
	got, err := parsePaths(data)
	if err != nil {
		t.Fatalf("parsePaths: %v", err)
	}
	want := map[string]struct{}{
		"/usr/local/bin/vault":        {},
		"/opt/docker/sbom/vault.json": {},
		"/already/absolute":           {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsePaths() = %v, want %v", keys(got), keys(want))
	}
}

func TestParsePathsBareSPDX(t *testing.T) {
	// A bare SPDX document (no in-toto envelope), as a user might pass via
	// --sbom-file.
	data := []byte(`{"spdxVersion":"SPDX-2.3","files":[{"fileName":"usr/bin/tini"}]}`)
	got, err := parsePaths(data)
	if err != nil {
		t.Fatalf("parsePaths: %v", err)
	}
	if _, ok := got["/usr/bin/tini"]; !ok || len(got) != 1 {
		t.Errorf("parsePaths() = %v, want just /usr/bin/tini", keys(got))
	}
}

func TestParsePathsNoFiles(t *testing.T) {
	// A package-level SPDX SBOM with no files[] (the apko/syft shape) yields an
	// empty set rather than an error.
	data := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"vault"}]}`)
	got, err := parsePaths(data)
	if err != nil {
		t.Fatalf("parsePaths: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("parsePaths() = %v, want empty", keys(got))
	}
}

func TestParsePathsInvalid(t *testing.T) {
	if _, err := parsePaths([]byte("not json")); err == nil {
		t.Error("parsePaths(invalid) should return an error")
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"usr/bin/vault":      "/usr/bin/vault",
		"./usr/bin/vault":    "/usr/bin/vault",
		"/usr/bin/vault":     "/usr/bin/vault",
		"./usr/../bin/vault": "/bin/vault",     // dot-dot cleaned
		"usr//bin//vault":    "/usr/bin/vault", // double slashes cleaned
	}
	for in, want := range cases {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadCappedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	// At or under the limit: returns the full contents.
	if got, err := readCappedFile(path, 10); err != nil || string(got) != "0123456789" {
		t.Errorf("readCappedFile(max=10) = %q, %v; want full contents, nil", got, err)
	}

	// Over the limit: errors instead of buffering.
	if _, err := readCappedFile(path, 5); err == nil {
		t.Error("readCappedFile(max=5) should error on an oversized file")
	}

	// Missing file: surfaces the open error.
	if _, err := readCappedFile(filepath.Join(dir, "nope.json"), 10); err == nil {
		t.Error("readCappedFile on a missing file should error")
	}
}

func TestFilePathsLocalFileTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")
	// A valid-looking but oversized document must be rejected before parsing.
	big := `{"files":[` + strings.Repeat(`{"fileName":"/a"},`, 100) + `{"fileName":"/b"}]}`
	if err := os.WriteFile(path, []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCappedFile(path, 16); err == nil {
		t.Error("expected oversized SBOM file to be rejected")
	}
	// Sanity check: within a generous limit it still parses correctly.
	got, err := FilePaths("", path)
	if err != nil {
		t.Fatalf("FilePaths: %v", err)
	}
	if _, ok := got["/a"]; !ok {
		t.Errorf("FilePaths() = %v, want to include /a", keys(got))
	}
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
