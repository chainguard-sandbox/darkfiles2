package sbom

import (
	"reflect"
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
		"usr/bin/vault":   "/usr/bin/vault",
		"./usr/bin/vault": "/usr/bin/vault",
		"/usr/bin/vault":  "/usr/bin/vault",
	}
	for in, want := range cases {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
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
