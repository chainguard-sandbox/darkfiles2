package fingerprint

import (
	"reflect"
	"testing"
)

func TestExtractStrings(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		minLen int
		want   string
	}{
		{"runs below min len dropped", []byte("ab\x00hello\x00"), 3, "hello"},
		{"strings newline joined", []byte("curl\x007.80.0\x00"), 3, "curl\n7.80.0"},
		{"tab is printable", []byte("a\tbc\x00"), 3, "a\tbc"},
		{"leading short run does not add newline", []byte("ab\x00hello\x00world\x00"), 3, "hello\nworld"},
		{"empty", []byte{}, 3, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractStrings(tc.data, tc.minLen); got != tc.want {
				t.Errorf("extractStrings(%q, %d) = %q, want %q", tc.data, tc.minLen, got, tc.want)
			}
		})
	}
}

func TestLoadEmbedded(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(db.checkers) == 0 {
		t.Fatal("expected checkers in embedded database")
	}
	if db.Skipped != 0 {
		t.Errorf("expected all embedded patterns to compile, %d skipped", db.Skipped)
	}
}

func TestScanDetectsVersion(t *testing.T) {
	// A minimal DB with a single checker matching a curl-style version string.
	json := `{"checkers":[{
		"name":"curl",
		"vendor_product":[["haxx","curl"],["haxx","libcurl"]],
		"version_patterns":["curl ([0-9]+\\.[0-9]+\\.[0-9]+)"]
	}]}`
	db, err := loadFrom([]byte(json))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}

	// The '\n' join is what lets the extracted "curl" and "8.21.0" runs be
	// matched by "curl X.Y.Z" only if adjacent; here they are on one run.
	dets := db.Fingerprint([]byte("... curl 8.21.0 ..."), "curl", DefaultMinLength, false)
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d: %+v", len(dets), dets)
	}
	d := dets[0]
	if d.Library != "curl" {
		t.Errorf("library = %q, want curl", d.Library)
	}
	if !reflect.DeepEqual(d.Versions, []string{"8.21.0"}) {
		t.Errorf("versions = %v, want [8.21.0]", d.Versions)
	}
	if !d.Evidence.MatchedContents {
		t.Error("expected MatchedContents to be true")
	}
	if d.Evidence.MatchedFilename {
		t.Error("expected MatchedFilename to be false without --use-filename")
	}
}

func TestScanPresenceOnlyIsUnknown(t *testing.T) {
	json := `{"checkers":[{
		"name":"foo",
		"vendor_product":[["acme","foo"]],
		"contains_patterns":["FOO_MARKER"]
	}]}`
	db, err := loadFrom([]byte(json))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	dets := db.Fingerprint([]byte("has FOO_MARKER inside"), "bin", DefaultMinLength, false)
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if !reflect.DeepEqual(dets[0].Versions, []string{Unknown}) {
		t.Errorf("versions = %v, want [UNKNOWN]", dets[0].Versions)
	}
}

func TestScanIgnorePattern(t *testing.T) {
	// The whole match "libfoo 9.9.9" is ignored, so no version is recorded and,
	// with no other evidence, the checker still reports presence as UNKNOWN
	// (version.is_match sets presence before ignore filtering).
	json := `{"checkers":[{
		"name":"libfoo",
		"vendor_product":[["acme","libfoo"]],
		"version_patterns":["libfoo ([0-9.]+)"],
		"ignore_patterns":["libfoo 9\\.9\\.9"]
	}]}`
	db, err := loadFrom([]byte(json))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	dets := db.Fingerprint([]byte("libfoo 9.9.9"), "bin", DefaultMinLength, false)
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if !reflect.DeepEqual(dets[0].Versions, []string{Unknown}) {
		t.Errorf("versions = %v, want [UNKNOWN] (ignored match)", dets[0].Versions)
	}
}

func TestScanUseFilename(t *testing.T) {
	json := `{"checkers":[{
		"name":"foo",
		"vendor_product":[["acme","foo"]],
		"filename_patterns":["foo"]
	}]}`
	db, err := loadFrom([]byte(json))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	// Without use_filename, a filename-only match is not evidence.
	if dets := db.Fingerprint([]byte("nothing here"), "foo", DefaultMinLength, false); len(dets) != 0 {
		t.Errorf("expected no detection without use_filename, got %+v", dets)
	}
	// With use_filename, the filename match counts.
	dets := db.Fingerprint([]byte("nothing here"), "foo", DefaultMinLength, true)
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection with use_filename, got %d", len(dets))
	}
	if !dets[0].Evidence.MatchedFilename {
		t.Error("expected MatchedFilename true")
	}
}

func TestVersionSeparatorRewrite(t *testing.T) {
	json := `{"checkers":[{
		"name":"foo",
		"vendor_product":[["acme","foo"]],
		"version_patterns":["ver ([0-9_-]+)"]
	}]}`
	db, err := loadFrom([]byte(json))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	dets := db.Fingerprint([]byte("ver 1_2-3"), "bin", DefaultMinLength, false)
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if !reflect.DeepEqual(dets[0].Versions, []string{"1.2.3"}) {
		t.Errorf("versions = %v, want [1.2.3] (underscore/dash rewritten)", dets[0].Versions)
	}
}
