package libdetect

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
	dets := db.Detect([]byte("... curl 8.21.0 ..."), DefaultMinLength)
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
	dets := db.Detect([]byte("has FOO_MARKER inside"), DefaultMinLength)
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if !reflect.DeepEqual(dets[0].Versions, []string{Unknown}) {
		t.Errorf("versions = %v, want [UNKNOWN]", dets[0].Versions)
	}
}

func TestScanIgnorePattern(t *testing.T) {
	// The whole match "libfoo 9.9.9" is ignored, so no version is recorded, but
	// the checker still reports presence as UNKNOWN (the version pattern matching
	// establishes presence before ignore filtering removes the version).
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
	dets := db.Detect([]byte("libfoo 9.9.9"), DefaultMinLength)
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if !reflect.DeepEqual(dets[0].Versions, []string{Unknown}) {
		t.Errorf("versions = %v, want [UNKNOWN] (ignored match)", dets[0].Versions)
	}
}

func TestFilenameOnlyCheckerNotDetected(t *testing.T) {
	// Detection is contents-only: a checker with only FILENAME patterns can never
	// match, and its file name is irrelevant.
	json := `{"checkers":[{
		"name":"foo",
		"vendor_product":[["acme","foo"]],
		"filename_patterns":["foo"]
	}]}`
	db, err := loadFrom([]byte(json))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if dets := db.Detect([]byte("nothing here"), DefaultMinLength); len(dets) != 0 {
		t.Errorf("expected no detection from a filename-only checker, got %+v", dets)
	}
}

func TestDistinctiveMarker(t *testing.T) {
	keep := []string{
		"libevent using: %s", // multi-word phrase
		"GNU Bison ",         // has uppercase + space
		"coreutils-",         // version connector
		"apr-util-1",         // punctuation + digit
	}
	drop := []string{
		"coreutils", // bare lowercase word
		"unbound ",  // trims to 7 chars, below threshold
		"apcupsd",   // bare word (safe to drop even though distinctive)
		"short",     // too short
		"",          // empty (version pattern started with a group)
	}
	for _, m := range keep {
		if !distinctiveMarker(m) {
			t.Errorf("distinctiveMarker(%q) = false, want true", m)
		}
	}
	for _, m := range drop {
		if distinctiveMarker(m) {
			t.Errorf("distinctiveMarker(%q) = true, want false", m)
		}
	}
}

func TestPresenceMarkerFallback(t *testing.T) {
	// A version-only checker whose anchored pattern needs the version adjacent to
	// "libfoo using: ". The literal prefix "libfoo using: " is a distinctive
	// marker.
	json := `{"checkers":[{
		"name":"libfoo",
		"vendor_product":[["acme","libfoo"]],
		"version_patterns":["libfoo using: [a-z ]*([0-9.]+)-stable"]
	}]}`
	db, err := loadFrom([]byte(json))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}

	// Adjacent: the full pattern matches, real version reported.
	dets := db.Detect([]byte("libfoo using: epoll 1.2.3-stable"), DefaultMinLength)
	if len(dets) != 1 || !reflect.DeepEqual(dets[0].Versions, []string{"1.2.3"}) {
		t.Fatalf("adjacent: got %+v, want libfoo 1.2.3", dets)
	}

	// Spaced apart: the anchored pattern fails (uppercase + '/' break the class),
	// but the marker still fires -> presence with UNKNOWN version.
	spaced := []byte("libfoo using: epoll\nSOME/Path/thing\n1.2.3-stable")
	dets = db.Detect(spaced, DefaultMinLength)
	if len(dets) != 1 || !reflect.DeepEqual(dets[0].Versions, []string{Unknown}) {
		t.Fatalf("spaced: got %+v, want libfoo UNKNOWN", dets)
	}
}

func TestPresenceMarkerNoBareWordFalsePositive(t *testing.T) {
	// "unbound (...)" yields the literal prefix "unbound ", which trims below the
	// length threshold and is rejected as a marker — so an English-word occurrence
	// must not be reported.
	json := `{"checkers":[{
		"name":"unbound",
		"vendor_product":[["nlnetlabs","unbound"]],
		"version_patterns":["unbound ([0-9.]+)"]
	}]}`
	db, err := loadFrom([]byte(json))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	dets := db.Detect([]byte("Sets hash slots as unbound for a node."), DefaultMinLength)
	if len(dets) != 0 {
		t.Errorf("expected no detection from bare-word marker, got %+v", dets)
	}
}

func TestPresenceMarkerOnlyForVersionOnlyCheckers(t *testing.T) {
	// A checker with a CONTAINS pattern must not gain a version-prefix marker;
	// presence for it is already well-defined by CONTAINS.
	json := `{"checkers":[{
		"name":"libfoo",
		"vendor_product":[["acme","libfoo"]],
		"contains_patterns":["FOO_BUILD_ID"],
		"version_patterns":["libfoo using: [a-z ]*([0-9.]+)-stable"]
	}]}`
	db, err := loadFrom([]byte(json))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if len(db.checkers[0].versionMarkers) != 0 {
		t.Errorf("checker with CONTAINS should have no version markers, got %v", db.checkers[0].versionMarkers)
	}
	// The marker string alone (no CONTAINS, no adjacent version) must not match.
	spaced := []byte("libfoo using: epoll\nSOME/Path\n1.2.3-stable")
	if dets := db.Detect(spaced, DefaultMinLength); len(dets) != 0 {
		t.Errorf("expected no detection (no marker fallback for CONTAINS checker), got %+v", dets)
	}
}

func TestVersionMatchAloneDoesNotEstablishPresence(t *testing.T) {
	// A checker with CONTAINS patterns must not be reported present on a VERSION
	// match alone: VERSION patterns are often loose and match mere references to a
	// library. Presence requires one of the (stronger) CONTAINS markers.
	json := `{"checkers":[{
		"name":"foo",
		"vendor_product":[["acme","foo"]],
		"contains_patterns":["FOO_RUNTIME_MARKER"],
		"version_patterns":["foo ([0-9]+\\.[0-9]+\\.[0-9]+)"]
	}]}`
	db, err := loadFrom([]byte(json))
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}

	// Version string present but no CONTAINS marker -> not detected.
	if dets := db.Detect([]byte("built against foo 1.2.3"), DefaultMinLength); len(dets) != 0 {
		t.Errorf("version-only match on a CONTAINS checker should not be detected, got %+v", dets)
	}

	// CONTAINS marker present -> detected, and the version is still extracted.
	dets := db.Detect([]byte("FOO_RUNTIME_MARKER\nfoo 1.2.3"), DefaultMinLength)
	if len(dets) != 1 || !reflect.DeepEqual(dets[0].Versions, []string{"1.2.3"}) {
		t.Fatalf("CONTAINS + version: got %+v, want foo 1.2.3", dets)
	}
}

// TestNodeFalsePositiveOnCompatRuntimes guards against reporting node.js in
// Node-compatible runtimes (deno, bun) that are not the node C++ runtime but
// embed references to it. Both ship the "https://nodejs.org/download/release/v"
// download URL (and deno a "node vX.Y.Z" mention) for their Node compatibility
// layer; neither contains node's runtime-specific markers. A real node binary,
// which does carry those markers, must still be detected.
func TestNodeFalsePositiveOnCompatRuntimes(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	nodeDetected := func(blob []byte) bool {
		for _, d := range db.Detect(blob, DefaultMinLength) {
			if d.Library == "node.js" {
				return true
			}
		}
		return false
	}

	// deno/bun embed only references to node; node must NOT be reported.
	denoish := []byte("deno\nhttps://nodejs.org/download/release/v21.2.0/node-v21.2.0.tar.gz\nnode v10.12.0\n")
	if nodeDetected(denoish) {
		t.Errorf("node.js falsely detected from Node-compat reference strings (deno/bun scenario)")
	}

	// A real node binary carries runtime-specific markers and must be detected.
	realNode := []byte("Usage: node [options]\nDocumentation can be found at https://nodejs.org/\nhttps://nodejs.org/download/release/v21.2.0/\n")
	if !nodeDetected(realNode) {
		t.Errorf("node.js not detected from genuine node runtime markers")
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
	dets := db.Detect([]byte("ver 1_2-3"), DefaultMinLength)
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if !reflect.DeepEqual(dets[0].Versions, []string{"1.2.3"}) {
		t.Errorf("versions = %v, want [1.2.3] (underscore/dash rewritten)", dets[0].Versions)
	}
}
