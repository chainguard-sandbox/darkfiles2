// Package libdetect detects statically-linked libraries and their versions
// inside a binary using string-signature heuristics. The signature database is
// ported from cve-bin-tool's per-library checkers, but everything CVE-related
// (vulnerability databases, NVD downloads, reporting) is dropped: it answers one
// question — which libraries and versions are in this file?
//
// The pipeline mirrors cve-bin-tool: printable strings are extracted from the
// file (see extractStrings), then each checker's regex patterns are matched
// against the extracted blob. This is the Go port of the darkrustmaster (`drm`)
// tool.
package libdetect

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// signaturesJSON is the signature database (449 libraries, ported from
// cve-bin-tool), baked into the binary at build time.
//
//go:embed signatures.json
var signaturesJSON []byte

// rawDB is the JSON model produced by darkrustmaster's extract_checkers.py.
type rawDB struct {
	Checkers []rawChecker `json:"checkers"`
}

type rawChecker struct {
	Name             string     `json:"name"`
	VendorProduct    [][]string `json:"vendor_product"`
	FilenamePatterns []string   `json:"filename_patterns"`
	ContainsPatterns []string   `json:"contains_patterns"`
	VersionPatterns  []string   `json:"version_patterns"`
	IgnorePatterns   []string   `json:"ignore_patterns"`
}

// VendorProduct is one vendor/product pair a checker maps to.
type VendorProduct struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

// presenceMarkerMinLen is the minimum length of a literal version-pattern prefix
// for it to be used as a presence marker (see checker.versionMarkers). Short
// prefixes like "go" or "git/" are too generic and would cause false positives.
const presenceMarkerMinLen = 8

// checker is a single library's signature with all patterns compiled. Detection
// is contents-only, so FILENAME patterns are not compiled or matched; they are
// still read from the database to determine version-marker eligibility below.
type checker struct {
	name          string
	vendorProduct []VendorProduct
	contains      []*regexp.Regexp
	version       []*regexp.Regexp
	ignore        []*regexp.Regexp

	// versionMarkers are literal prefixes of this checker's version patterns,
	// used as a weaker presence signal: some libraries (e.g. libevent) have no
	// CONTAINS patterns, so presence relies solely on a VERSION pattern matching.
	// When the version number sits too far from its marker in the binary's string
	// table, that anchored match fails even though the library is present. If a
	// marker string still appears, we report the library present with an UNKNOWN
	// version. Only populated for version-only checkers (no CONTAINS/FILENAME) to
	// keep the extra recall targeted and the false-positive rate low.
	versionMarkers []string
}

// DB is a compiled signature database, ready to scan against.
type DB struct {
	checkers []checker
	// Skipped counts individual patterns that failed to compile and were
	// dropped rather than aborting the whole load.
	Skipped int
}

// Load parses and compiles the embedded signature database.
func Load() (*DB, error) { return loadFrom(signaturesJSON) }

func loadFrom(data []byte) (*DB, error) {
	var raw rawDB
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing signature database: %w", err)
	}
	db := &DB{}
	for _, rc := range raw.Checkers {
		c := checker{name: rc.Name}
		for _, vp := range rc.VendorProduct {
			if len(vp) == 2 {
				c.vendorProduct = append(c.vendorProduct, VendorProduct{Vendor: vp[0], Product: vp[1]})
			}
		}
		c.contains = db.compileAll(rc.ContainsPatterns)
		c.version = db.compileAll(rc.VersionPatterns)
		c.ignore = db.compileAll(rc.IgnorePatterns)

		// Derive presence markers only for version-only checkers, where the strict
		// version match is the sole presence signal.
		if len(rc.ContainsPatterns) == 0 && len(rc.FilenamePatterns) == 0 {
			for _, re := range c.version {
				prefix, _ := re.LiteralPrefix()
				if distinctiveMarker(prefix) {
					c.versionMarkers = append(c.versionMarkers, prefix)
				}
			}
		}

		db.checkers = append(db.checkers, c)
	}
	return db, nil
}

// distinctiveMarker reports whether a literal version-pattern prefix is specific
// enough to use as a presence marker. A bare single word is rejected: it is
// either an ordinary English word (e.g. "unbound", "coreutils") that appears in
// unrelated help text, or too short once whitespace is trimmed. A marker is kept
// only if, after trimming, it still meets the length threshold and contains a
// space (a multi-word phrase like "libevent using: %s" or "GNU Bison ") or a
// non-letter character (a version connector like "coreutils-" or "apr-util-1").
func distinctiveMarker(prefix string) bool {
	s := strings.TrimSpace(prefix)
	if len(s) < presenceMarkerMinLen {
		return false
	}
	for _, r := range s {
		if r == ' ' || !unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// compileAll compiles each pattern, dropping (and counting) any the regexp
// engine rejects. The cve-bin-tool patterns are Python-flavoured but every one
// in the current database compiles under Go's RE2 engine; the counter guards
// against future additions that use unsupported constructs.
func (db *DB) compileAll(pats []string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, p := range pats {
		re, err := regexp.Compile(p)
		if err != nil {
			db.Skipped++
			continue
		}
		out = append(out, re)
	}
	return out
}
