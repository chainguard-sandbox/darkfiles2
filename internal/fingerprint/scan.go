package fingerprint

import (
	"regexp"
	"sort"
	"strings"
)

// Unknown is the reported version when a library is present but no version can
// be parsed.
const Unknown = "UNKNOWN"

// Detection is one library found in a scanned file.
type Detection struct {
	// Library is the checker's product name; the primary key users care about.
	Library string `json:"library"`
	// Versions are the detected versions (sorted). ["UNKNOWN"] if presence-only.
	Versions []string `json:"versions"`
	// VendorProducts is every vendor/product pair the checker maps to.
	VendorProducts []VendorProduct `json:"vendor_products"`
	Evidence       Evidence        `json:"evidence"`
}

// Evidence records what matched: file contents, the file name, or both.
type Evidence struct {
	MatchedContents bool `json:"matched_contents"`
	MatchedFilename bool `json:"matched_filename"`
}

// Fingerprint extracts printable strings from data and returns every library
// detected in it. filename is used only when useFilename is true. minLen bounds
// the printable-run length (use DefaultMinLength for the standard behaviour).
func (db *DB) Fingerprint(data []byte, filename string, minLen int, useFilename bool) []Detection {
	blob := extractStrings(data, minLen)
	return db.scan(blob, filename, useFilename)
}

// scan runs every checker against the extracted string blob (and, optionally,
// the file name), returning detections sorted by library name.
func (db *DB) scan(blob, filename string, useFilename bool) []Detection {
	var dets []Detection
	for i := range db.checkers {
		if d, ok := db.checkers[i].detect(blob, filename, useFilename); ok {
			dets = append(dets, d)
		}
	}
	sort.Slice(dets, func(i, j int) bool { return dets[i].Library < dets[j].Library })
	return dets
}

// detect runs one checker against the blob and file name. It mirrors
// cve-bin-tool's Checker.get_versions:
//   - presence = a CONTAINS/VERSION pattern is found in the blob (and, if
//     enabled, a FILENAME pattern matches the file name at position 0);
//   - versions = capture group 1 of each VERSION pattern, trimmed, with '_'/'-'
//     rewritten to '.'; the whole match is what's tested against IGNORE patterns;
//   - present but no version parsed -> UNKNOWN.
func (c *checker) detect(blob, filename string, useFilename bool) (Detection, bool) {
	matchedContents := anyMatch(c.contains, blob) || anyMatch(c.version, blob)
	matchedFilename := useFilename && anyMatchAtStart(c.filename, filename)

	// Presence fallback: for version-only checkers whose anchored version pattern
	// didn't match, a literal marker string still indicates the library is present
	// (version reported as UNKNOWN).
	if !matchedContents && anySubstr(c.versionMarkers, blob) {
		matchedContents = true
	}

	if !matchedContents && !matchedFilename {
		return Detection{}, false
	}

	seen := map[string]struct{}{}
	for _, re := range c.version {
		for _, m := range re.FindAllStringSubmatch(blob, -1) {
			whole := m[0]
			if anyMatch(c.ignore, whole) {
				continue
			}
			if len(m) < 2 {
				continue
			}
			v := strings.TrimSpace(m[1])
			v = strings.ReplaceAll(v, "_", ".")
			v = strings.ReplaceAll(v, "-", ".")
			if v != "" {
				seen[v] = struct{}{}
			}
		}
	}

	versions := make([]string, 0, len(seen))
	for v := range seen {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	if len(versions) == 0 {
		versions = []string{Unknown}
	}

	library := c.name
	if len(c.vendorProduct) > 0 {
		library = c.vendorProduct[0].Product
	}

	return Detection{
		Library:        library,
		Versions:       versions,
		VendorProducts: c.vendorProduct,
		Evidence: Evidence{
			MatchedContents: matchedContents,
			MatchedFilename: matchedFilename,
		},
	}, true
}

// anyMatch reports whether any pattern matches anywhere in text (re.search).
func anyMatch(res []*regexp.Regexp, text string) bool {
	for _, re := range res {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// anySubstr reports whether any marker is a literal substring of text.
func anySubstr(markers []string, text string) bool {
	for _, m := range markers {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}

// anyMatchAtStart reports whether any pattern matches at position 0 (re.match).
func anyMatchAtStart(res []*regexp.Regexp, text string) bool {
	for _, re := range res {
		if loc := re.FindStringIndex(text); loc != nil && loc[0] == 0 {
			return true
		}
	}
	return false
}
