package libdetect

import (
	"regexp"
	"sort"
	"strings"
)

// Unknown is the reported version when a library is present but no version can
// be parsed.
const Unknown = "UNKNOWN"

// Detection is one library found in a scanned file. Detection is always based on
// the file's contents (extracted strings); there is no filename-based matching.
type Detection struct {
	// Library is the checker's product name; the primary key users care about.
	Library string `json:"library"`
	// Versions are the detected versions (sorted). ["UNKNOWN"] if presence-only.
	Versions []string `json:"versions"`
	// VendorProducts is every vendor/product pair the checker maps to.
	VendorProducts []VendorProduct `json:"vendor_products"`
}

// Detect extracts printable strings from data and returns every library detected
// in its contents. minLen bounds the printable-run length (use DefaultMinLength
// for the standard behaviour).
func (db *DB) Detect(data []byte, minLen int) []Detection {
	blob := extractStrings(data, minLen)
	return db.scan(blob)
}

// scan runs every checker against the extracted string blob, returning
// detections sorted by library name.
func (db *DB) scan(blob string) []Detection {
	var dets []Detection
	for i := range db.checkers {
		if d, ok := db.checkers[i].detect(blob); ok {
			dets = append(dets, d)
		}
	}
	sort.Slice(dets, func(i, j int) bool { return dets[i].Library < dets[j].Library })
	return dets
}

// detect runs one checker against the blob. It mirrors cve-bin-tool's
// Checker.get_versions:
//   - presence = a CONTAINS match when CONTAINS patterns exist, otherwise a
//     VERSION match (or the version-only marker fallback) is found in the blob;
//   - versions = capture group 1 of each VERSION pattern, trimmed, with '_'/'-'
//     rewritten to '.'; the whole match is what's tested against IGNORE patterns;
//   - present but no version parsed -> UNKNOWN.
func (c *checker) detect(blob string) (Detection, bool) {
	var matched bool
	if len(c.contains) > 0 {
		// When a checker carries CONTAINS patterns, those are its strong presence
		// signal; a VERSION pattern matching alone is not enough. VERSION patterns
		// are often loose and match mere *references* to a library — e.g. node's
		// "https://nodejs.org/download/release/vX.Y.Z/" download URL, which any
		// Node-compatible runtime (deno, bun) embeds without being the node runtime.
		// Requiring a CONTAINS match here keeps those references from registering as
		// presence while the VERSION patterns still supply the version below.
		matched = anyMatch(c.contains, blob)
	} else {
		matched = anyMatch(c.version, blob)

		// Presence fallback: for version-only checkers whose anchored version pattern
		// didn't match, a literal marker string still indicates the library is present
		// (version reported as UNKNOWN). Only version-only checkers populate
		// versionMarkers (see loadFrom), so this never applies to CONTAINS checkers.
		if !matched && anySubstr(c.versionMarkers, blob) {
			matched = true
		}
	}

	if !matched {
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
