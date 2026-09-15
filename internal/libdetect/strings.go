package libdetect

import "strings"

// DefaultMinLength is the default minimum printable-run length for string
// extraction, matching cve-bin-tool / darkrustmaster.
const DefaultMinLength = 3

// extractStrings returns printable-character runs from data, joined by '\n'.
// Bytes in the range 32..=127 plus tab (9) are "printable"; maximal runs of at
// least minLen such bytes are emitted. The newline join is load-bearing: many
// version regexes anchor on \r?\n between adjacent strings.
func extractStrings(data []byte, minLen int) string {
	var b strings.Builder
	b.Grow(len(data))
	start := -1
	wrote := false
	flush := func(run []byte) {
		if wrote {
			b.WriteByte('\n')
		}
		b.Write(run)
		wrote = true
	}
	for i, c := range data {
		printable := (c >= 32 && c <= 127) || c == 9
		if printable {
			if start < 0 {
				start = i
			}
		} else if start >= 0 {
			if i-start >= minLen {
				flush(data[start:i])
			}
			start = -1
		}
	}
	if start >= 0 && len(data)-start >= minLen {
		flush(data[start:])
	}
	return b.String()
}
