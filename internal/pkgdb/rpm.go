package pkgdb

import (
	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

// scanRPM returns file paths tracked by RPM.
// Parsing the RPM BDB/sqlite database requires cgo or external tooling; since
// we want a pure-Go binary without cgo deps, we report an empty set and fall
// back to the best-effort multi-scanner. A future implementation could shell
// out to `rpm -qa --queryformat` if rpm is available inside the image.
func scanRPM(fs *image.ImageFS) (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}
