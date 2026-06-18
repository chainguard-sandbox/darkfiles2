package pkgdb

import (
	"encoding/json"
	"strings"

	"github.com/chainguard-dev/darkfiles2/internal/image"
)

// scanSBOM reads any SPDX JSON SBOMs embedded in the image (e.g. the per-package
// SBOMs that apko writes to /var/lib/db/sbom/*.spdx.json) and returns all file
// paths they reference.  This supplements — but does not replace — the package
// manager database scan.
func scanSBOM(fs *image.ImageFS) (map[string]struct{}, error) {
	tracked := map[string]struct{}{}

	for path, data := range fs.FileContent {
		if !strings.HasPrefix(path, "/var/lib/db/sbom/") {
			continue
		}
		if err := parseSPDX(data, tracked); err != nil {
			// Non-fatal: skip malformed files.
			continue
		}
	}

	return tracked, nil
}

// spdxDoc is a minimal representation of an SPDX 2.x JSON document — just enough
// to extract the file names referenced in the packages.
type spdxDoc struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"versionInfo"`
	} `json:"packages"`
	Files []struct {
		FileName string `json:"fileName"`
	} `json:"files"`
	Relationships []struct {
		RelationshipType string `json:"relationshipType"`
		RelatedElement   string `json:"relatedSpdxElement"`
		SpdxElementID    string `json:"spdxElementId"`
	} `json:"relationships"`
}

func parseSPDX(data []byte, tracked map[string]struct{}) error {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	for _, f := range doc.Files {
		name := f.FileName
		if !strings.HasPrefix(name, "/") {
			name = "/" + strings.TrimPrefix(name, "./")
		}
		tracked[name] = struct{}{}
	}
	return nil
}
