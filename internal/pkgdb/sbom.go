package pkgdb

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/chainguard-dev/darkfiles2/internal/image"
)

// trackedFromSBOM returns the file paths tracked by SBOMs. When path is set it
// reads that external SPDX JSON file (a parse failure there is fatal, since the
// user asked for it explicitly); otherwise it discovers SBOMs embedded in the
// image under /var/lib/db/sbom/.
func trackedFromSBOM(fs *image.ImageFS, path string) (map[string]struct{}, error) {
	if path == "" {
		return scanSBOM(fs)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tracked := map[string]struct{}{}
	if err := parseSPDX(data, tracked); err != nil {
		return nil, err
	}
	return tracked, nil
}

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
