package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/chainguard-sandbox/darkfiles2/internal/libdetect"
)

// FileDetections pairs a scanned file with the libraries detected in it.
type FileDetections struct {
	Path       string
	Detections []libdetect.Detection
}

// PrintDetections writes a human-readable report of detected libraries,
// grouped by file. Files with no detections are omitted from the per-file
// listing but counted in the trailing summary. results is sorted by path.
func PrintDetections(w io.Writer, results []FileDetections) {
	sorted := make([]FileDetections, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	withHits := 0
	for _, r := range sorted {
		if len(r.Detections) == 0 {
			continue
		}
		withHits++
		fmt.Fprintf(w, "\n%s\n", sanitize(r.Path))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, d := range r.Detections {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
				sanitize(d.Library),
				sanitize(strings.Join(d.Versions, ", ")),
				sanitize(vendors(d.VendorProducts)),
				evidence(d.Evidence),
			)
		}
		tw.Flush()
	}

	fmt.Fprintf(w, "\nScanned %d file(s); %d with detected libraries.\n", len(sorted), withHits)
}

// PrintDetectionsJSON writes the library-detection results as JSON to w.
func PrintDetectionsJSON(w io.Writer, results []FileDetections) error {
	sorted := make([]FileDetections, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	type fileOut struct {
		Path       string                `json:"path"`
		Detections []libdetect.Detection `json:"detections"`
	}
	files := make([]fileOut, 0, len(sorted))
	for _, r := range sorted {
		dets := r.Detections
		if dets == nil {
			dets = []libdetect.Detection{}
		}
		files = append(files, fileOut{Path: r.Path, Detections: dets})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]interface{}{"files": files})
}

// vendors joins the distinct vendor names of a detection, preserving order.
func vendors(vps []libdetect.VendorProduct) string {
	seen := map[string]bool{}
	var out []string
	for _, vp := range vps {
		if vp.Vendor == "" || seen[vp.Vendor] {
			continue
		}
		seen[vp.Vendor] = true
		out = append(out, vp.Vendor)
	}
	return strings.Join(out, ", ")
}

// evidence renders which signals matched (contents, filename, or both).
func evidence(e libdetect.Evidence) string {
	var parts []string
	if e.MatchedContents {
		parts = append(parts, "contents")
	}
	if e.MatchedFilename {
		parts = append(parts, "filename")
	}
	return strings.Join(parts, "+")
}
