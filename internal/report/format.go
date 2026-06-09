package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
)

// PrintStats writes a human-readable statistics summary to w.
func PrintStats(w io.Writer, r *Result) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Image:\t%s\n", r.ImageRef)
	fmt.Fprintf(tw, "Distro:\t%s\n", r.Distro)
	fmt.Fprintf(tw, "Total files:\t%d\n", r.TotalFiles)
	fmt.Fprintf(tw, "Total size:\t%s\n", humanBytes(r.TotalBytes))
	fmt.Fprintf(tw, "Tracked files:\t%d (%.1f%%)\n", r.TrackedFiles, 100-r.DarkFilePct())
	fmt.Fprintf(tw, "Tracked size:\t%s (%.1f%%)\n", humanBytes(r.TrackedBytes), 100-r.DarkBytesPct())
	fmt.Fprintf(tw, "Dark files:\t%d (%.1f%%)\n", r.DarkCount(), r.DarkFilePct())
	fmt.Fprintf(tw, "Dark size:\t%s (%.1f%%)\n", humanBytes(r.DarkBytes()), r.DarkBytesPct())
	tw.Flush()
}

// PrintJSON writes stats as JSON to w.
func PrintJSON(w io.Writer, r *Result) error {
	out := map[string]interface{}{
		"image":           r.ImageRef,
		"distro":          r.Distro,
		"total_files":     r.TotalFiles,
		"total_bytes":     r.TotalBytes,
		"tracked_files":   r.TrackedFiles,
		"tracked_bytes":   r.TrackedBytes,
		"dark_files":      r.DarkCount(),
		"dark_bytes":      r.DarkBytes(),
		"dark_file_pct":   r.DarkFilePct(),
		"dark_bytes_pct":  r.DarkBytesPct(),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// PrintDarkFiles writes a sorted list of dark file paths to w.
func PrintDarkFiles(w io.Writer, r *Result) {
	paths := make([]string, 0, len(r.DarkFiles))
	for _, f := range r.DarkFiles {
		paths = append(paths, f.Path)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintln(w, p)
	}
}

// PrintDarkFilesDetailed writes dark files with sizes to w.
func PrintDarkFilesDetailed(w io.Writer, r *Result) {
	type entry struct {
		path string
		size int64
	}
	entries := make([]entry, 0, len(r.DarkFiles))
	for _, f := range r.DarkFiles {
		entries = append(entries, entry{f.Path, f.Size})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].path < entries[j].path
	})

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\n", e.path, humanBytes(e.size))
	}
	tw.Flush()
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
