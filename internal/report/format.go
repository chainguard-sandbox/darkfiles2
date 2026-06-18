package report

import (
	"encoding/json"
	"fmt"
	"io"
	iofs "io/fs"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/chainguard-dev/darkfiles2/internal/image"
)

// categoryOrder controls the display order of categories in stats output.
var categoryOrder = []Category{
	CategoryUnknown,
	CategoryPkgManagerState,
	CategoryRuntimeGenerated,
	CategoryDeviceFile,
	CategoryBuildMetadata,
}

// PrintStats writes a human-readable statistics summary to w, including a
// per-category breakdown of dark files.
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

	// Per-category breakdown.
	bycat := r.ByCategory()
	if len(bycat) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Dark file breakdown:")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, cat := range categoryOrder {
		files := bycat[cat]
		if len(files) == 0 {
			continue
		}
		var sz int64
		for _, f := range files {
			sz += f.Size
		}
		marker := ""
		if cat == CategoryUnknown {
			marker = "  ◀ investigate"
		}
		fmt.Fprintf(tw, "  %s:\t%d files,  %s%s\n", cat.String(), len(files), humanBytes(sz), marker)
	}
	tw.Flush()

	// Highlight executable code among the dark files — the highest-signal subset.
	if code := r.DarkCodeCounts(); len(code) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Dark code:  %s  ◀ investigate\n", formatCodeCounts(code))
	}
}

// codeKindOrder fixes the display order of code kinds in summaries.
var codeKindOrder = []image.FileKind{
	image.KindExecutable,
	image.KindSharedLibrary,
	image.KindScript,
	image.KindStaticLibrary,
}

func formatCodeCounts(counts map[image.FileKind]int) string {
	var parts []string
	for _, k := range codeKindOrder {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, pluralize(k.String(), n)))
		}
	}
	return strings.Join(parts, ", ")
}

func pluralize(s string, n int) string {
	if n == 1 {
		return s
	}
	if strings.HasSuffix(s, "y") {
		return s[:len(s)-1] + "ies" // library -> libraries
	}
	return s + "s"
}

// PrintJSON writes full stats plus per-category counts as JSON to w.
func PrintJSON(w io.Writer, r *Result) error {
	type catSummary struct {
		Count int   `json:"count"`
		Bytes int64 `json:"bytes"`
	}
	cats := map[string]catSummary{}
	for cat, files := range r.ByCategory() {
		var sz int64
		for _, f := range files {
			sz += f.Size
		}
		cats[cat.String()] = catSummary{Count: len(files), Bytes: sz}
	}

	code := map[string]int{}
	for k, n := range r.DarkCodeCounts() {
		code[k.String()] = n
	}

	out := map[string]interface{}{
		"image":          r.ImageRef,
		"distro":         r.Distro,
		"total_files":    r.TotalFiles,
		"total_bytes":    r.TotalBytes,
		"tracked_files":  r.TrackedFiles,
		"tracked_bytes":  r.TrackedBytes,
		"dark_files":     r.DarkCount(),
		"dark_bytes":     r.DarkBytes(),
		"dark_file_pct":  r.DarkFilePct(),
		"dark_bytes_pct": r.DarkBytesPct(),
		"categories":     cats,
		"dark_code":      code,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// PrintDarkFiles writes a sorted list of dark file paths to w, optionally
// grouped by category.
func PrintDarkFiles(w io.Writer, r *Result, grouped bool) {
	if grouped {
		printGrouped(w, r, false)
		return
	}
	paths := sortedPaths(r.DarkFiles)
	for _, p := range paths {
		fmt.Fprintln(w, p)
	}
}

// PrintDarkFilesDetailed writes dark files with sizes to w, optionally grouped.
func PrintDarkFilesDetailed(w io.Writer, r *Result, grouped bool) {
	if grouped {
		printGrouped(w, r, true)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range sortedFiles(r.DarkFiles) {
		fmt.Fprintf(tw, "%s\t%s%s\n", f.Path, humanBytes(f.Size), kindTag(f))
	}
	tw.Flush()
}

// kindTag returns a "  [executable]" style suffix for code files, else "".
func kindTag(f CategorizedFile) string {
	if f.Kind.IsCode() {
		return "  [" + f.Kind.String() + "]"
	}
	return ""
}

func printGrouped(w io.Writer, r *Result, detailed bool) {
	bycat := r.ByCategory()
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, cat := range categoryOrder {
		files := bycat[cat]
		if len(files) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n── %s (%d) ──\n", cat.String(), len(files))
		for _, f := range sortedFiles(files) {
			if detailed {
				fmt.Fprintf(tw, "  %s\t%s%s\n", f.Path, humanBytes(f.Size), kindTag(f))
			} else {
				fmt.Fprintln(w, " ", f.Path)
			}
		}
		if detailed {
			tw.Flush()
		}
	}
}

// PrintByLayer writes files grouped by the image layer (Dockerfile instruction)
// that introduced them, with size and mode. When showCat is true, each file is
// tagged with its category — useful when the selection mixes expected and
// unexpected dark files.
func PrintByLayer(w io.Writer, layers []image.Layer, files []CategorizedFile, showCat, color bool) {
	byLayer := map[int][]CategorizedFile{}
	for _, f := range files {
		byLayer[f.LayerIndex] = append(byLayer[f.LayerIndex], f)
	}

	idxs := make([]int, 0, len(byLayer))
	for idx := range byLayer {
		idxs = append(idxs, idx)
	}
	sort.Ints(idxs)

	for _, lIdx := range idxs {
		lf := byLayer[lIdx]

		cmd := fmt.Sprintf("layer %d", lIdx)
		diffID := ""
		if lIdx >= 0 && lIdx < len(layers) {
			cmd = layers[lIdx].Command()
			diffID = shortDigest(layers[lIdx].DiffID)
		}

		fmt.Fprintf(w, "\n┌─ Layer %d", lIdx)
		if diffID != "" {
			fmt.Fprintf(w, " [%s]", diffID)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "│  %s\n", cmd)
		fmt.Fprintf(w, "│  %d file(s)\n", len(lf))
		fmt.Fprintln(w, "│")

		// StripEscape lets us wrap ANSI colour codes so tabwriter ignores their
		// width and columns stay aligned.
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.StripEscape)
		for _, f := range sortedFiles(lf) {
			tag := kindTag(f)
			if showCat {
				tag += fmt.Sprintf("  [%s]", f.Cat)
			}
			path, size, mode := f.Path, humanBytes(f.Size), formatMode(f.File)
			if color && f.Kind.IsCode() {
				path = paint(codeColor, path)
				size = paint(codeColor, size)
				mode = paint(codeColor, mode)
				tag = paint(codeColor, tag)
			}
			fmt.Fprintf(tw, "│  ├── %s\t%s\t%s%s\n", path, size, mode, tag)
		}
		tw.Flush()
		fmt.Fprintln(w, "└"+strings.Repeat("─", 60))
	}
}

const (
	codeColor = "\033[1;31m" // bold red
	ansiReset = "\033[0m"
)

// paint wraps s in an ANSI colour, bracketing the escape sequences with
// tabwriter.Escape (\xff) bytes so the formatter does not count them toward
// column width. Used only with a tabwriter created with tabwriter.StripEscape.
func paint(code, s string) string {
	if s == "" {
		return s
	}
	esc := string([]byte{tabwriter.Escape})
	return esc + code + esc + s + esc + ansiReset + esc
}

func shortDigest(d string) string {
	s := strings.TrimPrefix(d, "sha256:")
	if len(s) > 12 {
		s = s[:12]
	}
	return s
}

func formatMode(f image.File) string {
	if f.IsSymlink {
		return fmt.Sprintf("-> %s", f.LinkTarget)
	}
	return iofs.FileMode(f.Mode).String()
}

func sortedPaths(files []CategorizedFile) []string {
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.Path
	}
	sort.Strings(paths)
	return paths
}

func sortedFiles(files []CategorizedFile) []CategorizedFile {
	out := make([]CategorizedFile, len(files))
	copy(out, files)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
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
