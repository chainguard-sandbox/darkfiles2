package report

import (
	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

// CategorizedFile is a dark file with its assigned category.
type CategorizedFile struct {
	image.File
	Cat Category
}

// Result holds the analysis output for an image.
type Result struct {
	ImageRef     string
	Distro       string
	TotalFiles   int
	TotalBytes   int64
	TrackedFiles int
	TrackedBytes int64
	// DarkFiles contains every untracked file, each tagged with a category.
	// When an SBOM has been applied (see ApplySBOM), files the SBOM documents
	// are moved out of this slice and into SBOMFiles, so they no longer count
	// as dark.
	DarkFiles []CategorizedFile
	// SBOMFiles holds the untracked files that the image's SBOM documents. They
	// are accounted for by the SBOM and therefore excluded from the dark set.
	// Only populated after ApplySBOM.
	SBOMFiles []CategorizedFile
	// SBOMChecked is true once ApplySBOM has run, enabling the "In SBOM" summary
	// line even when nothing matched.
	SBOMChecked bool
	// GoFiles holds the untracked files identified as Go binaries with embedded
	// build info (plus symlinks resolving to them). Scanners read that metadata
	// directly, so these are excluded from the dark set. Only populated after
	// ApplyGoBinaries.
	GoFiles []CategorizedFile
	// GoChecked is true once ApplyGoBinaries has run.
	GoChecked bool
}

func (r *Result) DarkCount() int { return len(r.DarkFiles) }

func (r *Result) DarkBytes() int64 {
	var n int64
	for _, f := range r.DarkFiles {
		n += f.Size
	}
	return n
}

func (r *Result) DarkFilePct() float64 {
	if r.TotalFiles == 0 {
		return 0
	}
	return 100.0 * float64(r.DarkCount()) / float64(r.TotalFiles)
}

func (r *Result) DarkBytesPct() float64 {
	if r.TotalBytes == 0 {
		return 0
	}
	return 100.0 * float64(r.DarkBytes()) / float64(r.TotalBytes)
}

// UnknownFiles returns only the dark files in CategoryUnknown — the ones that
// genuinely warrant investigation.
func (r *Result) UnknownFiles() []CategorizedFile {
	var out []CategorizedFile
	for _, f := range r.DarkFiles {
		if f.Cat == CategoryUnknown {
			out = append(out, f)
		}
	}
	return out
}

// ApplySBOM removes from the dark set every untracked file whose path the image's
// SBOM documents, moving it into SBOMFiles. Such files are not tracked by the
// package database but are accounted for by the SBOM, so they should not count
// as dark. It records that the cross-reference ran so the summary can report on
// it even when nothing matched.
func (r *Result) ApplySBOM(paths map[string]struct{}) {
	r.SBOMChecked = true
	var dark []CategorizedFile
	for _, f := range r.DarkFiles {
		if _, ok := paths[f.Path]; ok {
			r.SBOMFiles = append(r.SBOMFiles, f)
		} else {
			dark = append(dark, f)
		}
	}
	r.DarkFiles = dark
}

// GoCandidates returns the files to inspect for Go build info: the dark
// regular executables and shared libraries, plus everything along the link
// chain of each dark symlink or hard link (see ApplyGoBinaries). A chain is
// followed through any mix of symlinks and hard links, with cycle protection:
// every hard link on it is inspected, as it carries its target's content as of
// when it was linked; so is its final target if that is a regular executable or
// library — or, when the chain passed through a hard link, any final target,
// since its content at link time may differ from what is there now. Targets
// keep their own bucket; only the dark aliases are affected.
func (r *Result) GoCandidates(fs *image.ImageFS) map[string]bool {
	want := map[string]bool{}
	var files map[string]image.File
	for _, f := range r.DarkFiles {
		if !isLink(f.File) {
			if isBinaryKind(f.Kind) {
				want[f.Path] = true
			}
			continue
		}
		if files == nil {
			files = fileIndex(fs)
		}
		viaHardLink := false
		walkLinkChain(f.Path, fs, files, func(p string) bool {
			file, ok := files[p]
			switch {
			case ok && file.HardLinkTarget != "":
				want[p] = true
				viaHardLink = true
				return true // keep following
			case viaHardLink, ok && isBinaryKind(file.Kind):
				want[p] = true
			}
			return false
		})
	}
	return want
}

// ApplyGoBinaries moves into GoFiles every dark file found to be a Go binary.
// results holds the inspection outcome per path (from GoCandidates' selection):
// a regular file is judged by its own result; a symlink by the file it resolves
// to; and a hard link by its own result — its content as of when it was linked,
// unaffected by later replacement or deletion of its target — falling back to
// following the link only when no content was captured for it (e.g. it links to
// a symlink). Chains of mixed links are followed with cycle protection. Targets
// outside the dark set keep their bucket; only their dark aliases move.
func (r *Result) ApplyGoBinaries(results map[string]bool, fs *image.ImageFS) {
	r.GoChecked = true
	var files map[string]image.File
	var dark []CategorizedFile
	for _, f := range r.DarkFiles {
		isGo, inspected := results[f.Path]
		if !inspected && isLink(f.File) {
			if files == nil {
				files = fileIndex(fs)
			}
			walkLinkChain(f.Path, fs, files, func(p string) bool {
				var ok bool
				isGo, ok = results[p]
				return !ok // no result here: keep following if p is a hard link
			})
		}
		if isGo {
			r.GoFiles = append(r.GoFiles, f)
		} else {
			dark = append(dark, f)
		}
	}
	r.DarkFiles = dark
}

// walkLinkChain follows path through symlinks (resolved via fs.ResolveSymlink,
// including symlinked parent directories) and hard links. visit is called on
// each non-symlink path reached; when it returns true and the path is a hard
// link, the walk continues to the link's target. A path seen twice ends the walk.
func walkLinkChain(path string, fs *image.ImageFS, files map[string]image.File, visit func(p string) bool) {
	seen := map[string]bool{}
	for !seen[path] {
		seen[path] = true
		if resolved := fs.ResolveSymlink(path); resolved != path {
			path = resolved
			continue
		}
		if !visit(path) {
			return
		}
		f, ok := files[path]
		if !ok || f.HardLinkTarget == "" {
			return
		}
		path = f.HardLinkTarget
	}
}

func isLink(f image.File) bool { return f.IsSymlink || f.HardLinkTarget != "" }

func isBinaryKind(k image.FileKind) bool {
	return k == image.KindExecutable || k == image.KindSharedLibrary
}

func fileIndex(fs *image.ImageFS) map[string]image.File {
	m := make(map[string]image.File, len(fs.Files))
	for _, f := range fs.Files {
		m[f.Path] = f
	}
	return m
}

// GoCount returns the number of files accounted for as Go binaries.
func (r *Result) GoCount() int { return len(r.GoFiles) }

// GoBytes returns the total size of the files accounted for as Go binaries.
func (r *Result) GoBytes() int64 { return sumBytes(r.GoFiles) }

// GoFilePct returns the Go binary files as a percentage of all files.
func (r *Result) GoFilePct() float64 { return pct(int64(r.GoCount()), int64(r.TotalFiles)) }

// GoBytesPct returns the Go binary bytes as a percentage of all bytes.
func (r *Result) GoBytesPct() float64 { return pct(r.GoBytes(), r.TotalBytes) }

func sumBytes(files []CategorizedFile) int64 {
	var n int64
	for _, f := range files {
		n += f.Size
	}
	return n
}

func pct(n, total int64) float64 {
	if total == 0 {
		return 0
	}
	return 100.0 * float64(n) / float64(total)
}

// SBOMCount returns the number of files accounted for by the SBOM (i.e. moved
// out of the dark set).
func (r *Result) SBOMCount() int { return len(r.SBOMFiles) }

// SBOMBytes returns the total size of the files accounted for by the SBOM.
func (r *Result) SBOMBytes() int64 {
	var n int64
	for _, f := range r.SBOMFiles {
		n += f.Size
	}
	return n
}

// SBOMFilePct returns the SBOM-accounted files as a percentage of all files.
func (r *Result) SBOMFilePct() float64 {
	if r.TotalFiles == 0 {
		return 0
	}
	return 100.0 * float64(r.SBOMCount()) / float64(r.TotalFiles)
}

// SBOMBytesPct returns the SBOM-accounted bytes as a percentage of all bytes.
func (r *Result) SBOMBytesPct() float64 {
	if r.TotalBytes == 0 {
		return 0
	}
	return 100.0 * float64(r.SBOMBytes()) / float64(r.TotalBytes)
}

// TrackedFilePct returns package-tracked files as a percentage of all files.
func (r *Result) TrackedFilePct() float64 {
	if r.TotalFiles == 0 {
		return 0
	}
	return 100.0 * float64(r.TrackedFiles) / float64(r.TotalFiles)
}

// TrackedBytesPct returns package-tracked bytes as a percentage of all bytes.
func (r *Result) TrackedBytesPct() float64 {
	if r.TotalBytes == 0 {
		return 0
	}
	return 100.0 * float64(r.TrackedBytes) / float64(r.TotalBytes)
}

// DarkCodeCounts counts dark files that are executable code, keyed by kind.
func (r *Result) DarkCodeCounts() map[image.FileKind]int {
	m := map[image.FileKind]int{}
	for _, f := range r.DarkFiles {
		if f.Kind.IsCode() {
			m[f.Kind]++
		}
	}
	return m
}

// ByCategory returns dark files grouped by category.
func (r *Result) ByCategory() map[Category][]CategorizedFile {
	m := map[Category][]CategorizedFile{}
	for _, f := range r.DarkFiles {
		m[f.Cat] = append(m[f.Cat], f)
	}
	return m
}

// Analyze builds a Result from the image filesystem and tracked-file set.
// Symlinks whose fully-resolved target is tracked are also considered tracked,
// enabling correct handling of merged-usr layouts (e.g. /bin → /usr/bin) and
// busybox multi-call installations.
func Analyze(ref, distro string, fs *image.ImageFS, tracked map[string]struct{}) *Result {
	r := &Result{
		ImageRef: ref,
		Distro:   distro,
	}
	tracked = canonicalizeTracked(tracked, fs)
	for _, f := range fs.Files {
		r.TotalFiles++
		r.TotalBytes += f.Size
		if isTracked(f, tracked, fs) {
			r.TrackedFiles++
			r.TrackedBytes += f.Size
		} else {
			r.DarkFiles = append(r.DarkFiles, CategorizedFile{
				File: f,
				Cat:  Classify(f),
			})
		}
	}
	return r
}

// canonicalizeTracked returns a tracked set augmented with the symlink-resolved
// form of every path. Package databases often record a file under a path that
// runs through a symlinked directory — e.g. APK records libffi under
// /usr/lib64/... while /usr/lib64 -> lib, so the real file lives at /usr/lib/...
// Resolving each tracked path lets the canonical on-disk file match. Both the
// original and resolved spellings are kept so direct matches still work.
func canonicalizeTracked(tracked map[string]struct{}, fs *image.ImageFS) map[string]struct{} {
	out := make(map[string]struct{}, len(tracked)*2)
	for p := range tracked {
		out[p] = struct{}{}
		if resolved := fs.ResolveSymlink(p); resolved != p {
			out[resolved] = struct{}{}
		}
	}
	return out
}

func isTracked(f image.File, tracked map[string]struct{}, fs *image.ImageFS) bool {
	// Direct match.
	if _, ok := tracked[f.Path]; ok {
		return true
	}
	// For symlinks, follow the full chain (handles merged-usr, busybox multi-call, etc.)
	if f.IsSymlink {
		resolved := fs.ResolveSymlink(f.Path)
		if _, ok := tracked[resolved]; ok {
			return true
		}
	}
	return false
}
