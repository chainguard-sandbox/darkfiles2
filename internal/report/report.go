package report

import (
	"github.com/chainguard-dev/darkfiles2/internal/image"
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
	DarkFiles []CategorizedFile
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
