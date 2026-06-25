package report

import (
	"math"
	"testing"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

func newFS(files []image.File, symlinks map[string]string) *image.ImageFS {
	if symlinks == nil {
		symlinks = map[string]string{}
	}
	return &image.ImageFS{Files: files, Symlinks: symlinks}
}

func TestAnalyzeBasic(t *testing.T) {
	files := []image.File{
		{Path: "/usr/bin/curl", Size: 100}, // tracked
		{Path: "/lib/libc.so", Size: 200},  // tracked
		{Path: "/app/server", Size: 50},    // dark, unknown
		{Path: "/etc/passwd", Size: 10},    // dark, runtime
	}
	tracked := map[string]struct{}{
		"/usr/bin/curl": {},
		"/lib/libc.so":  {},
	}
	r := Analyze("img:latest", "wolfi", newFS(files, nil), tracked)

	if r.ImageRef != "img:latest" || r.Distro != "wolfi" {
		t.Errorf("metadata not propagated: %+v", r)
	}
	if r.TotalFiles != 4 {
		t.Errorf("TotalFiles = %d, want 4", r.TotalFiles)
	}
	if r.TotalBytes != 360 {
		t.Errorf("TotalBytes = %d, want 360", r.TotalBytes)
	}
	if r.TrackedFiles != 2 {
		t.Errorf("TrackedFiles = %d, want 2", r.TrackedFiles)
	}
	if r.TrackedBytes != 300 {
		t.Errorf("TrackedBytes = %d, want 300", r.TrackedBytes)
	}
	if r.DarkCount() != 2 {
		t.Errorf("DarkCount() = %d, want 2", r.DarkCount())
	}
	if r.DarkBytes() != 60 {
		t.Errorf("DarkBytes() = %d, want 60", r.DarkBytes())
	}
}

func TestAnalyzeSymlinkTracked(t *testing.T) {
	// /bin -> /usr/bin (merged-usr); /bin/sh is a symlink whose resolved target
	// /usr/bin/busybox is tracked, so /bin/sh must be counted as tracked.
	files := []image.File{
		{Path: "/usr/bin/busybox", Size: 1000},
		{Path: "/bin/sh", Size: 0, IsSymlink: true, LinkTarget: "busybox"},
	}
	symlinks := map[string]string{
		"/bin":        "/usr/bin",
		"/bin/sh":     "busybox",
		"/usr/bin/sh": "busybox",
	}
	tracked := map[string]struct{}{
		"/usr/bin/busybox": {},
	}
	r := Analyze("img", "wolfi", newFS(files, symlinks), tracked)
	if r.DarkCount() != 0 {
		t.Errorf("DarkCount() = %d, want 0 (symlink to tracked target should be tracked); dark: %+v", r.DarkCount(), r.DarkFiles)
	}
}

// Regression: APK records libffi's files under /usr/lib64/... but /usr/lib64 is
// a symlink to lib, so the real (non-symlink) files live at /usr/lib/... They
// must be counted as tracked, not flagged dark. See cgr.dev cephcsi image.
func TestAnalyzeTrackedPathThroughSymlinkedDir(t *testing.T) {
	files := []image.File{
		// Real file at the canonical location — NOT a symlink itself.
		{Path: "/usr/lib/libffi.so.8.2.0", Size: 57000},
		// Versioned dev/runtime symlinks pointing at the real file.
		{Path: "/usr/lib/libffi.so.8", IsSymlink: true, LinkTarget: "libffi.so.8.2.0"},
		{Path: "/usr/lib/libffi.so", IsSymlink: true, LinkTarget: "libffi.so.8.2.0"},
	}
	// /usr/lib64 -> lib is the directory symlink that causes the spelling
	// mismatch between the APK db and the on-disk paths.
	symlinks := map[string]string{
		"/usr/lib64":           "lib",
		"/usr/lib/libffi.so.8": "libffi.so.8.2.0",
		"/usr/lib/libffi.so":   "libffi.so.8.2.0",
	}
	// APK db spelling: everything under the symlinked /usr/lib64.
	tracked := map[string]struct{}{
		"/usr/lib64/libffi.so.8.2.0": {},
		"/usr/lib64/libffi.so.8":     {},
		"/usr/lib64/libffi.so":       {},
	}

	r := Analyze("img", "wolfi", newFS(files, symlinks), tracked)

	for _, f := range r.DarkFiles {
		t.Errorf("expected no dark files, but %q (%v) was flagged", f.Path, f.Cat)
	}
	if r.TrackedFiles != 3 {
		t.Errorf("TrackedFiles = %d, want 3 (all libffi files)", r.TrackedFiles)
	}
}

func TestResultPercentages(t *testing.T) {
	r := &Result{
		TotalFiles: 4,
		TotalBytes: 1000,
		DarkFiles: []CategorizedFile{
			{File: image.File{Path: "/a", Size: 100}, Cat: CategoryUnknown},
		},
	}
	if got := r.DarkFilePct(); !approx(got, 25.0) {
		t.Errorf("DarkFilePct() = %v, want 25", got)
	}
	if got := r.DarkBytesPct(); !approx(got, 10.0) {
		t.Errorf("DarkBytesPct() = %v, want 10", got)
	}
}

func TestResultPercentagesZeroDivision(t *testing.T) {
	r := &Result{}
	if got := r.DarkFilePct(); got != 0 {
		t.Errorf("DarkFilePct() with no files = %v, want 0", got)
	}
	if got := r.DarkBytesPct(); got != 0 {
		t.Errorf("DarkBytesPct() with no bytes = %v, want 0", got)
	}
}

func TestUnknownFilesAndByCategory(t *testing.T) {
	r := &Result{
		DarkFiles: []CategorizedFile{
			{File: image.File{Path: "/app/x"}, Cat: CategoryUnknown},
			{File: image.File{Path: "/etc/passwd"}, Cat: CategoryRuntimeGenerated},
			{File: image.File{Path: "/app/y"}, Cat: CategoryUnknown},
			{File: image.File{Path: "/dev/null"}, Cat: CategoryDeviceFile},
		},
	}
	unknown := r.UnknownFiles()
	if len(unknown) != 2 {
		t.Errorf("UnknownFiles() = %d, want 2", len(unknown))
	}
	for _, f := range unknown {
		if f.Cat != CategoryUnknown {
			t.Errorf("UnknownFiles() returned non-unknown: %+v", f)
		}
	}

	grouped := r.ByCategory()
	if len(grouped[CategoryUnknown]) != 2 {
		t.Errorf("ByCategory()[Unknown] = %d, want 2", len(grouped[CategoryUnknown]))
	}
	if len(grouped[CategoryRuntimeGenerated]) != 1 {
		t.Errorf("ByCategory()[Runtime] = %d, want 1", len(grouped[CategoryRuntimeGenerated]))
	}
	if len(grouped[CategoryDeviceFile]) != 1 {
		t.Errorf("ByCategory()[Device] = %d, want 1", len(grouped[CategoryDeviceFile]))
	}
}

func TestApplySBOM(t *testing.T) {
	r := &Result{
		TotalFiles: 3,
		TotalBytes: 180,
		DarkFiles: []CategorizedFile{
			{File: image.File{Path: "/usr/local/bin/vault", Size: 100}, Cat: CategoryUnknown},
			{File: image.File{Path: "/app/mystery", Size: 50}, Cat: CategoryUnknown},
			{File: image.File{Path: "/usr/bin/tini", Size: 30}, Cat: CategoryUnknown},
		},
	}
	if r.SBOMChecked {
		t.Fatal("SBOMChecked should be false before ApplySBOM")
	}

	r.ApplySBOM(map[string]struct{}{
		"/usr/local/bin/vault": {},
		"/usr/bin/tini":        {},
		"/not/in/image":        {}, // SBOM path with no matching dark file
	})

	if !r.SBOMChecked {
		t.Error("SBOMChecked should be true after ApplySBOM")
	}
	// Matched files are moved out of the dark set.
	if got := r.SBOMCount(); got != 2 {
		t.Errorf("SBOMCount() = %d, want 2", got)
	}
	if got := r.SBOMBytes(); got != 130 {
		t.Errorf("SBOMBytes() = %d, want 130", got)
	}
	if got := r.DarkCount(); got != 1 {
		t.Errorf("DarkCount() = %d, want 1 (SBOM files excluded)", got)
	}
	if got := r.DarkBytes(); got != 50 {
		t.Errorf("DarkBytes() = %d, want 50", got)
	}
	if len(r.DarkFiles) != 1 || r.DarkFiles[0].Path != "/app/mystery" {
		t.Errorf("DarkFiles should be only /app/mystery, got %+v", r.DarkFiles)
	}
	if len(r.SBOMFiles) != 2 {
		t.Fatalf("SBOMFiles has %d, want 2", len(r.SBOMFiles))
	}
}

func TestApplySBOMEmptyStillRecorded(t *testing.T) {
	// Applying with no matches must still flip SBOMChecked, so the summary can
	// show "0" rather than omitting the line entirely, and must not disturb the
	// dark set.
	r := &Result{DarkFiles: []CategorizedFile{{File: image.File{Path: "/a"}}}}
	r.ApplySBOM(map[string]struct{}{})
	if !r.SBOMChecked {
		t.Error("SBOMChecked should be true even when nothing matched")
	}
	if r.SBOMCount() != 0 {
		t.Errorf("SBOMCount() = %d, want 0", r.SBOMCount())
	}
	if r.DarkCount() != 1 {
		t.Errorf("DarkCount() = %d, want 1 (unchanged)", r.DarkCount())
	}
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestDarkCodeCountsAndFormat(t *testing.T) {
	r := &Result{
		DarkFiles: []CategorizedFile{
			{File: image.File{Path: "/a", Kind: image.KindExecutable}},
			{File: image.File{Path: "/b", Kind: image.KindExecutable}},
			{File: image.File{Path: "/lib.so", Kind: image.KindSharedLibrary}},
			{File: image.File{Path: "/s.sh", Kind: image.KindScript}},
			{File: image.File{Path: "/data", Kind: image.KindOther}}, // excluded
		},
	}
	counts := r.DarkCodeCounts()
	if counts[image.KindExecutable] != 2 || counts[image.KindSharedLibrary] != 1 || counts[image.KindScript] != 1 {
		t.Errorf("DarkCodeCounts() = %v", counts)
	}
	if _, ok := counts[image.KindOther]; ok {
		t.Error("DarkCodeCounts() should not include KindOther")
	}

	// Order is fixed; libraries pluralize irregularly; singular stays singular.
	got := formatCodeCounts(counts)
	want := "2 executables, 1 shared library, 1 script"
	if got != want {
		t.Errorf("formatCodeCounts() = %q, want %q", got, want)
	}
}

func TestPluralize(t *testing.T) {
	cases := map[[2]string]string{
		{"executable", "1"}:     "executable",
		{"executable", "2"}:     "executables",
		{"shared library", "2"}: "shared libraries",
		{"script", "3"}:         "scripts",
	}
	for k, want := range cases {
		n := 1
		if k[1] == "2" {
			n = 2
		} else if k[1] == "3" {
			n = 3
		}
		if got := pluralize(k[0], n); got != want {
			t.Errorf("pluralize(%q, %d) = %q, want %q", k[0], n, got, want)
		}
	}
}
