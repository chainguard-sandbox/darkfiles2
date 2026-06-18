package report

import (
	"testing"

	"github.com/chainguard-dev/darkfiles2/internal/image"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		path string
		want Category
	}{
		// Device files.
		{"/dev/null", CategoryDeviceFile},
		{"/dev/shm/foo", CategoryDeviceFile},

		// Package manager state.
		{"/etc/apk/world", CategoryPkgManagerState},
		{"/lib/apk/db/scripts.tar", CategoryPkgManagerState},
		{"/var/lib/dpkg/status", CategoryPkgManagerState},
		{"/var/lib/rpm/Packages", CategoryPkgManagerState},
		{"/etc/alternatives/awk", CategoryPkgManagerState},
		{"/var/cache/apt/archives/foo.deb", CategoryPkgManagerState},

		// Runtime-generated.
		{"/etc/passwd", CategoryRuntimeGenerated},
		{"/etc/ld.so.cache", CategoryRuntimeGenerated},
		{"/run/secrets/token", CategoryRuntimeGenerated},
		{"/tmp/scratch", CategoryRuntimeGenerated},
		{"/var/log/messages", CategoryRuntimeGenerated},
		{"/etc/machine-id", CategoryRuntimeGenerated},
		{"/etc/pam.d/login", CategoryRuntimeGenerated},

		// Build metadata.
		{"/etc/apko.json", CategoryBuildMetadata},
		{"/.dockerenv", CategoryBuildMetadata},
		{"/var/lib/db/sbom", CategoryBuildMetadata},

		// Unknown — the bucket that matters.
		{"/app/server", CategoryUnknown},
		{"/usr/local/bin/mytool", CategoryUnknown},
		{"/opt/data/blob.bin", CategoryUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := Classify(image.File{Path: tt.path})
			if got != tt.want {
				t.Errorf("Classify(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestCategoryString(t *testing.T) {
	tests := []struct {
		cat  Category
		want string
	}{
		{CategoryUnknown, "Unknown"},
		{CategoryDeviceFile, "Device files"},
		{CategoryPkgManagerState, "Package manager state"},
		{CategoryRuntimeGenerated, "Runtime-generated"},
		{CategoryBuildMetadata, "Build metadata"},
		{Category(999), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.cat.String(); got != tt.want {
			t.Errorf("Category(%d).String() = %q, want %q", tt.cat, got, tt.want)
		}
	}
}

// sbom-tracked exact path takes the build-metadata exact branch, while a path
// *under* the same prefix is package-manager state. Guards against the two
// overlapping rules silently reordering.
func TestClassifySBOMPathPrecedence(t *testing.T) {
	if got := Classify(image.File{Path: "/var/lib/db/sbom"}); got != CategoryBuildMetadata {
		t.Errorf("Classify(/var/lib/db/sbom) = %v, want CategoryBuildMetadata", got)
	}
	if got := Classify(image.File{Path: "/var/lib/db/sbom/x.json"}); got != CategoryPkgManagerState {
		t.Errorf("Classify(/var/lib/db/sbom/x.json) = %v, want CategoryPkgManagerState", got)
	}
}
