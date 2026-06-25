package pkgdb

import (
	"testing"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name       string
		osRelease  map[string]string
		wantDistro string
	}{
		{"alpine by ID", map[string]string{"ID": "alpine"}, "alpine"},
		{"wolfi by ID", map[string]string{"ID": "wolfi"}, "wolfi"},
		{"chainguard maps to wolfi", map[string]string{"ID": "chainguard"}, "wolfi"},
		{"alpine via ID_LIKE", map[string]string{"ID": "something", "ID_LIKE": "alpine"}, "alpine"},
		{"debian by ID", map[string]string{"ID": "debian"}, "debian"},
		{"ubuntu by ID", map[string]string{"ID": "ubuntu"}, "debian"},
		{"debian via ID_LIKE", map[string]string{"ID": "mint", "ID_LIKE": "ubuntu debian"}, "debian"},
		{"fedora by ID", map[string]string{"ID": "fedora"}, "rpm"},
		{"rocky via ID", map[string]string{"ID": "rocky"}, "rpm"},
		{"rhel via ID_LIKE", map[string]string{"ID": "amzn", "ID_LIKE": "rhel fedora"}, "rpm"},
		{"case insensitive", map[string]string{"ID": "ALPINE"}, "alpine"},
		{"unknown", map[string]string{"ID": "plan9"}, "unknown"},
		{"empty", map[string]string{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &image.ImageFS{OsRelease: tt.osRelease}
			distro, scanner := detect(fs)
			if distro != tt.wantDistro {
				t.Errorf("detect() distro = %q, want %q", distro, tt.wantDistro)
			}
			if scanner == nil {
				t.Error("detect() returned nil scanner")
			}
		})
	}
}
