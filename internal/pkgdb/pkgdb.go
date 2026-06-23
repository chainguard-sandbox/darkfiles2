package pkgdb

import (
	"fmt"
	"strings"

	"github.com/chainguard-dev/darkfiles2/internal/image"
)

// TrackedFiles returns the set of file paths tracked by the package manager
// database, plus the detected distro name.
func TrackedFiles(fs *image.ImageFS) (map[string]struct{}, string, error) {
	distro, scanner := detect(fs)

	tracked, err := scanner(fs)
	if err != nil {
		return nil, distro, fmt.Errorf("scanning %s package db: %w", distro, err)
	}
	return tracked, distro, nil
}

type scannerFn func(*image.ImageFS) (map[string]struct{}, error)

func detect(fs *image.ImageFS) (string, scannerFn) {
	id := strings.ToLower(fs.OsRelease["ID"])
	idLike := strings.ToLower(fs.OsRelease["ID_LIKE"])

	switch {
	case id == "alpine" || strings.Contains(idLike, "alpine"):
		return "alpine", scanAPK
	case id == "wolfi" || id == "chainguard" || strings.Contains(idLike, "wolfi"):
		return "wolfi", scanAPK
	case id == "debian" || id == "ubuntu" ||
		strings.Contains(idLike, "debian") || strings.Contains(idLike, "ubuntu"):
		return "debian", scanDpkg
	case id == "fedora" || id == "rhel" || id == "centos" || id == "rocky" ||
		strings.Contains(idLike, "rhel") || strings.Contains(idLike, "fedora"):
		return "rpm", scanRPM
	default:
		return "unknown", scanBestEffort
	}
}

func scanBestEffort(fs *image.ImageFS) (map[string]struct{}, error) {
	scanners := []scannerFn{scanAPK, scanDpkg, scanRPM}
	best := map[string]struct{}{}
	for _, s := range scanners {
		tracked, err := s(fs)
		if err == nil && len(tracked) > len(best) {
			best = tracked
		}
	}
	return best, nil
}
