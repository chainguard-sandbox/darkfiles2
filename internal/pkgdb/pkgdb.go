package pkgdb

import (
	"errors"
	"fmt"
	"strings"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

// ErrNoTrackedFiles is returned when the image carries a package database but
// reading it yielded no files. That indicates the database could not be parsed
// (an unsupported layout or format), not that every file is dark, so it is
// reported as a scan failure rather than as a 100%-dark result.
var ErrNoTrackedFiles = errors.New("package database present but no tracked files could be read from it")

// TrackedFiles returns the set of file paths tracked by the package manager
// database, plus the detected distro name.
func TrackedFiles(fs *image.ImageFS) (map[string]struct{}, string, error) {
	distro, scanner := detect(fs)

	tracked, err := scanner(fs)
	if err != nil {
		return nil, distro, fmt.Errorf("scanning %s package db: %w", distro, err)
	}
	if len(tracked) == 0 && hasPkgDB(fs) {
		return nil, distro, fmt.Errorf("scanning %s package db: %w", distro, ErrNoTrackedFiles)
	}
	return tracked, distro, nil
}

// hasPkgDB reports whether the image carries a non-empty package database of
// any supported kind.
func hasPkgDB(fs *image.ImageFS) bool {
	for _, p := range apkDBPaths {
		if len(fs.FileContent[p]) > 0 {
			return true
		}
	}
	if _, ok := findRPMDB(fs); ok {
		return true
	}
	return hasDpkgDB(fs)
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
