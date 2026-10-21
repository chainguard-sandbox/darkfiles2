package pkgdb

import (
	"strings"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

const (
	dpkgStatusPath = "/var/lib/dpkg/status"
	dpkgInfoDir    = "/var/lib/dpkg/info/"
	// dpkgStatusDDir is the layout used by distroless-style images, which ship
	// no status file or info/*.list files. Each package instead has a control
	// stanza at status.d/<pkg> and its file list at status.d/<pkg>.md5sums.
	dpkgStatusDDir = "/var/lib/dpkg/status.d/"
)

// scanDpkg returns all file paths tracked by dpkg.
// It reads per-package *.list files under /var/lib/dpkg/info/ which each contain
// one absolute path per line. The status file tells us which packages are installed.
// It also reads the status.d/<pkg>.md5sums file lists of the distroless layout.
func scanDpkg(fs *image.ImageFS) (map[string]struct{}, error) {
	// Collect installed package names from the status file.
	installed := dpkgInstalledPackages(fs)

	tracked := map[string]struct{}{}

	for path, data := range fs.FileContent {
		switch {
		case strings.HasPrefix(path, dpkgInfoDir) && strings.HasSuffix(path, ".list"):
			// Extract package name from path like /var/lib/dpkg/info/<name>.list
			// or /var/lib/dpkg/info/<name>:<arch>.list
			base := strings.TrimPrefix(path, dpkgInfoDir)
			base = strings.TrimSuffix(base, ".list")
			// Strip architecture suffix.
			if idx := strings.Index(base, ":"); idx != -1 {
				base = base[:idx]
			}

			// If we have a status file, only count installed packages.
			if len(installed) > 0 {
				if _, ok := installed[base]; !ok {
					continue
				}
			}

			for line := range strings.Lines(string(data)) {
				line = strings.TrimSpace(line)
				if line == "" || line == "/" {
					continue
				}
				tracked[line] = struct{}{}
			}

		case strings.HasPrefix(path, dpkgStatusDDir) && strings.HasSuffix(path, ".md5sums"):
			// Each line is "<md5>  <path>", the path relative to / and possibly
			// containing spaces.
			for line := range strings.Lines(string(data)) {
				_, p, ok := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
				if !ok {
					continue
				}
				p = strings.TrimLeft(p, " *")
				if p == "" {
					continue
				}
				tracked["/"+strings.TrimPrefix(p, "/")] = struct{}{}
			}
		}
	}

	return tracked, nil
}

func dpkgInstalledPackages(fs *image.ImageFS) map[string]struct{} {
	data, ok := fs.FileContent[dpkgStatusPath]
	if !ok {
		return nil
	}

	installed := map[string]struct{}{}
	var currentPkg string
	var isInstalled bool

	for line := range strings.Lines(string(data)) {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if currentPkg != "" && isInstalled {
				installed[currentPkg] = struct{}{}
			}
			currentPkg = ""
			isInstalled = false
			continue
		}

		if strings.HasPrefix(line, "Package:") {
			currentPkg = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		} else if strings.HasPrefix(line, "Status:") {
			// Status field format: "Status: <want> <flag> <status>"
			// Only "install ok installed" is fully installed; states like
			// "half-installed" or "half-configured" must not be counted.
			fields := strings.Fields(strings.TrimPrefix(line, "Status:"))
			isInstalled = len(fields) >= 3 && fields[2] == "installed"
		}
	}
	if currentPkg != "" && isInstalled {
		installed[currentPkg] = struct{}{}
	}

	return installed
}

// hasDpkgDB reports whether the image carries any non-empty dpkg database
// file, in either the classic or the status.d layout.
func hasDpkgDB(fs *image.ImageFS) bool {
	for path, data := range fs.FileContent {
		if len(data) == 0 {
			continue
		}
		if path == dpkgStatusPath ||
			strings.HasPrefix(path, dpkgStatusDDir) ||
			(strings.HasPrefix(path, dpkgInfoDir) && strings.HasSuffix(path, ".list")) {
			return true
		}
	}
	return false
}
