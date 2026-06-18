package pkgdb

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/chainguard-dev/darkfiles2/internal/image"
)

// scanDpkg returns all file paths tracked by dpkg.
// It reads per-package *.list files under /var/lib/dpkg/info/ which each contain
// one absolute path per line. The status file tells us which packages are installed.
func scanDpkg(fs *image.ImageFS) (map[string]struct{}, error) {
	// Collect installed package names from the status file.
	installed := dpkgInstalledPackages(fs)

	tracked := map[string]struct{}{}

	for path, data := range fs.FileContent {
		if !strings.HasPrefix(path, "/var/lib/dpkg/info/") || !strings.HasSuffix(path, ".list") {
			continue
		}

		// Extract package name from path like /var/lib/dpkg/info/<name>.list
		// or /var/lib/dpkg/info/<name>:<arch>.list
		base := strings.TrimPrefix(path, "/var/lib/dpkg/info/")
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

		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || line == "/" {
				continue
			}
			tracked[line] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	return tracked, nil
}

func dpkgInstalledPackages(fs *image.ImageFS) map[string]struct{} {
	data, ok := fs.FileContent["/var/lib/dpkg/status"]
	if !ok {
		return nil
	}

	installed := map[string]struct{}{}
	var currentPkg string
	var isInstalled bool

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
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
			// Status: install ok installed
			isInstalled = strings.Contains(line, "installed")
		}
	}
	if currentPkg != "" && isInstalled {
		installed[currentPkg] = struct{}{}
	}

	return installed
}
