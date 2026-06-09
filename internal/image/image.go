package image

import (
	"archive/tar"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// File represents a file (or symlink) found in the container filesystem.
type File struct {
	Path      string
	Size      int64
	Mode      uint32
	IsSymlink bool
	LinkTarget string // only set when IsSymlink is true
}

// ImageFS holds the flattened filesystem and image metadata.
type ImageFS struct {
	Files     []File
	OsRelease map[string]string
	// FileContent holds the raw bytes of files we need for package DB parsing.
	FileContent map[string][]byte
	// Symlinks maps each symlink path to its (raw, unresolved) link target.
	Symlinks map[string]string
}

// ResolveSymlink follows the full symlink chain (including directory symlinks)
// for up to maxDepth hops and returns the canonical path.
func (fs *ImageFS) ResolveSymlink(path string) string {
	const maxDepth = 16
	for i := 0; i < maxDepth; i++ {
		// Try exact match first.
		if target, ok := fs.Symlinks[path]; ok {
			path = joinSymlink(path, target)
			continue
		}
		// Try resolving each directory component in case a parent dir is a symlink
		// (e.g. /bin → /usr/bin means /bin/ash resolves to /usr/bin/ash).
		resolved, changed := fs.resolvePrefix(path)
		if !changed {
			return path
		}
		path = resolved
	}
	return path
}

// resolvePrefix walks the components of path and resolves the first directory
// component that is itself a symlink. Returns the new path and whether a
// substitution was made.
func (fs *ImageFS) resolvePrefix(path string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := ""
	for i, part := range parts {
		current += "/" + part
		if target, ok := fs.Symlinks[current]; ok {
			// Replace current prefix with resolved target.
			resolved := joinSymlink(current, target)
			rest := strings.Join(parts[i+1:], "/")
			if rest != "" {
				resolved = resolved + "/" + rest
			}
			return filepath.Clean(resolved), true
		}
	}
	return path, false
}

func joinSymlink(symlinkPath, target string) string {
	if strings.HasPrefix(target, "/") {
		return filepath.Clean(target)
	}
	dir := symlinkPath[:strings.LastIndex(symlinkPath, "/")+1]
	return filepath.Clean(dir + target)
}

// pkgDBPaths are file paths whose contents we need to parse package databases.
var pkgDBPaths = map[string]bool{
	// APK (Alpine)
	"/lib/apk/db/installed": true,
	// APK (Wolfi / newer Alpine)
	"/usr/lib/apk/db/installed": true,
	// dpkg (Debian / Ubuntu)
	"/var/lib/dpkg/status": true,
}

func isPkgDBPath(path string) bool {
	if pkgDBPaths[path] {
		return true
	}
	// dpkg per-package file lists: /var/lib/dpkg/info/*.list
	if strings.HasPrefix(path, "/var/lib/dpkg/info/") && strings.HasSuffix(path, ".list") {
		return true
	}
	// RPM db files
	if strings.HasPrefix(path, "/var/lib/rpm/") {
		return true
	}
	// In-image SBOM files (e.g. Wolfi/Chainguard apko SBOMs)
	if strings.HasPrefix(path, "/var/lib/db/sbom/") {
		return true
	}
	return false
}

// Load pulls an image by reference and returns its flattened filesystem.
func Load(ref string) (*ImageFS, error) {
	img, err := crane.Pull(ref, crane.WithAuthFromKeychain(defaultKeychain()))
	if err != nil {
		return nil, fmt.Errorf("pulling image %q: %w", ref, err)
	}
	return fromImage(img)
}

// LoadFromTar loads an image from a local OCI tar file.
func LoadFromTar(path string) (*ImageFS, error) {
	img, err := crane.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading image tar: %w", err)
	}
	return fromImage(img)
}

func fromImage(img v1.Image) (*ImageFS, error) {
	pr, pw := io.Pipe()

	errCh := make(chan error, 1)
	go func() {
		err := crane.Export(img, pw)
		pw.CloseWithError(err)
		errCh <- err
	}()

	fs := &ImageFS{
		OsRelease:   map[string]string{},
		FileContent: map[string][]byte{},
		Symlinks:    map[string]string{},
	}
	seen := map[string]struct{}{}

	tr := tar.NewReader(pr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}

		path := cleanPath(hdr.Name)

		switch {
		case path == "/etc/os-release" || path == "/usr/lib/os-release":
			data, _ := io.ReadAll(tr)
			// Keep the first real file we find (not a symlink).
			if hdr.Typeflag != tar.TypeSymlink && len(fs.OsRelease) == 0 {
				fs.OsRelease = parseOsRelease(string(data))
			}

		case isPkgDBPath(path):
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", path, err)
			}
			fs.FileContent[path] = data

		default:
			// Skip directories.
			if hdr.Typeflag == tar.TypeDir {
				continue
			}
			if _, ok := seen[path]; ok {
				// Overlay layers can repeat entries; keep the first (topmost) occurrence.
				continue
			}
			seen[path] = struct{}{}

			// Drain any content we won't store.
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return nil, fmt.Errorf("draining %s: %w", path, err)
			}

			f := File{
				Path: path,
				Size: hdr.Size,
				Mode: uint32(hdr.Mode),
			}
			if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
				f.IsSymlink = true
				f.LinkTarget = hdr.Linkname
				fs.Symlinks[path] = hdr.Linkname
			}
			fs.Files = append(fs.Files, f)
		}
	}

	if err := <-errCh; err != nil {
		return nil, fmt.Errorf("exporting image: %w", err)
	}

	return fs, nil
}

func cleanPath(name string) string {
	return "/" + strings.TrimPrefix(filepath.Clean("/"+name), "/")
}

func parseOsRelease(content string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		m[key] = val
	}
	return m
}
