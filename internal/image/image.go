package image

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// FileKind classifies a file by what it contains. It is orthogonal to a dark
// file's Category: an unknown dark file can also be an executable.
type FileKind int

const (
	// KindOther is anything not recognised as executable code.
	KindOther         FileKind = iota
	KindExecutable             // ELF/Mach-O/PE executable
	KindSharedLibrary          // .so / .dylib shared object
	KindScript                 // shebang (#!) script
	KindStaticLibrary          // ar archive (.a)
)

func (k FileKind) String() string {
	switch k {
	case KindExecutable:
		return "executable"
	case KindSharedLibrary:
		return "shared library"
	case KindScript:
		return "script"
	case KindStaticLibrary:
		return "static library"
	default:
		return ""
	}
}

// IsCode reports whether the file is executable code (binary, library, script).
func (k FileKind) IsCode() bool { return k != KindOther }

// File represents a file (or symlink) found in the container filesystem.
type File struct {
	Path       string
	Size       int64
	Mode       uint32
	IsSymlink  bool
	LinkTarget string   // only set when IsSymlink is true
	LayerIndex int      // index into ImageFS.Layers
	Kind       FileKind // executable/library/script classification
}

// Layer describes a single image layer and the Dockerfile command that created it.
type Layer struct {
	Index     int    // index into the real (non-empty) layer list
	DiffID    string // sha256 of the uncompressed tar
	CreatedBy string // raw string from image config history
	Comment   string
	IsEmpty   bool // true for ENV, LABEL, etc. entries with no layer tar
}

// Command returns a cleaned-up display version of CreatedBy.
func (l Layer) Command() string {
	s := l.CreatedBy
	if idx := strings.Index(s, "#(nop) "); idx != -1 {
		s = strings.TrimSpace(s[idx+len("#(nop) "):])
	} else {
		for _, pfx := range []string{"/bin/sh -c ", "/bin/bash -c "} {
			s = strings.TrimPrefix(s, pfx)
		}
	}
	const max = 120
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// ImageFS holds the flattened filesystem and image metadata.
type ImageFS struct {
	Files       []File
	Layers      []Layer // all history entries (including empty)
	OsRelease   map[string]string
	FileContent map[string][]byte // package manager database files
	Symlinks    map[string]string // path -> raw link target
}

// ResolveSymlink follows the full symlink chain for up to maxDepth hops.
func (fs *ImageFS) ResolveSymlink(path string) string {
	const maxDepth = 16
	for i := 0; i < maxDepth; i++ {
		if target, ok := fs.Symlinks[path]; ok {
			path = joinSymlink(path, target)
			continue
		}
		resolved, changed := fs.resolvePrefix(path)
		if !changed {
			return path
		}
		path = resolved
	}
	return path
}

func (fs *ImageFS) resolvePrefix(path string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := ""
	for i, part := range parts {
		current += "/" + part
		if target, ok := fs.Symlinks[current]; ok {
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

var pkgDBPaths = map[string]bool{
	"/lib/apk/db/installed":     true,
	"/usr/lib/apk/db/installed": true,
	"/var/lib/dpkg/status":      true,
}

func isPkgDBPath(path string) bool {
	if pkgDBPaths[path] {
		return true
	}
	if strings.HasPrefix(path, "/var/lib/dpkg/info/") && strings.HasSuffix(path, ".list") {
		return true
	}
	if strings.HasPrefix(path, "/var/lib/rpm/") {
		return true
	}
	return false
}

func isOsReleasePath(path string) bool {
	return path == "/etc/os-release" || path == "/usr/lib/os-release"
}

// forgetCachedPath drops cached pkg-db bytes and distro info for a path removed
// by a whiteout, keeping fs.FileContent/fs.OsRelease consistent with overlay
// state. Without this, a deleted package db would still mark its files tracked.
func forgetCachedPath(fs *ImageFS, path string) {
	delete(fs.FileContent, path)
	if isOsReleasePath(path) {
		fs.OsRelease = map[string]string{}
	}
}

// forgetCachedPrefix is forgetCachedPath for an opaque whiteout, which removes
// every entry under dir (prefix ends in "/").
func forgetCachedPrefix(fs *ImageFS, prefix string) {
	for p := range fs.FileContent {
		if strings.HasPrefix(p, prefix) {
			delete(fs.FileContent, p)
		}
	}
	if strings.HasPrefix("/etc/os-release", prefix) || strings.HasPrefix("/usr/lib/os-release", prefix) {
		fs.OsRelease = map[string]string{}
	}
}

// Load pulls an image by reference and returns its layered filesystem.
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
	layers, err := buildLayerMetadata(img)
	if err != nil {
		return nil, err
	}

	fs := &ImageFS{
		Layers:      layers,
		OsRelease:   map[string]string{},
		FileContent: map[string][]byte{},
		Symlinks:    map[string]string{},
	}

	imgLayers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting image layers: %w", err)
	}

	// Map real layer index -> Layers slice index.
	layerIdxMap := buildLayerIndexMap(layers)

	// Overlay state: last writer wins.
	fileOrigin := map[string]int{} // path -> Layers slice index
	fileInfo := map[string]File{}  // path -> latest File metadata

	for realIdx, imgLayer := range imgLayers {
		lIdx, ok := layerIdxMap[realIdx]
		if !ok {
			lIdx = realIdx
		}
		rc, err := imgLayer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("layer %d uncompressed: %w", realIdx, err)
		}
		err = scanLayerTar(rc, lIdx, fs, fileOrigin, fileInfo)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("scanning layer %d: %w", realIdx, err)
		}
	}

	for _, f := range fileInfo {
		f.LayerIndex = fileOrigin[f.Path]
		fs.Files = append(fs.Files, f)
	}

	return fs, nil
}

func scanLayerTar(
	rc io.Reader,
	layerIdx int,
	fs *ImageFS,
	fileOrigin map[string]int,
	fileInfo map[string]File,
) error {
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		name := cleanPath(hdr.Name)

		if isWhiteout(name) {
			target := whiteoutTarget(name)
			delete(fileOrigin, target)
			delete(fileInfo, target)
			forgetCachedPath(fs, target)
			io.Copy(io.Discard, tr)
			continue
		}
		if isOpaqueWhiteout(name) {
			dir := filepath.Dir(name)
			for p := range fileOrigin {
				if strings.HasPrefix(p, dir+"/") {
					delete(fileOrigin, p)
					delete(fileInfo, p)
				}
			}
			forgetCachedPrefix(fs, dir+"/")
			io.Copy(io.Discard, tr)
			continue
		}

		if name == "/etc/os-release" || name == "/usr/lib/os-release" {
			data, err := readCapped(tr, maxOsReleaseSize)
			if err != nil {
				return fmt.Errorf("reading %s: %w", name, err)
			}
			// Last layer wins — consistent with overlay FS semantics. Symlink
			// entries (e.g. /etc/os-release -> /usr/lib/os-release on Alpine) are
			// skipped so we only parse real files.
			if hdr.Typeflag != tar.TypeSymlink {
				fs.OsRelease = parseOsRelease(string(data))
			}
			continue
		}

		if isPkgDBPath(name) {
			data, err := readCapped(tr, maxPkgDBSize)
			if err != nil {
				return fmt.Errorf("reading %s: %w", name, err)
			}
			fs.FileContent[name] = data
			continue
		}

		if hdr.Typeflag == tar.TypeDir {
			io.Copy(io.Discard, tr)
			continue
		}

		f := File{
			Path: name,
			Size: hdr.Size,
			Mode: uint32(hdr.Mode),
		}
		switch hdr.Typeflag {
		case tar.TypeSymlink:
			f.IsSymlink = true
			f.LinkTarget = hdr.Linkname
			fs.Symlinks[name] = hdr.Linkname
			io.Copy(io.Discard, tr)
		case tar.TypeLink:
			// Hard links share an inode with another file in the archive; there
			// is no body to read. Classify by name and mode only (no magic bytes)
			// and do NOT add to Symlinks — hard links are not symbolic links.
			f.Kind = classifyKind(name, hdr.Mode, nil)
		default:
			// Sniff the leading bytes to classify executables/libraries, then
			// drain the rest. We never retain full file content.
			magic := make([]byte, magicLen)
			n, _ := io.ReadFull(tr, magic)
			io.Copy(io.Discard, tr)
			f.Kind = classifyKind(name, hdr.Mode, magic[:n])
		}
		fileOrigin[name] = layerIdx
		fileInfo[name] = f
	}
	return nil
}

func buildLayerMetadata(img v1.Image) ([]Layer, error) {
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("reading image config: %w", err)
	}
	rootfs := cf.RootFS

	var layers []Layer
	realIdx := 0
	for _, h := range cf.History {
		l := Layer{
			CreatedBy: h.CreatedBy,
			Comment:   h.Comment,
			IsEmpty:   h.EmptyLayer,
		}
		if !h.EmptyLayer {
			l.Index = realIdx
			if realIdx < len(rootfs.DiffIDs) {
				l.DiffID = rootfs.DiffIDs[realIdx].String()
			}
			realIdx++
		}
		layers = append(layers, l)
	}

	if len(layers) == 0 {
		imgLayers, err := img.Layers()
		if err != nil {
			return nil, err
		}
		for i := range imgLayers {
			layers = append(layers, Layer{Index: i, CreatedBy: fmt.Sprintf("layer %d", i)})
		}
	}
	return layers, nil
}

func buildLayerIndexMap(layers []Layer) map[int]int {
	m := map[int]int{}
	for sliceIdx, l := range layers {
		if !l.IsEmpty {
			m[l.Index] = sliceIdx
		}
	}
	return m
}

func isWhiteout(path string) bool {
	base := filepath.Base(path)
	return strings.HasPrefix(base, ".wh.") && base != ".wh..wh..opq"
}
func isOpaqueWhiteout(path string) bool { return filepath.Base(path) == ".wh..wh..opq" }
func whiteoutTarget(whiteoutPath string) string {
	dir := filepath.Dir(whiteoutPath)
	base := strings.TrimPrefix(filepath.Base(whiteoutPath), ".wh.")
	return cleanPath(dir + "/" + base)
}

func cleanPath(name string) string {
	return "/" + strings.TrimPrefix(filepath.Clean("/"+name), "/")
}

// magicLen is how many leading bytes we read to identify a file. 18 bytes is
// enough to reach the ELF e_type field (offset 16) which splits executables
// from shared objects.
const magicLen = 18

// Caps on members we buffer entirely. Images are untrusted input, so a
// malicious entry could otherwise consume unbounded memory.
const (
	// maxOsReleaseSize bounds /etc/os-release. Real files are well under 1 KB.
	maxOsReleaseSize = 1 << 20 // 1 MiB
	// maxPkgDBSize bounds a package-manager database file. Legitimate dpkg/rpm
	// databases reach tens of MiB on large images; this leaves ample headroom.
	maxPkgDBSize = 512 << 20 // 512 MiB
)

// readCapped reads up to max+1 bytes from r and reports an error if the member
// exceeds max, so an oversized entry can't exhaust memory.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("member exceeds %d byte limit", max)
	}
	return data, nil
}

var (
	elfMagic  = []byte{0x7f, 'E', 'L', 'F'}
	arMagic   = []byte("!<arch>\n")
	wasmMagic = []byte{0x00, 'a', 's', 'm'}
)

// classifyKind identifies executable code from the file's leading bytes, using
// mode and path only to disambiguate (e.g. an ELF shared object that is really
// a PIE executable).
func classifyKind(name string, mode int64, magic []byte) FileKind {
	switch {
	case len(magic) >= 2 && magic[0] == '#' && magic[1] == '!':
		return KindScript
	case bytes.HasPrefix(magic, arMagic):
		return KindStaticLibrary
	case bytes.HasPrefix(magic, elfMagic):
		return classifyELF(name, mode, magic)
	case isMachO(magic):
		if looksLikeLibrary(name) {
			return KindSharedLibrary
		}
		return KindExecutable
	case len(magic) >= 2 && magic[0] == 'M' && magic[1] == 'Z': // PE / DOS
		return KindExecutable
	case bytes.HasPrefix(magic, wasmMagic):
		return KindExecutable
	default:
		return KindOther
	}
}

func classifyELF(name string, mode int64, magic []byte) FileKind {
	if len(magic) < 18 {
		// Header truncated; fall back to name/mode.
		if looksLikeLibrary(name) {
			return KindSharedLibrary
		}
		return KindExecutable
	}
	// e_type is a 2-byte field at offset 16; EI_DATA (magic[5]) gives endianness
	// (1 = little, 2 = big).
	var etype uint16
	if magic[5] == 2 {
		etype = uint16(magic[16])<<8 | uint16(magic[17])
	} else {
		etype = uint16(magic[16]) | uint16(magic[17])<<8
	}
	const (
		etExec = 2 // ET_EXEC
		etDyn  = 3 // ET_DYN — shared object or position-independent executable
	)
	switch etype {
	case etExec:
		return KindExecutable
	case etDyn:
		if looksLikeLibrary(name) {
			return KindSharedLibrary
		}
		if mode&0o111 != 0 || inBinDir(name) {
			return KindExecutable
		}
		return KindSharedLibrary
	default:
		return KindOther
	}
}

func isMachO(magic []byte) bool {
	if len(magic) < 4 {
		return false
	}
	// 32/64-bit, both byte orders. Fat/universal (0xCAFEBABE) is omitted because
	// it collides with Java .class files.
	for _, m := range [][]byte{
		{0xFE, 0xED, 0xFA, 0xCE}, {0xCE, 0xFA, 0xED, 0xFE},
		{0xFE, 0xED, 0xFA, 0xCF}, {0xCF, 0xFA, 0xED, 0xFE},
	} {
		if bytes.Equal(magic[:4], m) {
			return true
		}
	}
	return false
}

func looksLikeLibrary(name string) bool {
	base := filepath.Base(name)
	if strings.HasSuffix(base, ".dylib") || strings.HasSuffix(base, ".a") {
		return true
	}
	// libfoo.so, libfoo.so.1, libfoo.so.1.2.3
	if i := strings.Index(base, ".so"); i != -1 {
		rest := base[i+len(".so"):]
		if rest == "" || rest[0] == '.' {
			return true
		}
	}
	return false
}

func inBinDir(name string) bool {
	for _, d := range []string{
		"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
		"/usr/libexec/", "/usr/local/bin/", "/usr/local/sbin/",
	} {
		if strings.Contains(name, d) {
			return true
		}
	}
	return false
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
