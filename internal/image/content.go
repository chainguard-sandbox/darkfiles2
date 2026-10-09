package image

import (
	"archive/tar"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// maxContentSize caps how many bytes are buffered per file during content
// extraction. Images are untrusted input, and ExtractContents holds every
// requested file in memory at once, so an oversized member is truncated rather
// than allowed to exhaust memory. 512 MiB comfortably covers real binaries.
const maxContentSize = 512 << 20

// ExtractContents reads the full content of each requested path from the image
// layers. Only paths present in want are buffered; every other entry is streamed
// past. Overlay semantics are honoured — the last layer to write a path wins,
// and whiteouts drop earlier content — so the returned bytes match the flattened
// filesystem. Files larger than maxContentSize are truncated to that many bytes.
//
// The initial image scan (see fromImage) discards file bodies to keep memory
// bounded, so this performs a second pass over the layers. It is intended for
// opt-in features such as library detection, not the default analysis path.
func (fs *ImageFS) ExtractContents(want map[string]bool) (map[string][]byte, error) {
	return ScanContents(fs, want, func(data []byte) []byte { return data })
}

// ScanContents is a streaming form of ExtractContents: rather than retaining
// each requested file's bytes, it calls fn on them as the layers are read and
// keeps only fn's result, so at most one file body is held in memory at a time.
// Overlay semantics match ExtractContents — a later layer's version of a path
// replaces the earlier result, and whiteouts drop it — so each result reflects
// the flattened filesystem.
func ScanContents[T any](fs *ImageFS, want map[string]bool, fn func(data []byte) T) (map[string]T, error) {
	out := make(map[string]T, len(want))
	if len(want) == 0 {
		return out, nil
	}
	if fs.img == nil {
		return nil, fmt.Errorf("image source not available for content extraction")
	}

	layers, err := fs.img.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting image layers: %w", err)
	}
	for i, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("layer %d uncompressed: %w", i, err)
		}
		err = scanLayerContents(rc, want, out, fn)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("scanning layer %d: %w", i, err)
		}
	}
	return out, nil
}

func extractLayerContents(rc io.Reader, want map[string]bool, out map[string][]byte) error {
	return scanLayerContents(rc, want, out, func(data []byte) []byte { return data })
}

func scanLayerContents[T any](rc io.Reader, want map[string]bool, out map[string]T, fn func([]byte) T) error {
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
			delete(out, whiteoutTarget(name))
			continue
		}
		if isOpaqueWhiteout(name) {
			dir := filepath.Dir(name)
			for p := range out {
				if strings.HasPrefix(p, dir+"/") {
					delete(out, p)
				}
			}
			continue
		}

		if !want[name] {
			continue
		}

		// A wanted path re-appearing as a non-regular entry (symlink/dir) in a
		// later layer replaces any earlier content, matching overlay semantics.
		if !hdr.FileInfo().Mode().IsRegular() {
			delete(out, name)
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tr, maxContentSize))
		if err != nil {
			return fmt.Errorf("reading %s: %w", name, err)
		}
		out[name] = fn(data)
	}
	return nil
}
