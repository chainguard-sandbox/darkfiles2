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
// opt-in features such as fingerprinting, not the default analysis path.
func (fs *ImageFS) ExtractContents(want map[string]bool) (map[string][]byte, error) {
	out := make(map[string][]byte, len(want))
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
		err = extractLayerContents(rc, want, out)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("scanning layer %d: %w", i, err)
		}
	}
	return out, nil
}

func extractLayerContents(rc io.Reader, want map[string]bool, out map[string][]byte) error {
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
		out[name] = data
	}
	return nil
}
