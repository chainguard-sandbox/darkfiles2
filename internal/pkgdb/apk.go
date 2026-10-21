package pkgdb

import (
	"strings"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

// apkDBPaths lists the known locations for the APK installed database.
// Alpine uses /lib/apk/db/installed; Wolfi and newer distros use /usr/lib/apk/db/installed.
var apkDBPaths = []string{
	"/lib/apk/db/installed",
	"/usr/lib/apk/db/installed",
}

// scanAPK parses the APK installed database and returns all file paths owned by APK packages.
// The format is a sequence of stanzas separated by blank lines; lines starting with
// "F:" are directories and "R:" are filenames relative to that directory.
func scanAPK(fs *image.ImageFS) (map[string]struct{}, error) {
	var data []byte
	for _, p := range apkDBPaths {
		if d, ok := fs.FileContent[p]; ok {
			data = d
			break
		}
	}
	if data == nil {
		return map[string]struct{}{}, nil
	}

	tracked := map[string]struct{}{}
	var dir string

	// Iterate lines directly rather than with bufio.Scanner: its default 64 KiB
	// token limit is exceeded by long records (e.g. a large D: or p: line),
	// which would abort the scan and leave every file untracked.
	for line := range strings.Lines(string(data)) {
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 2 {
			dir = ""
			continue
		}
		tag := line[:2]
		val := line[2:]
		switch tag {
		case "F:":
			dir = "/" + strings.TrimPrefix(val, "/")
		case "R:":
			if dir == "/" {
				tracked["/"+val] = struct{}{}
			} else {
				tracked[dir+"/"+val] = struct{}{}
			}
		}
	}

	return tracked, nil
}
