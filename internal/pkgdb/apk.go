package pkgdb

import (
	"bufio"
	"bytes"
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

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
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

	return tracked, scanner.Err()
}
