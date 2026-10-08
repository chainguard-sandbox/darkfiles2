package pkgdb

import (
	"fmt"
	"os"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" driver used for rpmdb.sqlite

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

// rpmDBPaths lists known locations and names of the RPM package database. The
// on-disk format has changed over rpm's lifetime — BerkeleyDB (Packages), the
// "new db" format (Packages.db), and SQLite (rpmdb.sqlite, the default since
// rpm 4.16 / RHEL 9 / Fedora 33) — and newer distros relocated the directory
// from /var/lib/rpm to /usr/lib/sysimage/rpm (with the former a symlink). We do
// not care which format a file is: go-rpmdb sniffs it from the content, so this
// is only the lookup order for finding the database in the image.
var rpmDBPaths = []string{
	"/var/lib/rpm/rpmdb.sqlite",
	"/var/lib/rpm/Packages",
	"/var/lib/rpm/Packages.db",
	"/usr/lib/sysimage/rpm/rpmdb.sqlite",
	"/usr/lib/sysimage/rpm/Packages",
	"/usr/lib/sysimage/rpm/Packages.db",
}

// scanRPM returns the set of file paths owned by installed RPM packages.
//
// go-rpmdb parses the BerkeleyDB, NDB, and SQLite database formats in pure Go
// (the SQLite reader needs a registered "sqlite" driver, supplied by the
// modernc.org/sqlite blank import above — no cgo). It opens a database by path,
// so the in-memory database bytes captured during the image scan are written to
// a temporary file first.
func scanRPM(fs *image.ImageFS) (map[string]struct{}, error) {
	data, ok := findRPMDB(fs)
	if !ok {
		// No RPM database in the image — not an error; the caller may fall back
		// to the best-effort scanner.
		return map[string]struct{}{}, nil
	}

	path, cleanup, err := writeTempDB(data)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	db, err := rpmdb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening rpm database: %w", err)
	}
	defer db.Close()

	pkgs, err := db.ListPackages()
	if err != nil {
		return nil, fmt.Errorf("listing rpm packages: %w", err)
	}

	tracked := map[string]struct{}{}
	for _, p := range pkgs {
		files, err := p.InstalledFileNames()
		if err != nil {
			// A single corrupt package header should not abort the whole scan;
			// skip it and keep the paths we can read.
			continue
		}
		for _, f := range files {
			if f == "" {
				continue
			}
			tracked["/"+strings.TrimPrefix(f, "/")] = struct{}{}
		}
	}
	return tracked, nil
}

// findRPMDB returns the bytes of the first RPM database found in the image's
// captured package-db files, and whether one was found.
func findRPMDB(fs *image.ImageFS) ([]byte, bool) {
	for _, p := range rpmDBPaths {
		if d, ok := fs.FileContent[p]; ok && len(d) > 0 {
			return d, true
		}
	}
	return nil, false
}

// writeTempDB writes data to a temporary file and returns its path plus a
// cleanup function. go-rpmdb (and the sqlite driver in particular) needs a real
// file on disk to open.
func writeTempDB(data []byte) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "darkfiles-rpmdb-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp rpm database: %w", err)
	}
	cleanup = func() { os.Remove(f.Name()) }
	if _, err := f.Write(data); err != nil {
		f.Close()
		cleanup()
		return "", nil, fmt.Errorf("writing temp rpm database: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("closing temp rpm database: %w", err)
	}
	return f.Name(), cleanup, nil
}
