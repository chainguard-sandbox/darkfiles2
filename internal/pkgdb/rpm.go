package pkgdb

import (
	"encoding/binary"
	"errors"
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
// from /var/lib/rpm to /usr/lib/sysimage/rpm (with the former a symlink).
// rpmdb.sqlite is listed first so that a transitional image carrying both is
// read via the reliable SQLite path. The on-disk format is detected from the
// content (see rpmIsBerkeleyDB), not the filename.
var rpmDBPaths = []string{
	"/var/lib/rpm/rpmdb.sqlite",
	"/usr/lib/sysimage/rpm/rpmdb.sqlite",
	"/var/lib/rpm/Packages.db",
	"/usr/lib/sysimage/rpm/Packages.db",
	"/var/lib/rpm/Packages",
	"/usr/lib/sysimage/rpm/Packages",
}

// ErrBerkeleyDBUnsupported is returned when the image's RPM database is in the
// legacy BerkeleyDB hash format (RHEL/CentOS 7, UBI 8). The pure-Go reader we
// depend on parses that format incompletely — it silently drops packages whose
// header is stored inline or whose bucket entry it fails to enumerate — so
// trusting its output would under-report installed packages and over-report
// dark files. We refuse it rather than return a partial, misleading result.
var ErrBerkeleyDBUnsupported = errors.New(
	"unsupported BerkeleyDB rpm database (legacy format used by RHEL/CentOS 7 and UBI 8); " +
		"package tracking skipped to avoid under-reporting packages")

// bdbHashMagic is the Berkeley DB hash-database magic number, found as a uint32
// at byte offset 12 of the metadata page (first page). It is stored in the
// database's native byte order, so both endiannesses are checked.
const bdbHashMagic = 0x00061561

// scanRPM returns the set of file paths owned by installed RPM packages.
//
// The SQLite format (the default since rpm 4.16 / RHEL 9 / Fedora 33, and what
// every current RPM distro ships) and the NDB format are parsed via go-rpmdb in
// pure Go — the SQLite reader uses the "sqlite" driver registered by the
// modernc.org/sqlite blank import above, so there is no cgo. The legacy
// BerkeleyDB format is refused (see ErrBerkeleyDBUnsupported). go-rpmdb opens a
// database by path, so the in-memory bytes captured during the image scan are
// written to a temporary file first.
func scanRPM(fs *image.ImageFS) (map[string]struct{}, error) {
	data, ok := findRPMDB(fs)
	if !ok {
		// No RPM database in the image — not an error; the caller may fall back
		// to the best-effort scanner.
		return map[string]struct{}{}, nil
	}

	if rpmIsBerkeleyDB(data) {
		return nil, ErrBerkeleyDBUnsupported
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

	tracked := map[string]struct{}{}
	for result := range db.ReadPackages() {
		if result.Err != nil {
			continue
		}
		p := result.Package
		files, err := p.InstalledFileNames()
		if err != nil {
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

// rpmIsBerkeleyDB reports whether data is a Berkeley DB hash database (the
// on-disk format of the legacy rpm Packages file), identified by its magic
// number regardless of the filename it was stored under.
func rpmIsBerkeleyDB(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	return binary.LittleEndian.Uint32(data[12:16]) == bdbHashMagic ||
		binary.BigEndian.Uint32(data[12:16]) == bdbHashMagic
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
