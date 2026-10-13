package pkgdb

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
)

// bdbHeader builds the first 16 bytes of a Berkeley DB hash database: the magic
// number 0x00061561 at offset 12, in the requested byte order. That is all
// rpmIsBerkeleyDB inspects, so a full fixture is unnecessary.
func bdbHeader(bigEndian bool) []byte {
	b := make([]byte, 16)
	if bigEndian {
		binary.BigEndian.PutUint32(b[12:16], bdbHashMagic)
	} else {
		binary.LittleEndian.PutUint32(b[12:16], bdbHashMagic)
	}
	return b
}

// loadFixture reads the trimmed SQLite rpmdb fixture. It is a real rpm database
// (SQLite format, the default since rpm 4.16 / RHEL 9 / Fedora 33) containing a
// handful of small packages extracted from rockylinux:9-minimal, so it
// exercises the full go-rpmdb parse path while staying tiny.
func loadFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rpmdb.sqlite"))
	if err != nil {
		t.Fatalf("reading rpmdb fixture: %v", err)
	}
	return data
}

func TestScanRPM(t *testing.T) {
	fs := &image.ImageFS{
		FileContent: map[string][]byte{
			"/var/lib/rpm/rpmdb.sqlite": loadFixture(t),
		},
	}

	tracked, err := scanRPM(fs)
	if err != nil {
		t.Fatalf("scanRPM: %v", err)
	}
	if len(tracked) == 0 {
		t.Fatal("scanRPM returned no tracked files")
	}

	// Paths known to be owned by packages in the fixture.
	want := []string{
		"/usr/lib64/libbz2.so.1.0.8",
		"/usr/lib64/liblz4.so.1.9.3",
		"/usr/lib64/libnghttp2.so.14.20.1",
		"/usr/share/publicsuffix/public_suffix_list.dafsa",
	}
	for _, p := range want {
		if _, ok := tracked[p]; !ok {
			t.Errorf("expected %q to be tracked", p)
		}
	}

	// Every tracked path must be absolute.
	for p := range tracked {
		if !filepath.IsAbs(p) {
			t.Errorf("tracked path %q is not absolute", p)
		}
	}
}

func TestScanRPMContinuesAfterCorruptPackage(t *testing.T) {
	path, cleanup, err := writeTempDB(loadFixture(t))
	if err != nil {
		t.Fatalf("writeTempDB: %v", err)
	}
	defer cleanup()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture database: %v", err)
	}
	if _, err := db.Exec("INSERT INTO Packages(blob) VALUES (?)", make([]byte, 8)); err != nil {
		db.Close()
		t.Fatalf("insert corrupt package: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture database: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture database: %v", err)
	}
	tracked, err := scanRPM(&image.ImageFS{
		FileContent: map[string][]byte{"/var/lib/rpm/rpmdb.sqlite": data},
	})
	if err != nil {
		t.Fatalf("scanRPM: %v", err)
	}
	if _, ok := tracked["/usr/lib64/libbz2.so.1.0.8"]; !ok {
		t.Error("valid package files should still be tracked when another package is corrupt")
	}
}

// TestScanRPMViaTrackedFiles checks the full dispatch path: a Fedora-style
// os-release routes through detect() to scanRPM, and the database located at
// the newer /usr/lib/sysimage/rpm path is found.
func TestScanRPMViaTrackedFiles(t *testing.T) {
	fs := &image.ImageFS{
		OsRelease: map[string]string{"ID": "fedora"},
		FileContent: map[string][]byte{
			"/usr/lib/sysimage/rpm/rpmdb.sqlite": loadFixture(t),
		},
	}

	tracked, distro, err := TrackedFiles(fs)
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	if distro != "rpm" {
		t.Errorf("distro = %q, want rpm", distro)
	}
	if _, ok := tracked["/usr/lib64/libbz2.so.1.0.8"]; !ok {
		t.Error("expected libbz2 to be tracked via sysimage rpmdb path")
	}
}

func TestScanRPMNoDatabase(t *testing.T) {
	fs := &image.ImageFS{FileContent: map[string][]byte{}}
	tracked, err := scanRPM(fs)
	if err != nil {
		t.Fatalf("scanRPM with no database should not error: %v", err)
	}
	if len(tracked) != 0 {
		t.Errorf("expected empty set, got %d entries", len(tracked))
	}
}

func TestScanRPMEmptyFileIgnored(t *testing.T) {
	// A zero-length database file (e.g. a placeholder) must be treated as "no
	// database", not passed to the parser.
	fs := &image.ImageFS{FileContent: map[string][]byte{
		"/var/lib/rpm/rpmdb.sqlite": {},
	}}
	tracked, err := scanRPM(fs)
	if err != nil {
		t.Fatalf("scanRPM: %v", err)
	}
	if len(tracked) != 0 {
		t.Errorf("expected empty set, got %d entries", len(tracked))
	}
}

func TestScanRPMRefusesBerkeleyDB(t *testing.T) {
	// A BerkeleyDB database must be refused (not parsed partially), in either
	// byte order, regardless of the filename it is stored under.
	for _, tc := range []struct {
		name string
		path string
		data []byte
	}{
		{"little-endian Packages", "/var/lib/rpm/Packages", bdbHeader(false)},
		{"big-endian Packages", "/var/lib/rpm/Packages", bdbHeader(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := &image.ImageFS{FileContent: map[string][]byte{tc.path: tc.data}}
			_, err := scanRPM(fs)
			if !errors.Is(err, ErrBerkeleyDBUnsupported) {
				t.Errorf("scanRPM err = %v, want ErrBerkeleyDBUnsupported", err)
			}
		})
	}
}

// TestScanRPMBerkeleyDBSurfacedAsWarning checks the end-to-end dispatch: a
// BerkeleyDB image is detected as rpm and its unsupported-format error is
// returned by TrackedFiles (where the CLI surfaces it as a warning), with no
// tracked files.
func TestScanRPMBerkeleyDBSurfacedAsWarning(t *testing.T) {
	fs := &image.ImageFS{
		OsRelease:   map[string]string{"ID": "centos"},
		FileContent: map[string][]byte{"/var/lib/rpm/Packages": bdbHeader(false)},
	}
	tracked, distro, err := TrackedFiles(fs)
	if distro != "rpm" {
		t.Errorf("distro = %q, want rpm", distro)
	}
	if !errors.Is(err, ErrBerkeleyDBUnsupported) {
		t.Errorf("TrackedFiles err = %v, want ErrBerkeleyDBUnsupported", err)
	}
	if len(tracked) != 0 {
		t.Errorf("expected no tracked files for a refused BerkeleyDB, got %d", len(tracked))
	}
}

// TestScanRPMPrefersSQLiteOverBerkeleyDB ensures a transitional image carrying
// both databases is read via the reliable SQLite file rather than refused.
func TestScanRPMPrefersSQLiteOverBerkeleyDB(t *testing.T) {
	fs := &image.ImageFS{FileContent: map[string][]byte{
		"/var/lib/rpm/Packages":     bdbHeader(false),
		"/var/lib/rpm/rpmdb.sqlite": loadFixture(t),
	}}
	tracked, err := scanRPM(fs)
	if err != nil {
		t.Fatalf("scanRPM: %v", err)
	}
	if _, ok := tracked["/usr/lib64/libbz2.so.1.0.8"]; !ok {
		t.Error("expected SQLite database to be used when both formats are present")
	}
}

// TestScanRPMDatabaseErrorNotSilent guards the regression mosabua flagged: a
// database that opens but cannot be read (here a valid SQLite file missing the
// Packages table) must surface as an error, not an apparently-successful scan
// with zero tracked files that would mark every file in the image dark.
func TestScanRPMDatabaseErrorNotSilent(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "rpmdb-*.sqlite")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	f.Close()

	db, err := sql.Open("sqlite", f.Name())
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// A real SQLite database, but without the Packages table go-rpmdb queries.
	if _, err := db.Exec("CREATE TABLE NotPackages (blob BLOB)"); err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}

	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read sqlite: %v", err)
	}
	tracked, err := scanRPM(&image.ImageFS{
		FileContent: map[string][]byte{"/var/lib/rpm/rpmdb.sqlite": data},
	})
	if err == nil {
		t.Fatalf("expected a database-read error, got nil (tracked=%d)", len(tracked))
	}
}

func TestScanRPMMalformedDatabase(t *testing.T) {
	// Non-rpm bytes under a database path must surface as an error rather than
	// silently returning nothing.
	fs := &image.ImageFS{FileContent: map[string][]byte{
		"/var/lib/rpm/Packages": []byte("this is not an rpm database"),
	}}
	if _, err := scanRPM(fs); err == nil {
		t.Error("expected an error for a malformed rpm database, got nil")
	}
}
