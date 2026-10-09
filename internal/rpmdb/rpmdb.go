// Package rpmdb reads the RPM package database. It is a vendored copy of
// github.com/knqyf263/go-rpmdb (MIT, see LICENSE), brought in-module so the
// project installs cleanly via `go install ...@latest` (a replace directive
// would prevent that) and so local fixes can be carried: a typed DBReadError
// distinguishing database-level failures from recoverable per-package errors,
// and a guard against negative directory indexes in InstalledFileNames.
package rpmdb

import (
	"github.com/chainguard-sandbox/darkfiles2/internal/rpmdb/bdb"
	dbi "github.com/chainguard-sandbox/darkfiles2/internal/rpmdb/db"
	"github.com/chainguard-sandbox/darkfiles2/internal/rpmdb/ndb"
	"github.com/chainguard-sandbox/darkfiles2/internal/rpmdb/sqlite3"
	"golang.org/x/xerrors"
)

type RpmDB struct {
	db dbi.RpmDBInterface
}

func Open(path string) (*RpmDB, error) {
	// SQLite3 Open() returns nil, nil in case of DB format other than SQLite3
	sqldb, err := sqlite3.Open(path)
	if err != nil && !xerrors.Is(err, sqlite3.ErrorInvalidSQLite3) {
		return nil, err
	}
	if sqldb != nil {
		return &RpmDB{db: sqldb}, nil
	}

	// NDB Open() returns nil, nil in case of DB format other than NDB
	ndbh, err := ndb.Open(path)
	if err != nil && !xerrors.Is(err, ndb.ErrorInvalidNDB) {
		return nil, err
	}
	if ndbh != nil {
		return &RpmDB{db: ndbh}, nil
	}

	odb, err := bdb.Open(path)
	if err != nil {
		return nil, err
	}

	return &RpmDB{
		db: odb,
	}, nil

}

func (d *RpmDB) Close() error {
	return d.db.Close()
}

func (d *RpmDB) Package(name string) (*PackageInfo, error) {
	pkgs, err := d.ListPackages()
	if err != nil {
		return nil, xerrors.Errorf("unable to list packages: %w", err)
	}

	for _, pkg := range pkgs {
		if pkg.Name == name {
			return pkg, nil
		}
	}
	return nil, xerrors.Errorf("%s is not installed", name)
}

func (d *RpmDB) ListPackages() ([]*PackageInfo, error) {
	var pkgList []*PackageInfo

	for entry := range d.db.Read() {
		if entry.Err != nil {
			return nil, entry.Err
		}

		indexEntries, err := headerImport(entry.Value)
		if err != nil {
			return nil, xerrors.Errorf("error during importing header: %w", err)
		}
		pkg, err := getNEVRA(indexEntries)
		if err != nil {
			return nil, xerrors.Errorf("invalid package info: %w", err)
		}
		pkgList = append(pkgList, pkg)
	}

	return pkgList, nil
}

type PackageEntry struct {
	Package *PackageInfo
	Err     error
}

// DBReadError wraps a failure to read the underlying rpm database — I/O, a
// failed query, a corrupt or unsupported container — as opposed to a
// recoverable error parsing a single package's header. Callers can use
// errors.As to tell a broken database (where an empty result means "trust
// nothing") apart from one bad package (which can be skipped).
type DBReadError struct{ Err error }

func (e *DBReadError) Error() string { return "rpm database read error: " + e.Err.Error() }
func (e *DBReadError) Unwrap() error { return e.Err }

func (d *RpmDB) ReadPackages() <-chan PackageEntry {
	packages := make(chan PackageEntry)

	go func() {
		defer close(packages)

		for entry := range d.db.Read() {
			if entry.Err != nil {
				// A failure from the database layer, not a single package.
				packages <- PackageEntry{Err: &DBReadError{Err: entry.Err}}
				continue
			}

			indexEntries, err := headerImport(entry.Value)
			if err != nil {
				packages <- PackageEntry{Err: xerrors.Errorf("error during importing header: %w", err)}
				continue
			}
			pkg, err := getNEVRA(indexEntries)
			if err != nil {
				packages <- PackageEntry{Err: xerrors.Errorf("invalid package info: %w", err)}
				continue
			}
			packages <- PackageEntry{Package: pkg}
		}
	}()

	return packages
}
