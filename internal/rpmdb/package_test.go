package rpmdb

import "testing"

// TestInstalledFileNamesRejectsNegativeDirIndex guards the regression mosabua
// flagged: a corrupt or hostile package header with a negative directory index
// must be rejected with an error rather than panicking on the slice index.
func TestInstalledFileNamesRejectsNegativeDirIndex(t *testing.T) {
	p := &PackageInfo{
		Name:       "evil",
		DirNames:   []string{"/usr/bin/"},
		BaseNames:  []string{"sh"},
		DirIndexes: []int32{-1},
	}

	files, err := p.InstalledFileNames() // must not panic
	if err == nil {
		t.Fatalf("expected an error for a negative directory index, got files=%v", files)
	}
}

// TestInstalledFileNamesValid confirms the guard does not reject well-formed
// indexes.
func TestInstalledFileNamesValid(t *testing.T) {
	p := &PackageInfo{
		Name:       "ok",
		DirNames:   []string{"/usr/bin/", "/etc/"},
		BaseNames:  []string{"sh", "hosts"},
		DirIndexes: []int32{0, 1},
	}

	files, err := p.InstalledFileNames()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]bool{"/usr/bin/sh": true, "/etc/hosts": true}
	if len(files) != len(want) {
		t.Fatalf("got %v, want %v", files, want)
	}
	for _, f := range files {
		if !want[f] {
			t.Errorf("unexpected file %q", f)
		}
	}
}
