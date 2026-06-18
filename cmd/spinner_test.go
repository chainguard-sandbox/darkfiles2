package cmd

import (
	"errors"
	"os"
	"testing"
)

// When the output is not a terminal (here, a regular file), the spinner must
// stay completely silent so it never corrupts piped/redirected output.
func TestSpinnerDisabledOnNonTTY(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "spin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	s := newSpinner(f, "working")
	if s.enabled {
		t.Fatal("spinner should be disabled when output is a regular file")
	}
	s.Start()
	s.SetMessage("still working")
	s.Stop()

	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Errorf("spinner wrote %d bytes to a non-TTY, want 0", fi.Size())
	}
}

func TestWithSpinnerRunsFnAndPropagatesError(t *testing.T) {
	ran := false
	if err := withSpinner("noop", func() error { ran = true; return nil }); err != nil {
		t.Errorf("withSpinner returned %v, want nil", err)
	}
	if !ran {
		t.Error("withSpinner did not run fn")
	}

	want := errors.New("boom")
	if got := withSpinner("noop", func() error { return want }); !errors.Is(got, want) {
		t.Errorf("withSpinner error = %v, want %v", got, want)
	}
}
