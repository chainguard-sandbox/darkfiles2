package gobin

import (
	"os"
	"testing"
)

func TestIsGoBinarySelf(t *testing.T) {
	// The running test binary is itself a Go binary with build info.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatalf("reading test binary: %v", err)
	}
	if !IsGoBinary(data) {
		t.Error("IsGoBinary(test binary) = false, want true")
	}
}

func TestIsGoBinaryRejectsNonGo(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":    nil,
		"script":   []byte("#!/bin/sh\necho hi\n"),
		"bare ELF": []byte("\x7fELF\x02\x01\x01\x00garbage"),
	} {
		if IsGoBinary(data) {
			t.Errorf("IsGoBinary(%s) = true, want false", name)
		}
	}
}
