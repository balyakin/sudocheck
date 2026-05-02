package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildSuidBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "find")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 04755); err != nil {
		t.Fatal(err)
	}

	file, err := buildSuidBinary(path, map[string]bool{"suid": true})
	if err != nil {
		t.Fatal(err)
	}

	if file.BinaryName != "find" {
		t.Fatalf("unexpected binary name: %s", file.BinaryName)
	}
	if file.Type != "suid" {
		t.Fatalf("unexpected type: %s", file.Type)
	}
	if file.Perms == "" {
		t.Fatal("expected permissions")
	}
}

func TestFormatSuidTypeCombinesBits(t *testing.T) {
	typeName := formatSuidType(map[string]bool{
		"suid": true,
		"sgid": true,
	})

	if typeName != "suid+sgid" {
		t.Fatalf("unexpected type: %s", typeName)
	}
}

func TestFormatPermissionsIncludesSuidBit(t *testing.T) {
	permissions := formatPermissions(os.FileMode(0755) | os.ModeSetuid)

	if permissions != "4755" {
		t.Fatalf("unexpected permissions: %s", permissions)
	}
}
