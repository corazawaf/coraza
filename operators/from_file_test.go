// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"os"
	"path"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/corazawaf/coraza/v3/internal/io"
)

const fileContent = "abc123"

func getTestFile(t *testing.T) (string, string) {
	t.Helper()
	tmpDir := t.TempDir()
	filename := "tmpfile"
	err := os.WriteFile(filepath.Join(tmpDir, filename), []byte(fileContent), 0755)
	if err != nil {
		t.Fatal(err)
	}
	return tmpDir, filename
}

func TestLoadFromFileNoPaths(t *testing.T) {
	_, err := loadFromFile("non-existing-file", nil, io.OSFS{})
	if err == nil {
		t.Errorf("expected error: %s", errEmptyPaths.Error())
	}
}

func TestLoadFromFileNoExist(t *testing.T) {
	content, err := loadFromFile("non-existing-file", []string{t.TempDir()}, io.OSFS{})
	if err == nil {
		t.Errorf("expected error: %s", os.ErrNotExist.Error())
	}

	if len(content) != 0 {
		t.Errorf("expected empty content, got %q", content)
	}
}

func TestLoadFromFileAbsolutePath(t *testing.T) {
	testDir, testFile := getTestFile(t)

	content, err := loadFromFile(path.Join(testDir, testFile), nil, io.OSFS{})
	if err != nil {
		t.Error(err)
	}

	if want, have := fileContent, string(content); want != have {
		t.Errorf("unexpected content, want %q, have %q", want, have)
	}
}

func TestLoadFromFileRelativePath(t *testing.T) {
	testDir, testFile := getTestFile(t)

	content, err := loadFromFile(testFile, []string{"/does-not-exist", testDir}, io.OSFS{})
	if err != nil {
		t.Errorf("failed to load from file: %s", err.Error())
	}

	if want, have := fileContent, string(content); want != have {
		t.Errorf("unexpected content, want %q, have %q", want, have)
	}
}

func TestLoadFromCustomFS(t *testing.T) {
	fs := fstest.MapFS{}
	fs["animals/bear.txt"] = &fstest.MapFile{Data: []byte("pooh"), Mode: 0755}

	content, err := loadFromFile("bear.txt", []string{"animals"}, fs)
	if err != nil {
		t.Errorf("failed to load from file: %s", err.Error())
	}

	if want, have := "pooh", string(content); want != have {
		t.Errorf("unexpected content, want %q, have %q", want, have)
	}
}
