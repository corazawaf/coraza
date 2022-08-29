// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"os"
	"path/filepath"
	"testing"
)

const fileContent = "abc123"

func getTestFile(t *testing.T) (string, string) {
	t.Helper()
	tmpDir := t.TempDir()
	tmpFile, err := os.Create(filepath.Join(tmpDir, "tmpfile"))
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.WriteString(fileContent)
	return tmpDir, tmpFile.Name()
}

func TestLoadFromFileNoExist(t *testing.T) {
	content, err := loadFromFile("non-existing-file", []string{t.TempDir()})
	if err == nil {
		t.Errorf("expected error: %s", os.ErrNotExist.Error())
	}

	if len(content) != 0 {
		t.Errorf("expected empty content, got %q", content)
	}
}

func TestLoadFromFileAbsolutePath(t *testing.T) {
	_, testFile := getTestFile(t)
	absFilepath, err := filepath.Abs(testFile)
	if err != nil {
		t.Fatal(err)
	}

	content, err := loadFromFile(absFilepath, nil)
	if err != nil {
		t.Error(err)
	}

	if want, have := fileContent, string(content); want != have {
		t.Errorf("unexpected content, want %q, have %q", want, have)
	}
}

func TestLoadFromFileRelativePath(t *testing.T) {
	testDir, testFile := getTestFile(t)

	content, err := loadFromFile(testFile, []string{"/does-not-exist", testDir})
	if err != nil {
		t.Error(err)
	}

	if want, have := fileContent, string(content); want != have {
		t.Errorf("unexpected content, want %q, have %q", want, have)
	}
}
