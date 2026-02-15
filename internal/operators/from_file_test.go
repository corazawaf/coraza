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
	"github.com/stretchr/testify/require"
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
	require.Error(t, err, "expected error: %s", errEmptyDirs.Error())
}

func TestLoadFromFileNoExist(t *testing.T) {
	content, err := loadFromFile("non-existing-file", []string{t.TempDir()}, io.OSFS{})
	require.Error(t, err, "expected error: %s", os.ErrNotExist.Error())

	require.Empty(t, content, "expected empty content, got %q", content)
}

func TestLoadFromFileAbsolutePath(t *testing.T) {
	testDir, testFile := getTestFile(t)

	content, err := loadFromFile(path.Join(testDir, testFile), nil, io.OSFS{})
	require.NoError(t, err)

	require.Equal(t, fileContent, string(content), "unexpected content")
}

func TestLoadFromFileRelativePath(t *testing.T) {
	testDir, testFile := getTestFile(t)

	content, err := loadFromFile(testFile, []string{"/does-not-exist", testDir}, io.OSFS{})
	require.NoError(t, err, "failed to load from file")

	require.Equal(t, fileContent, string(content), "unexpected content")
}

func TestLoadFromCustomFS(t *testing.T) {
	fs := fstest.MapFS{}
	fs["animals/bear.txt"] = &fstest.MapFile{Data: []byte("pooh"), Mode: 0755}

	content, err := loadFromFile("bear.txt", []string{"animals"}, fs)
	require.NoError(t, err, "failed to load from file")

	require.Equal(t, "pooh", string(content), "unexpected content")
}
