// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package io

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

//go:embed testdata
var testdata embed.FS

func TestFSReadFile(t *testing.T) {
	testdir, err := os.MkdirTemp(t.TempDir(), "testdata")
	if err != nil {
		t.Fatal(err)
	}
	err = os.Mkdir(filepath.Join(testdir, "subdir"), os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(testdir, "subdir", "testfile.txt"), []byte("Hello World\n"), os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	realFS, err := fs.Sub(os.DirFS(testdir), ".")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		fail bool
		fs   fs.FS
	}{
		{name: "embed/unix path", path: "testdata/subdir/testfile.txt", fail: false, fs: testdata},
		{name: "embed/windows path", path: "testdata\\subdir\\testfile.txt", fail: runtime.GOOS != "windows", fs: testdata},
		{name: "embed/invalid", path: "testdata/subdir/notexist", fail: true, fs: testdata},
		{name: "real/unix path", path: "testdata/subdir/testfile.txt", fail: false, fs: realFS},
		{name: "real/windows path", path: "testdata\\subdir\\testfile.txt", fail: runtime.GOOS != "windows", fs: realFS},
		{name: "real/invalid", path: "testdata/subdir/notexist", fail: true, fs: realFS},
	}

	for _, next := range tests {
		test := next
		t.Run(test.name, func(t *testing.T) {
			data, err := FSReadFile(testdata, test.path)
			if test.fail {
				if err == nil {
					t.Fatal("expected an error but it is nil")
				}
				if data != nil {
					t.Fatal("expected data to be nil")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != "Hello World\n" {
					t.Fatal("unexpected output: \"", string(data), "\"")
				}
			}
		})
	}
}
