// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/types"
)

func TestBodyReaderMemory(t *testing.T) {
	br := NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     t.TempDir(),
		MemoryLimit: 500,
		Limit:       500,
	})
	if _, err := br.Write([]byte("test")); err != nil {
		t.Error(err)
	}
	buf := new(strings.Builder)
	reader, err := br.Reader()
	if err != nil {
		t.Error(err)
	}
	if _, err := io.Copy(buf, reader); err != nil {
		t.Error(err)
	}
	if buf.String() != "test" {
		t.Error("Failed to get BodyReader from memory")
	}
	_ = br.Reset()
}

func TestBodyReaderFile(t *testing.T) {
	if environment.IsTinyGo {
		return // t.Skip doesn't work on TinyGo
	}

	// body reader memory limit is 1 byte
	br := NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     t.TempDir(),
		MemoryLimit: 1,
		Limit:       100,
	})
	if _, err := br.Write([]byte("test")); err != nil {
		t.Error(err)
	}
	buf := new(strings.Builder)
	reader, err := br.Reader()
	if err != nil {
		t.Error(err)
	}
	if _, err := io.Copy(buf, reader); err != nil {
		t.Error(err)
	}
	if buf.String() != "test" {
		t.Error("Failed to get BodyReader from file")
	}
	// Let's check if files are being deleted
	f := br.writer
	if _, err := os.Stat(f.Name()); os.IsNotExist(err) {
		t.Error("BodyReader's Tmp file does not exist")
	}
	_ = br.Reset()
	if _, err := os.Stat(f.Name()); err == nil {
		t.Error("BodyReader's Tmp file was not deleted")
	}
}

func TestBodyReaderWriteFromReader(t *testing.T) {
	br := NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     t.TempDir(),
		MemoryLimit: 5,
		Limit:       5,
	})
	b := strings.NewReader("test")
	if _, err := io.Copy(br, b); err != nil {
		t.Error(err)
	}
	buf := new(strings.Builder)
	reader, err := br.Reader()
	if err != nil {
		t.Error(err)
	}
	if _, err := io.Copy(buf, reader); err != nil {
		t.Error(err)
	}
	if buf.String() != "test" {
		t.Error("Failed to write bodyreader from io.Reader")
	}
	_ = br.Reset()
}

func TestWriteLimit(t *testing.T) {
	testCases := map[string]struct {
		name               string
		initialBytes       []byte
		toBeWrittenBytes   []byte
		bodyBufferOptions  types.BodyBufferOptions
		expectedWriteError bool
	}{
		"last byte written": {
			toBeWrittenBytes: []byte("abc"),
			bodyBufferOptions: types.BodyBufferOptions{
				MemoryLimit: 3,
				Limit:       3,
			},
			expectedWriteError: false,
		},
		"over limit": {
			toBeWrittenBytes: []byte("abc"),
			bodyBufferOptions: types.BodyBufferOptions{
				MemoryLimit: 2,
				Limit:       2,
			},
			expectedWriteError: true,
		},
		"over limit when limit already reached": {
			initialBytes:     []byte("abc"), // buffer will reach its limit
			toBeWrittenBytes: []byte("a"),
			bodyBufferOptions: types.BodyBufferOptions{
				MemoryLimit: 3,
				Limit:       3,
			},
			expectedWriteError: true,
		},
	}
	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			br := NewBodyBuffer(tCase.bodyBufferOptions)
			_, err := br.Write(tCase.initialBytes)
			if err != nil {
				t.Fatalf("unexpected error writing initial buffer: %v", err)
			}
			writtenBytes, err := br.Write(tCase.toBeWrittenBytes)
			if tCase.expectedWriteError && err == nil {
				t.Fatal("unexpected successful Write above Limit")
			}
			if !tCase.expectedWriteError && writtenBytes != len(tCase.toBeWrittenBytes) {
				t.Fatalf("unexpected number of bytes written, want %d, have %d", len(tCase.toBeWrittenBytes), writtenBytes)
			}
			_ = br.Reset()
		})
	}

}
