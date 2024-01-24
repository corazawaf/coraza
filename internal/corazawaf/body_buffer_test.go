// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v4/internal/environment"
	"github.com/corazawaf/coraza/v4/types"
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
	if !environment.HasAccessToFS {
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
		initialBytes      []byte
		toBeWrittenBytes  []byte
		bodyBufferLimit   int64
		shouldReturnError bool
	}{
		"last byte written": {
			toBeWrittenBytes:  []byte("abc"),
			bodyBufferLimit:   3,
			shouldReturnError: false,
		},
		"over limit": {
			toBeWrittenBytes:  []byte("abc"),
			bodyBufferLimit:   2,
			shouldReturnError: true,
		},
		"over limit when limit already reached": {
			initialBytes:      []byte("abc"), // buffer will reach its limit
			toBeWrittenBytes:  []byte("a"),
			bodyBufferLimit:   3,
			shouldReturnError: true,
		},
	}
	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			br := NewBodyBuffer(types.BodyBufferOptions{
				MemoryLimit: tCase.bodyBufferLimit,
				Limit:       tCase.bodyBufferLimit,
			})
			_, err := br.Write(tCase.initialBytes)
			if err != nil {
				t.Fatalf("unexpected error writing initial buffer: %s", err.Error())
			}
			writtenBytes, err := br.Write(tCase.toBeWrittenBytes)
			if tCase.shouldReturnError && err == nil {
				t.Fatal("expected error when writing above the limit")
			}
			if !tCase.shouldReturnError && writtenBytes != len(tCase.toBeWrittenBytes) {
				t.Fatalf("unexpected number of bytes written, want: %d, have: %d", len(tCase.toBeWrittenBytes), writtenBytes)
			}
			_ = br.Reset()
		})
	}
}

// See https://github.com/corazawaf/coraza-caddy/issues/48
func TestBodyBufferResetAndReadTheReader(t *testing.T) {
	br := NewBodyBuffer(types.BodyBufferOptions{
		MemoryLimit: 5,
		Limit:       5,
	})
	br.Write([]byte("test1")) // nolint

	r, _ := br.Reader()

	dest := make([]byte, 5)
	nRead, err := r.Read(dest)
	if err != nil {
		t.Fatalf("unexpected error when creating reader %s", err.Error())
	}
	if nRead != 5 {
		t.Fatalf("unexpected number of bytes read, want: %d, have: %d", 5, nRead)
	}

	err = br.Reset()
	if err != nil {
		t.Fatalf("unexpected error %s", err.Error())
	}

	nCopied, err := io.Copy(io.Discard, r)
	if err != nil {
		t.Fatalf("unexpected error %s", err.Error())
	}
	if nCopied != 0 {
		t.Fatalf("unexpected number of bytes read, want: %d, have: %d", 5, nCopied)
	}
}
