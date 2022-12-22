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
		Limit:       50,
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

func TestWriteOverLimit(t *testing.T) {
	if environment.IsTinyGo {
		return // t.Skip doesn't work on TinyGo
	}
	br := NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     t.TempDir(),
		MemoryLimit: 0,
		Limit:       2,
	})
	n, err := br.Write([]byte{'a', 'b', 'c', 'd', 'e'})
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if want, have := 2, n; want != have {
		t.Errorf("unexpected number of bytes in write, want: %d, have: %d", want, have)
	}

	reader, err := br.Reader()
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	buf, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := "ab", string(buf); want != have {
		t.Errorf("unexpected body in file, want: %s, have: %s", want, have)
	}
	_ = br.Reset()
}
