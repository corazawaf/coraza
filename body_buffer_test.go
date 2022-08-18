// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package coraza

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
		TmpPath:     "/tmp",
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
	br.Close()
}

func TestBodyReaderFile(t *testing.T) {
	if environment.IsTinyGo {
		return // t.Skip doesn't work on TinyGo
	}

	// body reader memory limit is 1 byte
	br := NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     "/tmp",
		MemoryLimit: 1,
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
	br.Close()
	if _, err := os.Stat(f.Name()); err == nil {
		t.Error("BodyReader's Tmp file was not deleted")
	}
}

func TestBodyReaderWriteFromReader(t *testing.T) {
	br := NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     "/tmp",
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
	br.Close()
}
