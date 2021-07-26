// Copyright 2021 Juan Pablo Tosso
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

package engine

import (
	"bytes"
	"io"
	"os"
	"strings"
)

// BoddyReader is used to read RequestBody and ResponseBody objects
// It will handle memory usage for buffering and processing
type BodyBuffer struct {
	io.Writer   //OK?
	tmpDir      string
	buffer      *bytes.Buffer
	writer      *os.File
	length      int64
	memoryLimit int64
}

// Write appends data to the body buffer by chunks
// You may dump io.Readers using io.Copy(br, reader)
func (br *BodyBuffer) Write(data []byte) (n int, err error) {
	l := int64(len(data)) + br.length
	if l >= br.memoryLimit {
		if br.writer == nil {
			br.writer, err = os.CreateTemp(br.tmpDir, "body*")
			if err != nil {
				return 0, err
			}
			// we dump the previous buffer
			br.writer.Write(br.buffer.Bytes())
			defer br.buffer.Reset()
		}
		br.length = l
		return br.writer.Write(data)
	}
	br.length = l
	return br.buffer.Write(data)
}

// Reader Returns a working reader for the body buffer in memory or file
func (br *BodyBuffer) Reader() io.Reader {
	if br.writer == nil {
		return bytes.NewReader(br.buffer.Bytes())
	}
	br.writer.Seek(0, 0)
	return br.writer
}

// String returns a string with the whole body buffer
// In some cases it will be needed for body processing
func (br *BodyBuffer) String() string {
	buf := new(strings.Builder)
	io.Copy(buf, br.Reader())
	return buf.String()
}

// Size returns the current size of the body buffer
func (br *BodyBuffer) Size() int64 {
	return br.length
}

// Close will close all readers and delete temporary files
func (br *BodyBuffer) Close() {
	if br.writer == nil {
		return
	}
	br.writer.Close()
	if br.writer != nil {
		os.Remove(br.writer.Name())
	}
}

// NewBodyReader Initializes a body reader
// After writing memLimit bytes to the memory buffer, data will be
// written to a temporary file
// Temporary files will be written to tmpDir
func NewBodyReader(tmpDir string, memLimit int64) *BodyBuffer {
	return &BodyBuffer{
		buffer:      &bytes.Buffer{},
		tmpDir:      tmpDir,
		memoryLimit: memLimit,
	}
}
