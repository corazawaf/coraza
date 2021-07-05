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
type BodyReader struct {
	io.Writer   //OK?
	tmpDir      string
	buffer      *bytes.Buffer
	writter     *os.File
	length      int64
	memoryLimit int64
}

// Write appends data to the body buffer by chunks
// You may dump io.Readers using io.Copy(br, reader)
func (br *BodyReader) Write(data []byte) (n int, err error) {
	l := int64(len(data)) + br.length
	if l >= br.memoryLimit {
		if br.writter == nil {
			br.writter, err = os.CreateTemp(br.tmpDir, "body*")
			if err != nil {
				return 0, err
			}
			// we dump the previous buffer
			br.writter.Write(br.buffer.Bytes())
			defer br.buffer.Reset()
		}
		br.length = l
		return br.writter.Write(data)
	}
	br.length = l
	return br.buffer.Write(data)
}

// Reader Returns a working reader for the body buffer in memory or file
func (br *BodyReader) Reader() io.Reader {
	if br.writter == nil {
		return bytes.NewReader(br.buffer.Bytes())
	}
	br.writter.Seek(0, 0)
	return br.writter
}

// String returns a string with the whole body buffer
// In some cases it will be needed for body processing
func (br *BodyReader) String() string {
	buf := new(strings.Builder)
	io.Copy(buf, br.Reader())
	return buf.String()
}

// Size returns the current size of the body buffer
func (br *BodyReader) Size() int64 {
	return br.length
}

// Close will close all readers and delete temporary files
func (br *BodyReader) Close() {
	if br.writter == nil {
		return
	}
	br.writter.Close()
	os.Remove(br.writter.Name())
}

// NewBodyReader Initializes a body reader
// Temporary files will be written to tmpDir
// After writing memLimit bytes to the memory buffer, data will be
// written to a temporary file
func NewBodyReader(tmpDir string, memLimit int64) *BodyReader {
	return &BodyReader{
		buffer:      &bytes.Buffer{},
		tmpDir:      tmpDir,
		memoryLimit: memLimit,
	}
}
