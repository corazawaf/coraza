// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"io"
	"os"

	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/types"
)

// BodyBuffer is used to read RequestBody and ResponseBody objects
// It will handle memory usage for buffering and processing
// It implements io.Copy(bodyBuffer, someReader) by inherit io.Writer
type BodyBuffer struct {
	options      types.BodyBufferOptions
	memoryBuffer *bytes.Buffer
	fileBuffer   *os.File
	length       int64
}

var (
	_ io.WriterTo = (*BodyBuffer)(nil)
	_ io.Writer   = (*BodyBuffer)(nil)
)

func (br *BodyBuffer) WriteTo(w io.Writer) (int64, error) {
	if br.fileBuffer == nil {
		return br.memoryBuffer.WriteTo(w)
	}

	b := make([]byte, br.length)

	n, err := br.fileBuffer.Read(b)
	if err != nil {
		return 0, err
	}

	n, err = w.Write(b[:n])
	return int64(n), err
}

// Write appends data to the body buffer by chunks
// You may dump io.Readers using io.Copy(br, reader)
func (br *BodyBuffer) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		return 0, nil
	}

	l := int64(len(data)) + br.length
	if l > br.options.MemoryLimit {
		if environment.IsTinyGo {
			maxWritingDataLen := br.options.MemoryLimit - br.length
			if maxWritingDataLen == 0 {
				return 0, nil
			}
			br.length = br.options.MemoryLimit
			return br.memoryBuffer.Write(data[:maxWritingDataLen])
		} else {
			if br.fileBuffer == nil {
				br.fileBuffer, err = os.CreateTemp(br.options.TmpPath, "body*")
				if err != nil {
					return 0, err
				}
				// we dump the previous buffer
				if _, err := br.fileBuffer.Write(br.memoryBuffer.Bytes()); err != nil {
					return 0, err
				}
				br.memoryBuffer.Reset()
			}
			br.length = l
			return br.fileBuffer.Write(data)
		}
	}

	br.length = l
	return br.memoryBuffer.Write(data)
}

type bodyBufferReader struct {
	pos int
	br  *BodyBuffer
}

func (b *bodyBufferReader) Read(p []byte) (n int, err error) {
	if environment.IsTinyGo || b.br.fileBuffer == nil {
		buf := b.br.memoryBuffer.Bytes()
		n = len(p)
		if b.pos+n > len(buf) {
			n = len(buf) - b.pos
		}
		if n == 0 {
			return 0, io.EOF
		}
		copy(p, buf[b.pos:b.pos+n])
		b.pos += n
		return
	}

	n, err = b.br.fileBuffer.ReadAt(p, int64(b.pos))
	b.pos += n
	return
}

// Reader Returns a working reader for the body buffer in memory or file
func (br *BodyBuffer) Reader() (io.Reader, error) {
	return &bodyBufferReader{
		br: br,
	}, nil
}

// Size returns the current size of the body buffer
func (br *BodyBuffer) Size() int64 {
	return br.length
}

// Reset will reset buffers and delete temporary files
func (br *BodyBuffer) Reset() error {
	br.memoryBuffer.Reset()
	br.length = 0
	if !environment.IsTinyGo && br.fileBuffer != nil {
		w := br.fileBuffer
		br.fileBuffer = nil
		if err := w.Close(); err != nil {
			return err
		}
		return os.Remove(w.Name())
	}

	return nil
}

// NewBodyBuffer Initializes a body reader
// After writing memLimit bytes to the memory buffer, data will be
// written to a temporary file
// Temporary files will be written to tmpDir
func NewBodyBuffer(options types.BodyBufferOptions) *BodyBuffer {
	return &BodyBuffer{
		options:      options,
		memoryBuffer: &bytes.Buffer{},
	}
}
