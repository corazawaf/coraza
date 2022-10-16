// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"errors"
	"io"
	"os"

	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/types"
)

// BodyBuffer is used to read RequestBody and ResponseBody objects
// It will handle memory usage for buffering and processing
// It implements io.Copy(bodyBuffer, someReader) by inherit io.Writer
type BodyBuffer struct {
	io.Writer
	options  types.BodyBufferOptions
	buffer   *bytes.Buffer
	writer   *os.File
	length   int64
	isClosed bool
}

var errAlreadyClosed = errors.New("buffer already closed")

// Write appends data to the body buffer by chunks
// You may dump io.Readers using io.Copy(br, reader)
func (br *BodyBuffer) Write(data []byte) (n int, err error) {
	if br.isClosed {
		return 0, errAlreadyClosed
	}

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
			return br.buffer.Write(data[:maxWritingDataLen])
		} else {
			if br.writer == nil {
				br.writer, err = os.CreateTemp(br.options.TmpPath, "body*")
				if err != nil {
					return 0, err
				}
				// we dump the previous buffer
				if _, err := br.writer.Write(br.buffer.Bytes()); err != nil {
					return 0, err
				}
				defer br.buffer.Reset()
			}
			br.length = l
			return br.writer.Write(data)
		}
	}

	br.length = l
	return br.buffer.Write(data)
}

// Reader Returns a working reader for the body buffer in memory or file
func (br *BodyBuffer) Reader() (io.Reader, error) {
	if br.isClosed {
		return nil, errAlreadyClosed
	}

	if environment.IsTinyGo || br.writer == nil {
		return bytes.NewReader(br.buffer.Bytes()), nil
	}
	if _, err := br.writer.Seek(0, 0); err != nil {
		return nil, err
	}
	return br.writer, nil
}

// Size returns the current size of the body buffer
func (br *BodyBuffer) Size() int64 {
	if br.isClosed {
		return 0
	}

	return br.length
}

// Close will close all readers and delete temporary files
func (br *BodyBuffer) Close() error {
	if br.isClosed {
		return nil
	}

	br.isClosed = true
	br.buffer.Reset()
	br.buffer = nil
	if !environment.IsTinyGo && br.writer != nil {
		if err := br.writer.Close(); err != nil {
			return err
		}
		return os.Remove(br.writer.Name())
	}

	return nil
}

// NewBodyBuffer Initializes a body reader
// After writing memLimit bytes to the memory buffer, data will be
// written to a temporary file
// Temporary files will be written to tmpDir
func NewBodyBuffer(options types.BodyBufferOptions) *BodyBuffer {
	return &BodyBuffer{
		options: options,
		buffer:  &bytes.Buffer{},
	}
}
