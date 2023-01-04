// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"io"
	"math"
	"os"

	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/types"
)

// BodyBuffer is used to read RequestBody and ResponseBody objects
// It will handle memory usage for buffering and processing
// It implements io.Copy(bodyBuffer, someReader) by inherit io.Writer
type BodyBuffer struct {
	options             types.BodyBufferOptions
	buffer              *bytes.Buffer
	writer              *os.File
	length              int64
	lengthIsBeyondLimit bool
}

// Write appends data to the body buffer by chunks
// You may dump io.Readers using io.Copy(br, reader)
func (br *BodyBuffer) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		return 0, nil
	}

	if br.lengthIsBeyondLimit && br.options.DiscardOnBodyLimit {
		// if we are beyond the limit and the directive is to reject
		// the request, we don't record the body anymore.
		return 0, nil
	}

	var targetLen int64
	// Overflow check
	if br.length == math.MaxInt64 || br.length >= (math.MaxInt64-int64(len(data))) {
		// Overflow, buffer length will always be at most MaxInt
		targetLen = math.MaxInt64
	} else {
		// No Overflow
		targetLen = br.length + int64(len(data))
	}

	// Check if memory or disk limits are reached
	// Even if Overflow is explicitly checked, MemoryLimit real limits are below maxInt and machine dependenent.
	// bytes.Buffer growth is platform dependent with a growth rate capped at 2x. If the buffer can't grow it will panic with ErrTooLarge.
	// See https://github.com/golang/go/blob/go1.19.4/src/bytes/buffer.go#L117 and https://go-review.googlesource.com/c/go/+/349994
	// Local tests show these buffer limits:
	// 32-bit machine: 2147483647 (2^30, 1GiB)
	// 64-bit machine: 34359738368 (2^35, 32GiB) (Not reached the ErrTooLarge panic, the OS triggered an OOM)
	if targetLen > br.options.MemoryLimit {
		if environment.IsTinyGo {
			br.lengthIsBeyondLimit = true
			maxWritingDataLen := br.options.MemoryLimit - br.length
			if maxWritingDataLen == 0 {
				return 0, nil
			}
			br.length = br.options.MemoryLimit
			if br.options.DiscardOnBodyLimit {
				return 0, nil
			} else {
				// TinyGo: If Bytes are beyond MemoryLimit, and DiscardOnBodyLimit is not enable,
				// we still have to buffer them (Connectors rely on Coraza buffering the request)
				return br.buffer.Write(data)
				// return br.buffer.Write(data[:maxWritingDataLen])
			}
		} else {
			// Default: bytes are buffered to disk
			if br.writer == nil {
				defer br.buffer.Reset()
				br.writer, err = os.CreateTemp(br.options.TmpPath, "body*")
				if err != nil {
					return 0, err
				}
				// We dump the previous buffer
				if _, err := br.writer.Write(br.buffer.Bytes()); err != nil {
					return 0, err
				}
			}

			// Total limit is checked
			if targetLen >= br.options.Limit {
				br.lengthIsBeyondLimit = true
				if br.options.DiscardOnBodyLimit {
					return 0, nil
				} else {
					// Connectors rely on Coraza buffering the whole request, therefore,
					// if ProcessPartial is set, bytes beyond Limit are still buffered
					return br.writer.Write(data)
				}
			} else {
				// Total limit not exceeded, bytes are sent to disk
				br.length = targetLen
				return br.writer.Write(data)
			}
		}
	}

	br.length = targetLen
	return br.buffer.Write(data)
}

// Reader Returns a working reader for the body buffer in memory or file
func (br *BodyBuffer) Reader() (io.Reader, error) {
	if environment.IsTinyGo || br.writer == nil {
		return bytes.NewReader(br.buffer.Bytes()), nil
	}
	if _, err := br.writer.Seek(0, 0); err != nil {
		return nil, err
	}
	return br.writer, nil
}

func (br *BodyBuffer) IsEmpty() bool {
	return br.length == 0 && !br.lengthIsBeyondLimit
}

func (br *BodyBuffer) IsBeyondLimit() bool {
	return br.lengthIsBeyondLimit
}

// Reset will reset buffers and delete temporary files
func (br *BodyBuffer) Reset() error {
	br.buffer.Reset()
	br.length = 0
	if !environment.IsTinyGo && br.writer != nil {
		w := br.writer
		br.writer = nil
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
		options: options,
		buffer:  &bytes.Buffer{},
	}
}
