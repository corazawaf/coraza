// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"errors"
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
		// If we are beyond the limit and the directive is to reject the request,
		// we don't record the body anymore.
		// // This point should never be reached if the connector is properly
		// implemented (runs ProcessBody and stops writing once limit is reached)
		return 0, errors.New("buffer limit already rached")
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
			// TinyGo: Bytes beyond MemoryLimit are not written (no disk buffer)
			br.lengthIsBeyondLimit = true
			maxWritingDataLen := br.options.MemoryLimit - br.length
			if maxWritingDataLen == 0 {
				return 0, nil
			}
			br.length = br.options.MemoryLimit
			if br.options.DiscardOnBodyLimit {
				return 0, nil
			} else {
				// Writing up to MemoryLimit (equals to Limit for TinyGo)
				return br.buffer.Write(data[:maxWritingDataLen])
			}
		} else {
			// Default: bytes are buffered to disk until Limit is reached
			// First, total limit is checked
			if targetLen >= br.options.Limit {
				br.lengthIsBeyondLimit = true
				if br.options.DiscardOnBodyLimit {
					// Request is going to be discarded, no need to allocate disk buffer
					return 0, nil
				}
			}
			// A disk writer is needed: Process partial or total limit not exceeded
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
			if targetLen >= br.options.Limit {
				// Writing up to Limit
				maxWritingDataLen := br.options.Limit - br.length
				br.length = br.options.Limit
				return br.writer.Write(data[:maxWritingDataLen])
			}
			// Limit not reached, writing the whole data
			br.length = targetLen
			return br.writer.Write(data)
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
