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
	options types.BodyBufferOptions
	buffer  *bytes.Buffer
	writer  *os.File
	length  int64
	readers []*bodyBufferReader
}

var (
	_ io.WriterTo = (*BodyBuffer)(nil)
	_ io.Writer   = (*BodyBuffer)(nil)
)

func (br *BodyBuffer) WriteTo(w io.Writer) (int64, error) {
	if br.writer == nil {
		return br.buffer.WriteTo(w)
	}

	b := make([]byte, br.length)

	n, err := br.writer.Read(b)
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

	// Checks if the limit has been already reached and if the new data will exceed it.
	// if br.length == br.options.Limit the error will be always raised because len(data) at this point will always be >=1
	if br.length > (br.options.Limit - int64(len(data))) {
		// Write has been called without checking the Limit, it should never happen. Raising an error.
		// The buffers are private and populated only by WriteRequestBody, ReadRequestBodyFrom, and similar functions
		// that have to perform limit checks before calling Write()
		return 0, errors.New("limit reached while writing")
	}
	targetLen := br.length + int64(len(data))

	// Check if memory limits are reached
	// Even if Overflow is explicitly checked, MemoryLimit real limits are below maxInt and machine dependenent.
	// bytes.Buffer growth is platform dependent with a growth rate capped at 2x. If the buffer can't grow it will panic with ErrTooLarge.
	// See https://github.com/golang/go/blob/go1.19.4/src/bytes/buffer.go#L117 and https://go-review.googlesource.com/c/go/+/349994
	// Local tests show these buffer limits:
	// 32-bit machine: 1073741824 (2^30, 1GiB)
	// 64-bit machine: 34359738368 (2^35, 32GiB) (Not reached the ErrTooLarge panic, the OS triggered an OOM)
	if targetLen > br.options.MemoryLimit {
		if !environment.HasAccessToFS {
			// TinyGo MemoryLimit should be equal to Limit. Therefore, Write function has been called without Limit check.
			return 0, errors.New("memoryLimit reached while writing")
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
				br.buffer.Reset()
			}
			br.length = targetLen
			return br.writer.Write(data)
		}
	}

	br.length = targetLen
	return br.buffer.Write(data)
}

type bodyBufferReader struct {
	pos int
	// err, when set, is returned by every Read; used to surface
	// types.ErrBodyTruncated on readers invalidated by Truncate.
	err error
	br  *BodyBuffer
}

func (b *bodyBufferReader) Read(p []byte) (n int, err error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.br == nil {
		// reader has been closed and hence we don't attempt to do anymore read
		return 0, io.EOF
	}

	if !environment.HasAccessToFS || b.br.writer == nil {
		buf := b.br.buffer.Bytes()

		n = len(p)
		if b.pos+n > len(buf) {
			n = len(buf) - b.pos
		}
		if n == 0 {
			return 0, io.EOF
		}

		an := copy(p, buf[b.pos:b.pos+n])
		b.pos += an
		return an, nil
	}

	n, err = b.br.writer.ReadAt(p, int64(b.pos))
	b.pos += n
	return
}

// Close closes the reader
func (b *bodyBufferReader) Close() {
	b.br = nil
	b.pos = 0
}

// Reader Returns a working reader for the body buffer in memory or file
func (br *BodyBuffer) Reader() (io.Reader, error) {
	r := &bodyBufferReader{
		br: br,
	}
	br.readers = append(br.readers, r)
	return r, nil
}

// Size returns the current size of the body buffer
func (br *BodyBuffer) Size() int64 {
	return br.length
}

// Truncate discards all buffered content beyond limit bytes, releasing the
// backing memory. The in-memory buffer is replaced with a fresh one holding
// only the prefix (bytes.Buffer.Truncate retains the full backing array,
// which transaction pooling would keep alive past Close); the file-backed
// buffer is truncated in place, or closed and removed when limit is 0.
// A limit at or above the current size is a no-op.
func (br *BodyBuffer) Truncate(limit int64) error {
	if limit >= br.length {
		return nil
	}

	if environment.HasAccessToFS && br.writer != nil {
		if limit == 0 {
			w := br.writer
			br.writer = nil
			br.length = 0
			br.invalidateReaders()
			err := w.Close()
			// remove even when Close fails: br.writer is already nil, so
			// this is the last reference to the file and Reset() would no
			// longer clean it up.
			if rmErr := os.Remove(w.Name()); err == nil {
				err = rmErr
			}
			return err
		}
		if err := br.writer.Truncate(limit); err != nil {
			// nothing changed: length and readers stay valid
			return err
		}
		br.length = limit
		br.invalidateReaders()
		return nil
	}
	fresh := &bytes.Buffer{}
	fresh.Write(br.buffer.Bytes()[:limit])
	br.buffer = fresh
	br.length = limit
	br.invalidateReaders()
	return nil
}

// invalidateReaders marks all outstanding readers with ErrBodyTruncated:
// reading with a position beyond a shrunk buffer would panic, and quietly
// serving the prefix or EOF would hide the contract violation of holding a
// reader across truncation. New readers (e.g. audit log part C) see the
// kept prefix.
func (br *BodyBuffer) invalidateReaders() {
	for _, r := range br.readers {
		r.br = nil
		r.err = types.ErrBodyTruncated
	}
	br.readers = nil
}

// Reset will reset buffers and delete temporary files
func (br *BodyBuffer) Reset() error {
	// A pooled transaction keeps its buffer, so a buffer grown by one large
	// body would stay allocated until the transaction is reused, or forever.
	if br.buffer.Cap() > bodyBufferKeepCap {
		br.buffer = &bytes.Buffer{}
	} else {
		br.buffer.Reset()
	}
	br.length = 0

	// close all readers, this is important because connectors may have
	// a reference to a reader but the transaction is already closed and
	// hence the reader is not valid anymore.
	for _, r := range br.readers {
		r.Close()
	}
	br.readers = nil

	if environment.HasAccessToFS && br.writer != nil {
		w := br.writer
		br.writer = nil
		if err := w.Close(); err != nil {
			return err
		}
		return os.Remove(w.Name())
	}

	return nil
}

// bodyBufferKeepCap is the largest in-memory buffer capacity Reset keeps for
// reuse; a larger buffer is dropped.
const bodyBufferKeepCap = 64 * 1024

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
