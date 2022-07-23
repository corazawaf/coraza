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

	"github.com/corazawaf/coraza/v2/types"
	"github.com/stretchr/testify/require"
)

func TestBodyReaderMemory(t *testing.T) {
	br := NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     "/tmp",
		MemoryLimit: 500,
	})

	_, err := br.Write([]byte("test"))
	require.NoError(t, err)

	buf := new(strings.Builder)
	reader, err := br.Reader()
	require.NoError(t, err)

	_, err = io.Copy(buf, reader)
	require.NoError(t, err)
	require.Equal(t, "test", buf.String(), "failed to get BodyReader from memory")
	require.NoError(t, br.Close())
}

func TestBodyReaderFile(t *testing.T) {
	// body reader memory limit is 1 byte
	br := NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     "/tmp",
		MemoryLimit: 1,
	})

	_, err := br.Write([]byte("test"))
	require.NoError(t, err)

	buf := new(strings.Builder)
	reader, err := br.Reader()
	require.NoError(t, err)

	_, err = io.Copy(buf, reader)
	require.NoError(t, err)
	require.Equal(t, "test", buf.String(), "failed to get BodyReader from file")

	// Let's check if files are being deleted
	f := br.writer
	_, err = os.Stat(f.Name())
	require.False(t, os.IsNotExist(err), "BodyReader's tmp file does not exist")
	br.Close()

	_, err = os.Stat(f.Name())
	require.Error(t, err, "BodyReader's Tmp file was not deleted")
}

func TestBodyReaderWriteFromReader(t *testing.T) {
	br := NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     "/tmp",
		MemoryLimit: 5,
	})
	b := strings.NewReader("test")

	_, err := io.Copy(br, b)
	require.NoError(t, err)

	buf := new(strings.Builder)
	reader, err := br.Reader()
	require.NoError(t, err)

	_, err = io.Copy(buf, reader)
	require.NoError(t, err)
	require.Equal(t, "test", buf.String(), "failed to write bodyreader from io.Reader")

	br.Close()
}
