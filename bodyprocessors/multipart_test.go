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

package bodyprocessors

import (
	"mime/multipart"
	"net/textproto"
	"os"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v2/types/variables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultipartProcessor(t *testing.T) {
	payload := `-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="text"

text default
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file1"; filename="a.txt"
Content-Type: text/plain

Content of a.txt.

-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file2"; filename="a.html"
Content-Type: text/html

<!DOCTYPE html><title>Content of a.html.</title>

-----------------------------9051914041544843365972754266--`
	payload = strings.ReplaceAll(payload, "\n", "\r\n")

	p := multipartBodyProcessor{}
	err := p.Read(strings.NewReader(payload), Options{
		Mime:        "multipart/form-data; boundary=---------------------------9051914041544843365972754266",
		StoragePath: "/tmp",
	})
	require.NoError(t, err)

	res := p.Collections()
	require.Len(t, res[variables.FilesNames][""], 2, "unexpected number of files")
	require.Len(t, res[variables.ArgsPostNames], 1, "unexpected number of args")

	require.NotEmpty(t, res[variables.ArgsPost]["text"])
	require.Equal(t, "text default", res[variables.ArgsPost]["text"][0], "Expected text3 to be 'some super text content 3', got %v", res[variables.ArgsPost])

	require.Len(t, res[variables.FilesTmpNames][""], 2, "expected 2 files")

	if len(res[variables.FilesTmpNames]) > 0 {
		require.NotEmpty(t, res[variables.FilesTmpNames][""], "expected files")
		fname := res[variables.FilesTmpNames][""][0]
		_, err := os.Stat(fname)
		require.NoErrorf(t, err, "expected file %q to exist", fname)
	}
}

func TestOriginalFileName(t *testing.T) {
	tests := map[string][2]string{
		"no filename":       {` form-data ; name=foo`, ""},
		"contains filename": {`form-data; name="file"; filename="test.txt"`, "test.txt"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := &multipart.Part{
				Header: textproto.MIMEHeader{
					"Content-Disposition": []string{test[0]},
				},
			}
			assert.Equal(t, test[1], originFileName(p))
		})
	}
}
