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
	if err := p.Read(strings.NewReader(payload), Options{
		Mime:        "multipart/form-data; boundary=---------------------------9051914041544843365972754266",
		StoragePath: "/tmp",
	}); err != nil {
		t.Error(err)
	}

	res := p.Collections()
	if len(res[variables.FilesNames][""]) != 2 {
		t.Errorf("Expected 2 files, got %d", len(res[variables.FilesNames]))
	}
	if len(res[variables.ArgsPostNames]) != 1 {
		t.Errorf("Expected 1 args, got %d", len(res[variables.ArgsPostNames]))
	}
	if len(res[variables.ArgsPost]["text"]) == 0 || res[variables.ArgsPost]["text"][0] != "text default" {
		t.Errorf("Expected text3 to be 'some super text content 3', got %v", res[variables.ArgsPost])
	}
	if len(res[variables.FilesTmpNames][""]) != 2 {
		t.Errorf("Expected 2 files, got %d", len(res[variables.FilesTmpNames]))
	}
	if len(res[variables.FilesTmpNames]) > 0 {
		if len(res[variables.FilesTmpNames][""]) == 0 {
			t.Errorf("Expected files, got %d", len(res[variables.FilesTmpNames][""]))
		} else {
			fname := res[variables.FilesTmpNames][""][0]
			if _, err := os.Stat(fname); err != nil {
				t.Errorf("Expected file %s to exist", fname)
			}

		}
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
			if got, want := originFileName(p), test[1]; got != want {
				t.Errorf("OriginFileName(%v) = %v, want %v", p, got, want)
			}
		})
	}
}
