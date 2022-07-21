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

package http

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestRequestExtractionSuccess(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.coraza.io/test", strings.NewReader("test=456"))
	waf := NewWaf()
	tx := waf.NewTransaction(context.Background())
	if _, err := tx.ProcessRequest(req); err != nil {
		t.Fatal(err)
	}
	if tx.Variables.RequestMethod.String() != "POST" {
		t.Fatal("failed to set request from request object")
	}
	if err := tx.Clean(); err != nil {
		t.Fatal(err)
	}
}

func TestProcessRequestMultipart(t *testing.T) {
	req, _ := http.NewRequest("POST", "/some", nil)
	if err := multipartRequest(req); err != nil {
		t.Fatal(err)
	}
	tx := makeTransaction()
	tx.RequestBodyAccess = true
	if _, err := tx.ProcessRequest(req); err != nil {
		t.Fatal(err)
	}
	if req.Body == nil {
		t.Error("failed to process multipart request")
	}
	reader := bufio.NewReader(req.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Error("failed to read multipart request", err)
	}
	if err := tx.Clean(); err != nil {
		t.Error(err)
	}
}
