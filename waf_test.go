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
	"context"
	"testing"
)

var waf *Waf

func TestWAFInitialize(t *testing.T) {
	waf = NewWaf()
}

func TestNewTransaction(t *testing.T) {
	waf := NewWaf()
	waf.RequestBodyAccess = true
	waf.ResponseBodyAccess = true
	waf.RequestBodyLimit = 1044
	tx := waf.NewTransaction(context.Background())
	if !tx.RequestBodyAccess {
		t.Error("Request body access not enabled")
	}
	if !tx.ResponseBodyAccess {
		t.Error("Response body access not enabled")
	}
	if tx.RequestBodyLimit != 1044 {
		t.Error("Request body limit not set")
	}
}
