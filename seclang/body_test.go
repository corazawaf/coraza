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

package seclang

import (
	"context"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

/*
func TestRequestBodyAccessOff(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	if err := parser.FromString(`
	SecRequestBodyAccess Off
	`); err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction(context.Background())
	tx.ProcessURI("/", "POST", "http/1.1")
	tx.RequestBodyBuffer.Write([]byte("test=123"))
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()
	if len(tx.GetCollection(variables.ArgsPost).Data()) != 0 {
		t.Error("Should not have args")
	}
}*/

func TestRequestBodyAccessOn(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	if err := parser.FromString(`
	SecRequestBodyAccess On
	`); err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction(context.Background())
	tx.ProcessURI("/", "POST", "http/1.1")
	if _, err := tx.RequestBodyBuffer.Write([]byte("test=123")); err != nil {
		t.Error(err)
	}
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Error(err)
	}
	if len(tx.Variables.ArgsPost.FindAll()) == 0 {
		t.Error("Should have args")
	}
}
