// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"context"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"testing"
)

/*
func TestRequestBodyAccessOff(t *testing.T) {
	waf := coraza.NewWAF()
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
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
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
