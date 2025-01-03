// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestRestPath(t *testing.T) {
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	exp := "/some-random/url-{id}/{name}"
	path := "/some-random/url-123/juan"
	rp, err := newRESTPath(plugintypes.OperatorOptions{
		Arguments: exp,
	})
	if err != nil {
		t.Error(err)
	}
	if !rp.Evaluate(tx, path) {
		t.Errorf("Expected %s to match %s", exp, path)
	}
	if tx.Variables().ArgsPath().Get("id")[0] != "123" {
		t.Errorf("Expected id to be 123, got %s", tx.Variables().ArgsPath().Get("id"))
	}
}

func TestRestPathQueryShouldNotBeIncluded(t *testing.T) {
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	exp := "/some-random/url/{id}"
	path := "/some-random/url/123?name=foo"
	rp, err := newRESTPath(plugintypes.OperatorOptions{
		Arguments: exp,
	})
	if err != nil {
		t.Error(err)
	}
	if !rp.Evaluate(tx, path) {
		t.Errorf("Expected %s to match %s", exp, path)
	}
	if tx.Variables().ArgsPath().Get("id")[0] != "123" {
		t.Errorf("Expected id value of 123, got %s", tx.Variables().ArgsPath().Get("id"))
	}
}
