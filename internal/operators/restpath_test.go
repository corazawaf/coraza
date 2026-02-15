// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
)

func TestRestPath(t *testing.T) {
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	exp := "/some-random/url-{id}/{name}"
	path := "/some-random/url-123/juan"
	rp, err := newRESTPath(plugintypes.OperatorOptions{
		Arguments: exp,
	})
	require.NoError(t, err)
	require.True(t, rp.Evaluate(tx, path), "Expected %s to match %s", exp, path)
	require.Equal(t, "123", tx.Variables().ArgsPath().Get("id")[0], "Expected id to be 123")
	require.Equal(t, "juan", tx.Variables().ArgsPath().Get("name")[0], "Expected name to be juan")
}

func TestRestPathQueryShouldNotBeGreedy(t *testing.T) {
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()

	exp := "/some-random/url/{id}"
	testCases := map[string]string{
		"/some-random/url/123?q=test": "123", // ?q=test is query info
		"/some-random/url/456/test":   "456", // /test is extra path info
	}

	for path, want := range testCases {

		rp, err := newRESTPath(plugintypes.OperatorOptions{
			Arguments: exp,
		})
		require.NoError(t, err)
		require.True(t, rp.Evaluate(tx, path), "Expected %s to match %s", exp, path)
		require.Equal(t, want, tx.Variables().ArgsPath().Get("id")[0], "Expected id value of %s", want)
	}
}

func TestRestPathShouldNotBeGreedyOnMultiMatch(t *testing.T) {
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	exp := "/some-random/url-{id}/{expression}/{name}"
	path := "/some-random/url-123/foo/juan?q=test"
	rp, err := newRESTPath(plugintypes.OperatorOptions{
		Arguments: exp,
	})
	require.NoError(t, err)
	require.True(t, rp.Evaluate(tx, path), "Expected %s to match %s", exp, path)
	require.Equal(t, "123", tx.Variables().ArgsPath().Get("id")[0], "Expected id to be 123")
	require.Equal(t, "foo", tx.Variables().ArgsPath().Get("expression")[0], "Expected expression to be foo")
	require.Equal(t, "juan", tx.Variables().ArgsPath().Get("name")[0], "Expected name to be juan")
}

func TestRestPathWithBadExpressionShouldError(t *testing.T) {
	exp := "/some-random/url-{id/{name}"
	_, err := newRESTPath(plugintypes.OperatorOptions{
		Arguments: exp,
	})
	require.Error(t, err, "Expected error not to be nil with a bad expression")
}

func TestRestPathShouldNotMatchOnIncompleteURL(t *testing.T) {
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	exp := "/some-random/url-{id}/foo"
	path := "/some-random/url-123/"
	rp, err := newRESTPath(plugintypes.OperatorOptions{
		Arguments: exp,
	})
	if err != nil {
		t.Error(err)
	}
	if rp.Evaluate(tx, path) {
		t.Errorf("Expected %s to NOT match %s", exp, path)
	}
}

func TestRestPathShouldNotMatchOnIncompleteURLWithEndingParam(t *testing.T) {
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	exp := "/some-random/url-{id}/{name}"
	path := "/some-random/url-123/"
	rp, err := newRESTPath(plugintypes.OperatorOptions{
		Arguments: exp,
	})
	require.NoError(t, err)
	require.False(t, rp.Evaluate(tx, path), "Expected %s to NOT match %s", exp, path)
}

func TestRestPathShouldNotMatchOnEmptyPathElement(t *testing.T) {
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	exp := "/some-random/{id}/{name}"
	path := "/some-random//test"
	rp, err := newRESTPath(plugintypes.OperatorOptions{
		Arguments: exp,
	})
	require.NoError(t, err)
	require.False(t, rp.Evaluate(tx, path), "Expected %s to NOT match %s", exp, path)
}
