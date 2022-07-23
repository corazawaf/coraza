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
	"testing"

	"github.com/corazawaf/coraza/v2"
	"github.com/stretchr/testify/require"
)

func TestInvalidRule(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)

	err := p.FromString("")
	require.NoError(t, err)

	err = p.FromString("SecRule")
	require.Error(t, err, "expected malformed rule error")
}

func TestVariables(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)

	// single variable with key
	err := p.FromString(`SecRule REQUEST_HEADERS:test "" "id:1"`)
	require.NoError(t, err)

	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/^(?:phpMyAdminphp|MyAdmin_https)$/' "id:2"`)
	require.NoError(t, err)

	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/^(?:phpMyAdminphp|MyAdmin_https)$/'|ARGS:test "id:3"`)
	require.NoError(t, err)

	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/.*/'|ARGS:/a|b/ "id:4"`)
	require.NoError(t, err)

	err = p.FromString(`SecRule &REQUEST_COOKIES_NAMES:'/.*/'|ARGS:/a|b/|XML:/*|ARGS|REQUEST_HEADERS "id:5"`)
	require.NoError(t, err)

	err = p.FromString(`SecRule XML:/*|XML://@* "" "id:6"`)
	require.NoError(t, err)
}

func TestVariableCases(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromString(`SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "" "id:7,pass"`)
	require.NoError(t, err)
}

func TestSecRuleInlineVariableNegation(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromString(`
		SecRule REQUEST_URI|!REQUEST_COOKIES "abc" "id:7,phase:2"
	`)
	require.NoError(t, err)

	err = p.FromString(`
		SecRule REQUEST_URI|!REQUEST_COOKIES:xyz "abc" "id:8,phase:2"
	`)
	require.NoError(t, err)

	err = p.FromString(`
		SecRule REQUEST_URI|!REQUEST_COOKIES: "abc" "id:9,phase:2"
	`)

	require.Contains(t, err.Error(), "failed to compile rule")
}

func TestSecRuleUpdateTargetVariableNegation(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromString(`
		SecRule REQUEST_URI|REQUEST_COOKIES "abc" "id:7,phase:2"
		SecRuleUpdateTargetById 7 "!REQUEST_HEADERS:/xyz/"
		SecRuleUpdateTargetById 7 "!REQUEST_COOKIES:/xyz/"
	`)
	require.NoError(t, err)

	err = p.FromString(`
		SecRule REQUEST_URI|REQUEST_COOKIES "abc" "id:8,phase:2"
		SecRuleUpdateTargetById 8 "!REQUEST_HEADERS:"
	`)
	require.EqualError(t, err, "unknown variable")

	// Try to update undefined rule
	err = p.FromString(`
		SecRule REQUEST_URI|REQUEST_COOKIES "abc" "id:9,phase:2"
		SecRuleUpdateTargetById 99 "!REQUEST_HEADERS:xyz"
	`)
	require.EqualError(t, err, "cannot create a variable exception for an undefined rule")
}

func TestErrorLine(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromString("SecAction \"id:1\"\n#test\nSomefaulty")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Line 3", "failed to find error")
}

func TestDefaultActionsForPhase2(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromString(`
	SecAction "id:1,phase:2"
	SecAction "id:2,phase:1"`)
	require.NoError(t, err)
	require.True(t, waf.Rules.GetRules()[0].Log, "failed to set log to true because of default actions")
	require.True(t, waf.Rules.GetRules()[0].Audit, "failed to set audit to true because of default actions")
	require.False(t, waf.Rules.GetRules()[1].Log || waf.Rules.GetRules()[1].Audit, "phase 1 rules shouldn't have log set by default actions")
}
