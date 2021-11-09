// Copyright 2021 Juan Pablo Tosso
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

package actions

import (
	"fmt"

	"github.com/jptosso/coraza-waf/v2"
)

type RuleActionWrapper = func() coraza.RuleAction

var actionmap = map[string]RuleActionWrapper{}

func RegisterRuleAction(name string, a RuleActionWrapper) {
	actionmap[name] = a
}

func init() {
	RegisterRuleAction("allow", allow)
	RegisterRuleAction("append", append)
	RegisterRuleAction("auditlog", auditlog)
	RegisterRuleAction("block", block)
	RegisterRuleAction("capture", capture)
	RegisterRuleAction("chain", chain)
	RegisterRuleAction("ctl", ctl)
	RegisterRuleAction("deny", deny)
	RegisterRuleAction("drop", drop)
	RegisterRuleAction("exec", exec)
	RegisterRuleAction("expirevar", expirevar)
	RegisterRuleAction("id", id)
	RegisterRuleAction("initcol", initcol)
	RegisterRuleAction("log", log)
	RegisterRuleAction("logdata", logdata)
	RegisterRuleAction("maturity", maturity)
	RegisterRuleAction("msg", msg)
	RegisterRuleAction("multiMatch", multimatch)
	RegisterRuleAction("noauditlog", noauditlog)
	RegisterRuleAction("nolog", nolog)
	RegisterRuleAction("pass", pass)
	RegisterRuleAction("phase", phase)
	RegisterRuleAction("prepend", prepend)
	RegisterRuleAction("rev", rev)
	RegisterRuleAction("setenv", setenv)
	RegisterRuleAction("setvar", setvar)
	RegisterRuleAction("severity", severity)
	RegisterRuleAction("skip", skip)
	RegisterRuleAction("skipAfter", skipafter)
	RegisterRuleAction("status", status)
	RegisterRuleAction("t", t)
	RegisterRuleAction("tag", tag)
	RegisterRuleAction("ver", ver)
}

func GetAction(name string) (coraza.RuleAction, error) {
	if a, ok := actionmap[name]; ok {
		return a(), nil
	}
	return nil, fmt.Errorf("invalid action %q", name)
}
