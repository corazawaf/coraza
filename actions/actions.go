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

// RuleActionWrapper is used to wrap a RuleAction so that it can be registered
// and recreated on each call
type RuleActionWrapper = func() coraza.RuleAction

// TODO maybe change it to sync.Map
var actionmap = map[string]RuleActionWrapper{}

// RegisterRuleAction registers a new RuleAction
// It can be used also for plugins.
// If you register an action with an existing name, it will be overwritten.
func RegisterRuleAction(name string, a RuleActionWrapper) {
	actionmap[name] = a
}

func init() {
	RegisterRuleAction("allow", allow)
	RegisterRuleAction("append", append2)
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

// GetAction returns an unwrapped RuleAction from the actionmap based on the name
// If the action does not exist it returns an error
func GetAction(name string) (coraza.RuleAction, error) {
	if a, ok := actionmap[name]; ok {
		return a(), nil
	}
	return nil, fmt.Errorf("invalid action %q", name)
}
