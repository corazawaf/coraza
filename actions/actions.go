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

package actions

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v2"
)

// ruleActionWrapper is used to wrap a RuleAction so that it can be registered
// and recreated on each call
type ruleActionWrapper = func() coraza.RuleAction

// TODO maybe change it to sync.Map
var actionmap = map[string]ruleActionWrapper{}

// RegisterPlugin registers a new RuleAction
// It can be used also for plugins.
// If you register an action with an existing name, it will be overwritten.
func RegisterPlugin(name string, a func() coraza.RuleAction) {
	name = strings.ToLower(name)
	actionmap[name] = a
}

func init() {
	RegisterPlugin("allow", allow)
	RegisterPlugin("append", append2)
	RegisterPlugin("auditlog", auditlog)
	RegisterPlugin("block", block)
	RegisterPlugin("capture", capture)
	RegisterPlugin("chain", chain)
	RegisterPlugin("ctl", ctl)
	RegisterPlugin("deny", deny)
	RegisterPlugin("drop", drop)
	RegisterPlugin("exec", exec)
	RegisterPlugin("expirevar", expirevar)
	RegisterPlugin("id", id)
	RegisterPlugin("initcol", initcol)
	RegisterPlugin("log", log)
	RegisterPlugin("logdata", logdata)
	RegisterPlugin("maturity", maturity)
	RegisterPlugin("msg", msg)
	RegisterPlugin("multiMatch", multimatch)
	RegisterPlugin("noauditlog", noauditlog)
	RegisterPlugin("nolog", nolog)
	RegisterPlugin("pass", pass)
	RegisterPlugin("phase", phase)
	RegisterPlugin("prepend", prepend)
	RegisterPlugin("rev", rev)
	RegisterPlugin("setenv", setenv)
	RegisterPlugin("setvar", setvar)
	RegisterPlugin("severity", severity)
	RegisterPlugin("skip", skip)
	RegisterPlugin("skipAfter", skipafter)
	RegisterPlugin("status", status)
	RegisterPlugin("t", t)
	RegisterPlugin("tag", tag)
	RegisterPlugin("ver", ver)
}

// GetAction returns an unwrapped RuleAction from the actionmap based on the name
// If the action does not exist it returns an error
func GetAction(name string) (coraza.RuleAction, error) {
	name = strings.ToLower(name)
	if a, ok := actionmap[name]; ok {
		return a(), nil
	}
	return nil, fmt.Errorf("invalid action %q", name)
}
