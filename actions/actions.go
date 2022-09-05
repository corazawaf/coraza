// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"strings"
)

// ruleActionWrapper is used to wrap a RuleAction so that it can be registered
// and recreated on each call
type ruleActionWrapper = func() corazawaf.RuleAction

// TODO maybe change it to sync.Map
var actionmap = map[string]ruleActionWrapper{}

// RegisterPlugin registers a new RuleAction
// It can be used also for plugins.
// If you register an action with an existing name, it will be overwritten.
func RegisterPlugin(name string, a func() corazawaf.RuleAction) {
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
	RegisterPlugin("redirect", redirect)
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
func GetAction(name string) (corazawaf.RuleAction, error) {
	name = strings.ToLower(name)
	if a, ok := actionmap[name]; ok {
		return a(), nil
	}
	return nil, fmt.Errorf("invalid action %q", name)
}
