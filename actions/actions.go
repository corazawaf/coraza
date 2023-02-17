// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"
)

var (
	ErrUnexpectedArguments = errors.New("unexpected arguments")
	ErrMissingArguments    = errors.New("missing arguments")
	ErrInvalidKVArguments  = errors.New("invalid arguments, expected syntax {action}:{key}={value}")
)

// ruleActionWrapper is used to wrap a RuleAction so that it can be registered
// and recreated on each call
type ruleActionWrapper = func() rules.Action

// TODO maybe change it to sync.Map
var actionmap = map[string]ruleActionWrapper{}

// RegisterPlugin registers a new RuleAction
// It can be used also for plugins.
// If you register an action with an existing name, it will be overwritten.
func RegisterPlugin(name string, a func() rules.Action) {
	name = strings.ToLower(name)
	actionmap[name] = a
}

func init() {
	RegisterPlugin("allow", allow)
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

// Get returns an unwrapped RuleAction from the actionmap based on the name
// If the action does not exist it returns an error
func Get(name string) (rules.Action, error) {
	name = strings.ToLower(name)
	if a, ok := actionmap[name]; ok {
		return a(), nil
	}
	return nil, fmt.Errorf("invalid action %q", name)
}
