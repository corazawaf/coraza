// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var (
	ErrUnexpectedArguments = errors.New("unexpected arguments")
	ErrMissingArguments    = errors.New("missing arguments")
	ErrInvalidKVArguments  = errors.New("invalid arguments, expected syntax {action}:{key}={value}")
)

// ruleActionWrapper is used to wrap a RuleAction so that it can be registered
// and recreated on each call
type ruleActionWrapper = func() plugintypes.Action

// TODO maybe change it to sync.Map
var actionmap = map[string]ruleActionWrapper{}

// Register registers a new RuleAction
// It can be used also for plugins.
// If you register an action with an existing name, it will be overwritten.
func Register(name string, a func() plugintypes.Action) {
	name = strings.ToLower(name)
	actionmap[name] = a
}

func init() {
	Register("allow", allow)
	Register("auditlog", auditlog)
	Register("block", block)
	Register("capture", capture)
	Register("chain", chain)
	Register("ctl", ctl)
	Register("deny", deny)
	Register("drop", drop)
	Register("exec", exec)
	Register("expirevar", expirevar)
	Register("id", id)
	Register("initcol", initcol)
	Register("log", log)
	Register("logdata", logdata)
	Register("maturity", maturity)
	Register("msg", msg)
	Register("multiMatch", multimatch)
	Register("noauditlog", noauditlog)
	Register("nolog", nolog)
	Register("pass", pass)
	Register("phase", phase)
	Register("redirect", redirect)
	Register("rev", rev)
	Register("setenv", setenv)
	Register("setvar", setvar)
	Register("severity", severity)
	Register("skip", skip)
	Register("skipAfter", skipafter)
	Register("status", status)
	Register("t", t)
	Register("tag", tag)
	Register("ver", ver)
}

// Get returns an unwrapped RuleAction from the actionmap based on the name
// If the action does not exist it returns an error
func Get(name string) (plugintypes.Action, error) {
	name = strings.ToLower(name)
	if a, ok := actionmap[name]; ok {
		return a(), nil
	}
	return nil, fmt.Errorf("invalid action %q", name)
}
