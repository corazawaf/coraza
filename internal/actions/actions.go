// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
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

func init() {
	plugins.RegisterAction("allow", allow)
	plugins.RegisterAction("auditlog", auditlog)
	plugins.RegisterAction("block", block)
	plugins.RegisterAction("capture", capture)
	plugins.RegisterAction("chain", chain)
	plugins.RegisterAction("ctl", ctl)
	plugins.RegisterAction("deny", deny)
	plugins.RegisterAction("drop", drop)
	plugins.RegisterAction("exec", exec)
	plugins.RegisterAction("expirevar", expirevar)
	plugins.RegisterAction("id", id)
	plugins.RegisterAction("initcol", initcol)
	plugins.RegisterAction("log", log)
	plugins.RegisterAction("logdata", logdata)
	plugins.RegisterAction("maturity", maturity)
	plugins.RegisterAction("msg", msg)
	plugins.RegisterAction("multiMatch", multimatch)
	plugins.RegisterAction("noauditlog", noauditlog)
	plugins.RegisterAction("nolog", nolog)
	plugins.RegisterAction("pass", pass)
	plugins.RegisterAction("phase", phase)
	plugins.RegisterAction("redirect", redirect)
	plugins.RegisterAction("rev", rev)
	plugins.RegisterAction("setenv", setenv)
	plugins.RegisterAction("setvar", setvar)
	plugins.RegisterAction("severity", severity)
	plugins.RegisterAction("skip", skip)
	plugins.RegisterAction("skipAfter", skipafter)
	plugins.RegisterAction("status", status)
	plugins.RegisterAction("t", t)
	plugins.RegisterAction("tag", tag)
	plugins.RegisterAction("ver", ver)
}
