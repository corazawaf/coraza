// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package actions implements SecLang rule actions for processing and control flow.
//
// # Overview
//
// Actions define how the system handles HTTP requests when rule conditions match.
// Actions are defined as part of a SecRule or as parameters for SecAction or SecDefaultAction.
// A rule can have no or several actions which need to be separated by a comma.
//
// # Action Categories
//
// Actions are categorized into five types:
//
// 1. Disruptive Actions
//
// Trigger Coraza operations such as blocking or allowing transactions.
// Only one disruptive action per rule applies; if multiple are specified,
// the last one takes precedence. Disruptive actions will NOT be executed
// if SecRuleEngine is set to DetectionOnly.
//
// Examples: deny, drop, redirect, allow, block, pass
//
// 2. Non-disruptive Actions
//
// Perform operations without affecting rule flow, such as variable modifications,
// logging, or setting metadata. These actions execute regardless of SecRuleEngine mode.
//
// Examples: log, nolog, setvar, msg, logdata, severity, tag
//
// 3. Flow Actions
//
// Control rule processing and execution flow. These actions determine which rules
// are evaluated and in what order.
//
// Examples: chain, skip, skipAfter
//
// 4. Meta-data Actions
//
// Provide information about rules, such as identification, versioning, and classification.
// These actions do not affect transaction processing.
//
// Examples: id, rev, msg, tag, severity, maturity, ver
//
// 5. Data Actions
//
// Containers that hold data for use by other actions, such as status codes
// for blocking responses.
//
// Examples: status (used with deny/redirect)
//
// # Usage
//
// Actions are specified in SecRule directives as comma-separated values:
//
//	SecRule ARGS "@rx attack" "id:100,deny,log,msg:'Attack detected'"
//
// # Important Notes
//
// When using the allow action for allowlisting, it's recommended to add
// ctl:ruleEngine=On to ensure the rule executes even in DetectionOnly mode.
//
// For the complete list of available actions, see: https://coraza.io/docs/seclang/actions/
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
