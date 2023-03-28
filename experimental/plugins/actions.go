// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/corazawaf/coraza/v3/internal/actions"
	"github.com/corazawaf/coraza/v3/rules"
)

// ActionFactory is used to wrap a RuleAction so that it can be registered
// and recreated on each call
type ActionFactory = func() rules.Action

// RegisterAction registers a new RuleAction
// If you register an action with an existing name, it will be overwritten.
func RegisterAction(name string, a ActionFactory) {
	actions.Register(name, a)
}
