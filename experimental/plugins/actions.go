// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package plugins

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"
)

var actionmap = map[string]func() rules.Action{}

// RegisterAction registers a new RuleAction
// If you register an action with an existing name, it will be overwritten.
func RegisterAction(name string, a func() rules.Action) {
	name = strings.ToLower(name)
	actionmap[name] = a
}

// GetAction returns an unwrapped RuleAction from the actionmap based on the name
// If the action does not exist it returns an error
func GetAction(name string) (rules.Action, error) {
	name = strings.ToLower(name)
	if a, ok := actionmap[name]; ok {
		return a(), nil
	}
	return nil, fmt.Errorf("invalid action %q", name)
}
