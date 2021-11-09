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
	"strconv"

	"github.com/jptosso/coraza-waf/v2"
)

type severityFn struct {
}

func (a *severityFn) Init(r *coraza.Rule, data string) error {
	sev, err := strconv.Atoi(data)
	if err != nil {
		// its a string
		switch data {
		case "EMERGENCY":
			sev = 0
		case "ALERT":
			sev = 1
		case "CRITICAL":
			sev = 2
		case "ERROR":
			sev = 3
		case "WARNING":
			sev = 4
		case "NOTICE":
			sev = 5
		case "INFO":
			sev = 6
		case "DEBUG":
			sev = 7
		default:
			// if we reach this point we fail
			return fmt.Errorf("invalid severity %q", data)
		}
	} else if sev < 0 || sev > 7 {
		return fmt.Errorf("invalid severity %d", sev)
	}
	r.Severity = sev
	return nil
}

func (a *severityFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *severityFn) Type() coraza.RuleActionType {
	return coraza.ActionTypeMetadata
}

func severity() coraza.RuleAction {
	return &severityFn{}
}

var (
	_ coraza.RuleAction = &severityFn{}
	_ RuleActionWrapper = severity
)
