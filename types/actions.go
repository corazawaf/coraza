// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

// RuleActionType is used to define when an action is going
// to be triggered
type RuleActionType int

const (
	// ActionTypeMetadata is used to provide more information about rules.
	ActionTypeMetadata RuleActionType = 1
	// ActionTypeDisruptive is used to make the integrator do something like drop the request.
	ActionTypeDisruptive RuleActionType = 2
	// ActionTypeData Not really actions, these are mere containers that hold data used by other actions.
	ActionTypeData RuleActionType = 3
	// ActionTypeNondisruptive is used to do something that does not affect the flow of the rule.
	ActionTypeNondisruptive RuleActionType = 4
	// ActionTypeFlow is used to affect the rule flow (for example skip or skipAfter).
	ActionTypeFlow RuleActionType = 5
)
