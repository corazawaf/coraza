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
