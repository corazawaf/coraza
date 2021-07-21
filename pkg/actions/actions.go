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
	"github.com/jptosso/coraza-waf/pkg/engine"
)

func ActionsMap() map[string]engine.Action {
	//TODO optimize this
	return map[string]engine.Action{
		// #### Flow Actions ####
		//Sets variables for the transaction and rule
		"chain":     &Chain{},
		"skip":      &Skip{},
		"skipAfter": &SkipAfter{},

		// #### Metadata Actions ####
		//These variables goes to the rule object
		//"accuracy": &Accurracy{},
		"id":       &Id{},
		"maturity": &Maturity{},
		"msg":      &Msg{},
		"phase":    &Phase{},
		"rev":      &Rev{},
		"severity": &Severity{},
		"tag":      &Tag{},
		"ver":      &Ver{},

		// #### Data actions ####
		//These variables goes to the transaction
		"status": &Status{},
		//"xmlns": &Xmlns{},

		// #### Non Disruptive Actions ####
		//Can update transaction but cannot affect the flow nor disrupt the request
		"append":    &Append{},
		"capture":   &Capture{},
		"ctl":       &Ctl{},
		"exec":      &Exec{},
		"expirevar": &Expirevar{},
		//"deprecateVar": &DeprecateVar{},
		"initcol":    &InitCol{},
		"log":        &Log{},
		"auditlog":   &Log{}, //Just an alias
		"logdata":    &Logdata{},
		"multiMatch": &MultiMatch{},
		"nolog":      &Nolog{},
		"noauditlog": &NoAuditlog{},
		//"prepend": &Prepend{},
		//"sanitiseArg": &SanitiseArg{},
		//"sanitiseMatched": &SanitiseMatched{},
		//"sanitiseMatchedBytes": &SanitiseMatchedBytes{},
		//"sanitiseRequestHeader": &SanitiseRequestHeader{},
		//"sanitiseResponseHeader": &SanitiseResponseHeader{},
		//"setuid": &Setuid{},
		//"setrsc": &Setrsc{},
		//"setsid": &Setsid{},
		//"setenv": &Setenv{},
		"setvar": &Setvar{},
		"t":      &T{},

		// #### Disruptive Actions ####
		// can manage the whole request and response process, doesnt run if SecRuleEngine is off or DetectionOnly is on
		"allow": &Allow{},
		"block": &Block{},
		"deny":  &Deny{},
		"drop":  &Drop{},
		"pass":  &Pass{},
		//"pause": &Pause{},
		//"proxy": &Proxy{},
		//"redirect": &Redirect{},
	}
}
