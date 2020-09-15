// Copyright 2020 Juan Pablo Tosso
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
	"github.com/jptosso/coraza-waf/pkg/utils"
	"strconv"
	"strings"
)

type Ctl struct {
	Action     int
	Value      string
	Collection string
	ColKey     string
}

const (
	CTL_REMOVE_TARGET_BY_ID    = 0
	CTL_REMOVE_TARGET_BY_TAG   = 1
	CTL_REMOVE_TARGET_BY_MSG   = 2
	CTL_AUDIT_ENGINE           = 3
	CTL_AUDIT_LOG_PARTS        = 4
	CTL_FORCE_REQUEST_BODY_VAR = 5
	CTL_REQUEST_BODY_ACCESS    = 6
	CTL_REQUEST_BODY_LIMIT     = 7
	CTL_RULE_ENGINE            = 8
	CTL_RULE_REMOVE_BY_ID      = 9
	CTL_RULE_REMOVE_BY_MSG     = 10
	CTL_RULE_REMOVE_BY_TAG     = 11
	CTL_HASH_ENGINE            = 12
	CTL_HASH_ENFORCEMENT       = 13
	CTL_REQUEST_BODY_PROCESSOR = 14
	CTL_RESPONSE_BODY_ACCESS   = 15
	CTL_RESPONSE_BODY_LIMIT    = 16
)

func (a *Ctl) Init(r *engine.Rule, data string) string {
	var err string
	a.Action, a.Value, a.Collection, a.ColKey, err = parseCtl(data)
	return err
}

func (a *Ctl) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	switch a.Action {
	case CTL_REMOVE_TARGET_BY_ID:
		id, _ := strconv.Atoi(a.Value)
		tx.RemoveRuleTargetById(id, a.Collection, a.ColKey)
		break
	case CTL_REMOVE_TARGET_BY_TAG:
		rules := tx.WafInstance.Rules.GetRules()
		for _, r := range rules {
			if utils.ArrayContains(r.Tags, a.Value) {
				tx.RemoveRuleTargetById(r.Id, a.Collection, a.ColKey)
			}
		}
		break
	case CTL_REMOVE_TARGET_BY_MSG:
		rules := tx.WafInstance.Rules.GetRules()
		for _, r := range rules {
			if r.Msg == a.Value {
				tx.RemoveRuleTargetById(r.Id, a.Collection, a.ColKey)
			}
		}
		break
	case CTL_AUDIT_ENGINE:
		switch a.Value {
		case "On":
			tx.AuditEngine = engine.AUDIT_LOG_ENABLED
			break
		case "Off":
			tx.AuditEngine = engine.AUDIT_LOG_DISABLED
			break
		case "RelevantOnly":
			tx.AuditEngine = engine.AUDIT_LOG_RELEVANT
			break
		}
		break
	case CTL_AUDIT_LOG_PARTS:
		tx.AuditLogParts = []rune{}
		for _, c := range a.Value {
			tx.AuditLogParts = append(tx.AuditLogParts, c)
		}
		break
	case CTL_FORCE_REQUEST_BODY_VAR:
		if a.Value == "on" {
			tx.ForceRequestBodyVariable = true
		} else {
			tx.ForceRequestBodyVariable = false
		}
		break
	case CTL_REQUEST_BODY_ACCESS:
		tx.RequestBodyAccess = a.Value == "on"
		break
	case CTL_REQUEST_BODY_LIMIT:
		limit, err := strconv.ParseInt(a.Value, 10, 64)
		if err != nil {
			return //error
		}
		tx.RequestBodyLimit = limit
		break
	case CTL_RULE_ENGINE:
		tx.RuleEngine = (a.Value == "on")
		break
	case CTL_RULE_REMOVE_BY_ID:
		id, _ := strconv.Atoi(a.Value)
		tx.RuleRemoveById = append(tx.RuleRemoveById, id)
		break
	case CTL_RULE_REMOVE_BY_MSG:
		rules := tx.WafInstance.Rules.GetRules()
		for _, r := range rules {
			if r.Msg == a.Value {
				tx.RuleRemoveById = append(tx.RuleRemoveById, r.Id)
			}
		}
		break
	case CTL_RULE_REMOVE_BY_TAG:
		rules := tx.WafInstance.Rules.GetRules()
		for _, r := range rules {
			if utils.ArrayContains(r.Tags, a.Value) {
				tx.RuleRemoveById = append(tx.RuleRemoveById, r.Id)
			}
		}
		break
	case CTL_HASH_ENGINE:
		// Not supported yet
		break
	case CTL_HASH_ENFORCEMENT:
		// Not supported yet
		break
	}

}

func (a *Ctl) GetType() int {
	return engine.ACTION_TYPE_NONDISRUPTIVE
}

func parseCtl(data string) (int, string, string, string, string) {
	spl1 := strings.SplitN(data, "=", 2)
	spl2 := strings.SplitN(spl1[1], ";", 2)
	action := spl1[0]
	value := spl2[0]
	collection := ""
	colkey := ""
	if len(spl2) == 2 {
		spl3 := strings.SplitN(spl2[1], ":", 2)
		if len(spl3) == 2 {
			collection = spl3[0]
			colkey = spl3[1]
		} else {
			colkey = spl3[0]
		}
	}
	collection = strings.ToLower(collection)
	colkey = strings.ToLower(colkey)
	act := 0
	switch action {
	case "auditEngine":
		act = CTL_AUDIT_ENGINE
		break
	case "auditLogParts":
		act = CTL_AUDIT_LOG_PARTS
		break
	case "forceRequestBodyVariable":
		act = CTL_FORCE_REQUEST_BODY_VAR
		break
	case "requestBodyAccess":
		act = CTL_REQUEST_BODY_ACCESS
		break
	case "requestBodyLimit":
		act = CTL_REQUEST_BODY_LIMIT
		break
	case "requestBodyProcessor":
		act = CTL_REQUEST_BODY_PROCESSOR
		break
	case "responseBodyAccess":
		act = CTL_RESPONSE_BODY_ACCESS
		break
	case "responseBodyLimit":
		act = CTL_RESPONSE_BODY_LIMIT
		break
	case "ruleEngine":
		act = CTL_RULE_ENGINE
		break
	case "ruleRemoveById":
		act = CTL_RULE_REMOVE_BY_ID
		break
	case "ruleRemoveByMsg":
		act = CTL_RULE_REMOVE_BY_MSG
		break
	case "ruleRemoveByTag":
		act = CTL_RULE_REMOVE_BY_TAG
		break
	case "ruleRemoveTargetById":
		act = CTL_REMOVE_TARGET_BY_ID
		break
	case "ruleRemoveTargetByMsg":
		act = CTL_REMOVE_TARGET_BY_MSG
		break
	case "ruleRemoveTargetByTag":
		act = CTL_REMOVE_TARGET_BY_TAG
		break
	case "hashEngine":
		act = CTL_HASH_ENGINE
		break
	case "hashEnforcement":
		act = CTL_HASH_ENFORCEMENT
		break
	default:
		return 0, "", "", "", "Invalid ctl action"
	}
	return act, value, strings.TrimSpace(collection), strings.TrimSpace(colkey), ""
}
