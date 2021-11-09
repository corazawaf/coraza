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
	"strings"

	"github.com/jptosso/coraza-waf/v2"
	utils "github.com/jptosso/coraza-waf/v2/utils"
)

type ctlFn struct {
	action     int
	value      string
	collection coraza.RuleVariable
	colKey     string
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
	CTL_DEBUG_LOG_LEVEL        = 17
)

func (a *ctlFn) Init(r *coraza.Rule, data string) error {
	var err error
	a.action, a.value, a.collection, a.colKey, err = parseCtl(data)
	return err
}

func (a *ctlFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	switch a.action {
	case CTL_REMOVE_TARGET_BY_ID:
		id, _ := strconv.Atoi(a.value)
		tx.RemoveRuleTargetById(id, a.collection, a.colKey)
	case CTL_REMOVE_TARGET_BY_TAG:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if utils.StringInSlice(a.value, r.Tags) {
				tx.RemoveRuleTargetById(r.Id, a.collection, a.colKey)
			}
		}
	case CTL_REMOVE_TARGET_BY_MSG:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if r.Msg == a.value {
				tx.RemoveRuleTargetById(r.Id, a.collection, a.colKey)
			}
		}
	case CTL_AUDIT_ENGINE:
		switch a.value {
		case "On":
			tx.AuditEngine = coraza.AUDIT_LOG_ENABLED
		case "Off":
			tx.AuditEngine = coraza.AUDIT_LOG_DISABLED
		case "RelevantOnly":
			tx.AuditEngine = coraza.AUDIT_LOG_RELEVANT
		}
	case CTL_AUDIT_LOG_PARTS:
		//TODO lets switch it to a string
		tx.AuditLogParts = []rune(a.value)
	case CTL_FORCE_REQUEST_BODY_VAR:
		if strings.ToLower(a.value) == "on" {
			tx.ForceRequestBodyVariable = true
		} else {
			tx.ForceRequestBodyVariable = false
		}
	case CTL_REQUEST_BODY_ACCESS:
		tx.RequestBodyAccess = a.value == "on"
	case CTL_REQUEST_BODY_LIMIT:
		limit, _ := strconv.ParseInt(a.value, 10, 64)
		tx.RequestBodyLimit = limit
	case CTL_RULE_ENGINE:
		switch strings.ToLower(a.value) {
		case "off":
			tx.RuleEngine = coraza.RULE_ENGINE_OFF
		case "on":
			tx.RuleEngine = coraza.RULE_ENGINE_ON
		case "detectiononly":
			tx.RuleEngine = coraza.RULE_ENGINE_DETECTONLY
		}
	case CTL_RULE_REMOVE_BY_ID:
		id, _ := strconv.Atoi(a.value)
		tx.RemoveRuleById(id)
	case CTL_RULE_REMOVE_BY_MSG:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if r.Msg == a.value {
				tx.RemoveRuleById(r.Id)
			}
		}
	case CTL_RULE_REMOVE_BY_TAG:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if utils.StringInSlice(a.value, r.Tags) {
				tx.RemoveRuleById(r.Id)
			}
		}
	case CTL_REQUEST_BODY_PROCESSOR:
		switch strings.ToLower(a.value) {
		case "xml":
			tx.RequestBodyProcessor = coraza.REQUEST_BODY_PROCESSOR_XML
			tx.GetCollection(coraza.VARIABLE_REQBODY_PROCESSOR).Set("", []string{"XML"})
		case "json":
			tx.RequestBodyProcessor = coraza.REQUEST_BODY_PROCESSOR_JSON
			tx.GetCollection(coraza.VARIABLE_REQBODY_PROCESSOR).Set("", []string{"JSON"})
		case "urlencoded":
			tx.RequestBodyProcessor = coraza.REQUEST_BODY_PROCESSOR_URLENCODED
			tx.GetCollection(coraza.VARIABLE_REQBODY_PROCESSOR).Set("", []string{"URLENCODED"})
		case "multipart":
			tx.RequestBodyProcessor = coraza.REQUEST_BODY_PROCESSOR_MULTIPART
			tx.GetCollection(coraza.VARIABLE_REQBODY_PROCESSOR).Set("", []string{"MULTIPART"})
		}
	case CTL_HASH_ENGINE:
		// Not supported yet
	case CTL_HASH_ENFORCEMENT:
		// Not supported yet
	case CTL_DEBUG_LOG_LEVEL:
		//lvl, _ := strconv.Atoi(a.Value)
		// TODO
		// We cannot update the log level, it would affect the whole waf instance...
		//tx.Waf.SetLogLevel(lvl)
	}

}

func (a *ctlFn) Type() coraza.RuleActionType {
	return coraza.ActionTypeNondisruptive
}

func parseCtl(data string) (int, string, coraza.RuleVariable, string, error) {
	spl1 := strings.SplitN(data, "=", 2)
	spl2 := strings.SplitN(spl1[1], ";", 2)
	action := spl1[0]
	value := spl2[0]
	colname := ""
	colkey := ""
	if len(spl2) == 2 {
		spl3 := strings.SplitN(spl2[1], ":", 2)
		if len(spl3) == 2 {
			colname = spl3[0]
			colkey = spl3[1]
		} else {
			colkey = spl3[0]
		}
	}
	collection, _ := coraza.ParseRuleVariable(strings.TrimSpace(colname))
	colkey = strings.ToLower(colkey)
	act := 0
	switch action {
	case "auditEngine":
		act = CTL_AUDIT_ENGINE
	case "auditLogParts":
		act = CTL_AUDIT_LOG_PARTS
	case "forceRequestBodyVariable":
		act = CTL_FORCE_REQUEST_BODY_VAR
	case "requestBodyAccess":
		act = CTL_REQUEST_BODY_ACCESS
	case "requestBodyLimit":
		act = CTL_REQUEST_BODY_LIMIT
	case "requestBodyProcessor":
		act = CTL_REQUEST_BODY_PROCESSOR
	case "responseBodyAccess":
		act = CTL_RESPONSE_BODY_ACCESS
	case "responseBodyLimit":
		act = CTL_RESPONSE_BODY_LIMIT
	case "ruleEngine":
		act = CTL_RULE_ENGINE
	case "ruleRemoveById":
		act = CTL_RULE_REMOVE_BY_ID
	case "ruleRemoveByMsg":
		act = CTL_RULE_REMOVE_BY_MSG
	case "ruleRemoveByTag":
		act = CTL_RULE_REMOVE_BY_TAG
	case "ruleRemoveTargetById":
		act = CTL_REMOVE_TARGET_BY_ID
	case "ruleRemoveTargetByMsg":
		act = CTL_REMOVE_TARGET_BY_MSG
	case "ruleRemoveTargetByTag":
		act = CTL_REMOVE_TARGET_BY_TAG
	case "hashEngine":
		act = CTL_HASH_ENGINE
	case "hashEnforcement":
		act = CTL_HASH_ENFORCEMENT
	default:
		return 0, "", 0x00, "", fmt.Errorf("Invalid ctl action")
	}
	return act, value, collection, strings.TrimSpace(colkey), nil
}

func ctl() coraza.RuleAction {
	return &ctlFn{}
}

var (
	_ coraza.RuleAction = &ctlFn{}
	_ RuleActionWrapper = ctl
)
