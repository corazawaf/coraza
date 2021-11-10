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

type ctlFunctionType int

const (
	ctlRemoveTargetById     ctlFunctionType = 0
	ctlRemoveTargetByTag    ctlFunctionType = 1
	ctlRemoveTargetByMsg    ctlFunctionType = 2
	ctlAuditEngine          ctlFunctionType = 3
	ctlAuditLogParts        ctlFunctionType = 4
	ctlForceRequestBodyVar  ctlFunctionType = 5
	ctlRequestBodyAccess    ctlFunctionType = 6
	ctlRequestBodyLimit     ctlFunctionType = 7
	ctlRuleEngine           ctlFunctionType = 8
	ctlRuleRemoveById       ctlFunctionType = 9
	ctlRuleRemoveByMsg      ctlFunctionType = 10
	ctlRuleRemoveByTag      ctlFunctionType = 11
	ctlHashEngine           ctlFunctionType = 12
	ctlHashEnforcement      ctlFunctionType = 13
	ctlRequestBodyProcessor ctlFunctionType = 14
	ctlResponseBodyAccess   ctlFunctionType = 15
	ctlResponseBodyLimit    ctlFunctionType = 16
	ctlDebugLogLevel        ctlFunctionType = 17
)

type ctlFn struct {
	action     ctlFunctionType
	value      string
	collection coraza.RuleVariable
	colKey     string
}

func (a *ctlFn) Init(r *coraza.Rule, data string) error {
	var err error
	a.action, a.value, a.collection, a.colKey, err = parseCtl(data)
	return err
}

func (a *ctlFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	switch a.action {
	case ctlRemoveTargetById:
		id, _ := strconv.Atoi(a.value)
		tx.RemoveRuleTargetById(id, a.collection, a.colKey)
	case ctlRemoveTargetByTag:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if utils.StringInSlice(a.value, r.Tags) {
				tx.RemoveRuleTargetById(r.Id, a.collection, a.colKey)
			}
		}
	case ctlRemoveTargetByMsg:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if r.Msg == a.value {
				tx.RemoveRuleTargetById(r.Id, a.collection, a.colKey)
			}
		}
	case ctlAuditEngine:
		switch a.value {
		case "On":
			tx.AuditEngine = coraza.AUDIT_LOG_ENABLED
		case "Off":
			tx.AuditEngine = coraza.AUDIT_LOG_DISABLED
		case "RelevantOnly":
			tx.AuditEngine = coraza.AUDIT_LOG_RELEVANT
		}
	case ctlAuditLogParts:
		//TODO lets switch it to a string
		tx.AuditLogParts = []rune(a.value)
	case ctlForceRequestBodyVar:
		if strings.ToLower(a.value) == "on" {
			tx.ForceRequestBodyVariable = true
		} else {
			tx.ForceRequestBodyVariable = false
		}
	case ctlRequestBodyAccess:
		tx.RequestBodyAccess = a.value == "on"
	case ctlRequestBodyLimit:
		limit, _ := strconv.ParseInt(a.value, 10, 64)
		tx.RequestBodyLimit = limit
	case ctlRuleEngine:
		switch strings.ToLower(a.value) {
		case "off":
			tx.RuleEngine = coraza.RULE_ENGINE_OFF
		case "on":
			tx.RuleEngine = coraza.RULE_ENGINE_ON
		case "detectiononly":
			tx.RuleEngine = coraza.RULE_ENGINE_DETECTONLY
		}
	case ctlRuleRemoveById:
		id, _ := strconv.Atoi(a.value)
		tx.RemoveRuleById(id)
	case ctlRuleRemoveByMsg:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if r.Msg == a.value {
				tx.RemoveRuleById(r.Id)
			}
		}
	case ctlRuleRemoveByTag:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if utils.StringInSlice(a.value, r.Tags) {
				tx.RemoveRuleById(r.Id)
			}
		}
	case ctlRequestBodyProcessor:
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
	case ctlHashEngine:
		// Not supported yet
	case ctlHashEnforcement:
		// Not supported yet
	case ctlDebugLogLevel:
		//lvl, _ := strconv.Atoi(a.Value)
		// TODO
		// We cannot update the log level, it would affect the whole waf instance...
		//tx.Waf.SetLogLevel(lvl)
	}

}

func (a *ctlFn) Type() coraza.RuleActionType {
	return coraza.ActionTypeNondisruptive
}

func parseCtl(data string) (ctlFunctionType, string, coraza.RuleVariable, string, error) {
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
	var act ctlFunctionType
	switch action {
	case "auditEngine":
		act = ctlAuditEngine
	case "auditLogParts":
		act = ctlAuditLogParts
	case "forceRequestBodyVariable":
		act = ctlForceRequestBodyVar
	case "requestBodyAccess":
		act = ctlRequestBodyAccess
	case "requestBodyLimit":
		act = ctlRequestBodyLimit
	case "requestBodyProcessor":
		act = ctlRequestBodyProcessor
	case "responseBodyAccess":
		act = ctlResponseBodyAccess
	case "responseBodyLimit":
		act = ctlResponseBodyLimit
	case "ruleEngine":
		act = ctlRuleEngine
	case "ruleRemoveById":
		act = ctlRuleRemoveById
	case "ruleRemoveByMsg":
		act = ctlRuleRemoveByMsg
	case "ruleRemoveByTag":
		act = ctlRuleRemoveByTag
	case "ruleRemoveTargetById":
		act = ctlRemoveTargetById
	case "ruleRemoveTargetByMsg":
		act = ctlRemoveTargetByMsg
	case "ruleRemoveTargetByTag":
		act = ctlRemoveTargetByTag
	case "hashEngine":
		act = ctlHashEngine
	case "hashEnforcement":
		act = ctlHashEnforcement
	default:
		return 0, "", 0x00, "", fmt.Errorf("invalid ctl action")
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
