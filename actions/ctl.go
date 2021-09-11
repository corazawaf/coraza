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

	engine "github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/utils"
)

type Ctl struct {
	Action     int
	Value      string
	Collection byte
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
	CTL_DEBUG_LOG_LEVEL        = 17
)

func (a *Ctl) Init(r *engine.Rule, data string) error {
	var err error
	a.Action, a.Value, a.Collection, a.ColKey, err = parseCtl(data)
	return err
}

func (a *Ctl) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	switch a.Action {
	case CTL_REMOVE_TARGET_BY_ID:
		id, _ := strconv.Atoi(a.Value)
		tx.RemoveRuleTargetById(id, a.Collection, a.ColKey)
	case CTL_REMOVE_TARGET_BY_TAG:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if utils.StringInSlice(a.Value, r.Tags) {
				tx.RemoveRuleTargetById(r.Id, a.Collection, a.ColKey)
			}
		}
	case CTL_REMOVE_TARGET_BY_MSG:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if r.Msg == a.Value {
				tx.RemoveRuleTargetById(r.Id, a.Collection, a.ColKey)
			}
		}
	case CTL_AUDIT_ENGINE:
		switch a.Value {
		case "On":
			tx.AuditEngine = engine.AUDIT_LOG_ENABLED
		case "Off":
			tx.AuditEngine = engine.AUDIT_LOG_DISABLED
		case "RelevantOnly":
			tx.AuditEngine = engine.AUDIT_LOG_RELEVANT
		}
	case CTL_AUDIT_LOG_PARTS:
		//TODO lets switch it to a string
		tx.AuditLogParts = []rune{}
		for _, c := range a.Value {
			tx.AuditLogParts = append(tx.AuditLogParts, c)
		}
	case CTL_FORCE_REQUEST_BODY_VAR:
		if strings.ToLower(a.Value) == "on" {
			tx.ForceRequestBodyVariable = true
		} else {
			tx.ForceRequestBodyVariable = false
		}
	case CTL_REQUEST_BODY_ACCESS:
		tx.RequestBodyAccess = a.Value == "on"
	case CTL_REQUEST_BODY_LIMIT:
		limit, _ := strconv.ParseInt(a.Value, 10, 64)
		tx.RequestBodyLimit = limit
	case CTL_RULE_ENGINE:
		switch strings.ToLower(a.Value) {
		case "off":
			tx.RuleEngine = engine.RULE_ENGINE_OFF
		case "on":
			tx.RuleEngine = engine.RULE_ENGINE_ON
		case "detectiononly":
			tx.RuleEngine = engine.RULE_ENGINE_DETECTONLY
		}
	case CTL_RULE_REMOVE_BY_ID:
		id, _ := strconv.Atoi(a.Value)
		tx.RuleRemoveById = append(tx.RuleRemoveById, id)
	case CTL_RULE_REMOVE_BY_MSG:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if r.Msg == a.Value {
				tx.RuleRemoveById = append(tx.RuleRemoveById, r.Id)
			}
		}
	case CTL_RULE_REMOVE_BY_TAG:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if utils.StringInSlice(a.Value, r.Tags) {
				tx.RuleRemoveById = append(tx.RuleRemoveById, r.Id)
			}
		}
	case CTL_REQUEST_BODY_PROCESSOR:
		switch strings.ToLower(a.Value) {
		case "xml":
			tx.RequestBodyProcessor = engine.REQUEST_BODY_PROCESSOR_XML
			tx.GetCollection(engine.VARIABLE_REQBODY_PROCESSOR).Set("", []string{"XML"})
		case "json":
			tx.RequestBodyProcessor = engine.REQUEST_BODY_PROCESSOR_JSON
			tx.GetCollection(engine.VARIABLE_REQBODY_PROCESSOR).Set("", []string{"JSON"})
		case "urlencoded":
			tx.RequestBodyProcessor = engine.REQUEST_BODY_PROCESSOR_URLENCODED
			tx.GetCollection(engine.VARIABLE_REQBODY_PROCESSOR).Set("", []string{"URLENCODED"})
		case "multipart":
			tx.RequestBodyProcessor = engine.REQUEST_BODY_PROCESSOR_MULTIPART
			tx.GetCollection(engine.VARIABLE_REQBODY_PROCESSOR).Set("", []string{"MULTIPART"})
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

func (a *Ctl) Type() int {
	return engine.ACTION_TYPE_NONDISRUPTIVE
}

func parseCtl(data string) (int, string, byte, string, error) {
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
	collection, _ := engine.NameToVariable(strings.TrimSpace(colname))
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
