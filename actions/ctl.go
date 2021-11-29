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
	"regexp"
	"strconv"
	"strings"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types"
	"github.com/jptosso/coraza-waf/v2/types/variables"
	utils "github.com/jptosso/coraza-waf/v2/utils/strings"
	"go.uber.org/zap"
)

type ctlFunctionType int

const (
	ctlRemoveTargetByID     ctlFunctionType = 0
	ctlRemoveTargetByTag    ctlFunctionType = 1
	ctlRemoveTargetByMsg    ctlFunctionType = 2
	ctlAuditEngine          ctlFunctionType = 3
	ctlAuditLogParts        ctlFunctionType = 4
	ctlForceRequestBodyVar  ctlFunctionType = 5
	ctlRequestBodyAccess    ctlFunctionType = 6
	ctlRequestBodyLimit     ctlFunctionType = 7
	ctlRuleEngine           ctlFunctionType = 8
	ctlRuleRemoveByID       ctlFunctionType = 9
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
	collection variables.RuleVariable
	colKey     string
	colRx      *regexp.Regexp
}

func (a *ctlFn) Init(r *coraza.Rule, data string) error {
	var err error
	a.action, a.value, a.collection, a.colKey, err = parseCtl(data)
	if len(a.colKey) > 2 && a.colKey[0] == '/' && a.colKey[len(a.colKey)-1] == '/' {
		a.colRx, err = regexp.Compile(a.colKey[1 : len(a.colKey)-1])
		if err != nil {
			return err
		}
	}
	return err
}

func (a *ctlFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	switch a.action {
	case ctlRemoveTargetByID:
		id, _ := strconv.Atoi(a.value)
		tx.RemoveRuleTargetById(id, a.collection, a.colKey)
	case ctlRemoveTargetByTag:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if utils.StringInSlice(a.value, r.Tags) {
				tx.RemoveRuleTargetById(r.ID, a.collection, a.colKey)
			}
		}
	case ctlRemoveTargetByMsg:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if r.Msg == a.value {
				tx.RemoveRuleTargetById(r.ID, a.collection, a.colKey)
			}
		}
	case ctlAuditEngine:
		ae, err := types.ParseAuditEngineStatus(a.value)
		if err != nil {
			tx.Waf.Logger.Error(err.Error())
			return
		}
		tx.AuditEngine = ae
	case ctlAuditLogParts:
		// TODO lets switch it to a string
		tx.AuditLogParts = []rune(a.value)
	case ctlForceRequestBodyVar:
		val := strings.ToLower(a.value)
		tx.Waf.Logger.Debug("Forcing request body var with CTL", zap.String("status", val))
		if val == "on" {
			tx.ForceRequestBodyVariable = true
		} else if val == "off" {
			tx.ForceRequestBodyVariable = false
		}
	case ctlRequestBodyAccess:
		tx.RequestBodyAccess = a.value == "on"
	case ctlRequestBodyLimit:
		limit, _ := strconv.ParseInt(a.value, 10, 64)
		tx.RequestBodyLimit = limit
	case ctlRuleEngine:
		re, err := types.ParseRuleEngineStatus(a.value)
		if err != nil {
			tx.Waf.Logger.Error(err.Error())
		}
		tx.RuleEngine = re
	case ctlRuleRemoveByID:
		id, _ := strconv.Atoi(a.value)
		tx.RemoveRuleById(id)
	case ctlRuleRemoveByMsg:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if r.Msg == a.value {
				tx.RemoveRuleById(r.ID)
			}
		}
	case ctlRuleRemoveByTag:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if utils.StringInSlice(a.value, r.Tags) {
				tx.RemoveRuleById(r.ID)
			}
		}
	case ctlRequestBodyProcessor:
		tx.GetCollection(variables.ReqbodyProcessor).Set("", []string{strings.ToUpper(a.value)})
	case ctlHashEngine:
		// Not supported yet
	case ctlHashEnforcement:
		// Not supported yet
	case ctlDebugLogLevel:
		// lvl, _ := strconv.Atoi(a.Value)
		// TODO
		// We cannot update the log level, it would affect the whole waf instance...
		// tx.Waf.SetLogLevel(lvl)
	}

}

func (a *ctlFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func parseCtl(data string) (ctlFunctionType, string, variables.RuleVariable, string, error) {
	spl1 := strings.SplitN(data, "=", 2)
	if len(spl1) != 2 {
		return ctlRemoveTargetByID, "", 0, "", fmt.Errorf("invalid syntax")
	}
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
	collection, _ := variables.ParseVariable(strings.TrimSpace(colname))
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
		act = ctlRuleRemoveByID
	case "ruleRemoveByMsg":
		act = ctlRuleRemoveByMsg
	case "ruleRemoveByTag":
		act = ctlRuleRemoveByTag
	case "ruleRemoveTargetById":
		act = ctlRemoveTargetByID
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
	_ ruleActionWrapper = ctl
)
