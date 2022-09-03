// Copyright 2022 Juan Pablo Tosso
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

	"go.uber.org/zap"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types"
	"github.com/corazawaf/coraza/v2/types/variables"
	utils "github.com/corazawaf/coraza/v2/utils/strings"
)

type ctlFunctionType int

const (
	ctlRemoveTargetByID     ctlFunctionType = iota
	ctlRemoveTargetByTag    ctlFunctionType = iota
	ctlRemoveTargetByMsg    ctlFunctionType = iota
	ctlAuditEngine          ctlFunctionType = iota
	ctlAuditLogParts        ctlFunctionType = iota
	ctlForceRequestBodyVar  ctlFunctionType = iota
	ctlRequestBodyAccess    ctlFunctionType = iota
	ctlRequestBodyLimit     ctlFunctionType = iota
	ctlRuleEngine           ctlFunctionType = iota
	ctlRuleRemoveByID       ctlFunctionType = iota
	ctlRuleRemoveByMsg      ctlFunctionType = iota
	ctlRuleRemoveByTag      ctlFunctionType = iota
	ctlHashEngine           ctlFunctionType = iota
	ctlHashEnforcement      ctlFunctionType = iota
	ctlRequestBodyProcessor ctlFunctionType = iota
	ctlResponseBodyAccess   ctlFunctionType = iota
	ctlResponseBodyLimit    ctlFunctionType = iota
	ctlDebugLogLevel        ctlFunctionType = iota
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
	a.action, a.value, a.collection, a.colKey, err = a.parseCtl(data)
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
		ran, err := a.rangeToInts(tx.Waf.Rules.GetRules(), a.value)
		if err != nil {
			tx.Waf.Logger.Error("invalid range", zap.Error(err))
			return
		}
		for _, id := range ran {
			tx.RemoveRuleTargetByID(id, a.collection, a.colKey)
		}
	case ctlRemoveTargetByTag:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if utils.InSlice(a.value, r.Tags) {
				tx.RemoveRuleTargetByID(r.ID, a.collection, a.colKey)
			}
		}
	case ctlRemoveTargetByMsg:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if r.Msg.String() == a.value {
				tx.RemoveRuleTargetByID(r.ID, a.collection, a.colKey)
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
		tx.AuditLogParts = types.AuditLogParts(a.value)
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
		tx.RemoveRuleByID(id)
	case ctlRuleRemoveByMsg:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if r.Msg.String() == a.value {
				tx.RemoveRuleByID(r.ID)
			}
		}
	case ctlRuleRemoveByTag:
		rules := tx.Waf.Rules.GetRules()
		for _, r := range rules {
			if utils.InSlice(a.value, r.Tags) {
				tx.RemoveRuleByID(r.ID)
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

func (a *ctlFn) parseCtl(data string) (ctlFunctionType, string, variables.RuleVariable, string, error) {
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
	collection, _ := variables.Parse(strings.TrimSpace(colname))
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

func (a *ctlFn) rangeToInts(rules []*coraza.Rule, input string) ([]int, error) {
	ids := []int{}
	spl := strings.SplitN(input, "-", 2)
	var start, end int
	var err error
	if len(spl) != 2 {
		id, err := strconv.Atoi(input)
		if err != nil {
			return nil, err
		}
		start, end = id, id
	} else {
		start, err = strconv.Atoi(spl[0])
		if err != nil {
			return nil, err
		}
		end, err = strconv.Atoi(spl[1])
		if err != nil {
			return nil, err
		}
	}
	for _, r := range rules {
		if r.ID >= start && r.ID <= end {
			ids = append(ids, r.ID)
		}
	}
	return ids, nil
}

func ctl() coraza.RuleAction {
	return &ctlFn{}
}

var (
	_ coraza.RuleAction = &ctlFn{}
	_ ruleActionWrapper = ctl
)
