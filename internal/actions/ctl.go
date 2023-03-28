// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type ctlFunctionType int

const (
	ctlUnknown                   ctlFunctionType = iota
	ctlRuleRemoveTargetByID      ctlFunctionType = iota
	ctlRuleRemoveTargetByTag     ctlFunctionType = iota
	ctlRuleRemoveTargetByMsg     ctlFunctionType = iota
	ctlAuditEngine               ctlFunctionType = iota
	ctlAuditLogParts             ctlFunctionType = iota
	ctlForceRequestBodyVariable  ctlFunctionType = iota
	ctlRequestBodyAccess         ctlFunctionType = iota
	ctlRequestBodyLimit          ctlFunctionType = iota
	ctlRuleEngine                ctlFunctionType = iota
	ctlRuleRemoveByID            ctlFunctionType = iota
	ctlRuleRemoveByMsg           ctlFunctionType = iota
	ctlRuleRemoveByTag           ctlFunctionType = iota
	ctlHashEngine                ctlFunctionType = iota
	ctlHashEnforcement           ctlFunctionType = iota
	ctlRequestBodyProcessor      ctlFunctionType = iota
	ctlForceResponseBodyVariable ctlFunctionType = iota
	ctlResponseBodyProcessor     ctlFunctionType = iota
	ctlResponseBodyAccess        ctlFunctionType = iota
	ctlResponseBodyLimit         ctlFunctionType = iota
	ctlDebugLogLevel             ctlFunctionType = iota
)

type ctlFn struct {
	value      string
	colKey     string
	action     ctlFunctionType
	collection variables.RuleVariable
}

func (a *ctlFn) Init(_ rules.RuleMetadata, data string) error {
	var err error
	a.action, a.value, a.collection, a.colKey, err = parseCtl(data)
	return err
}

// parseOnOff turns a string value into a boolean equivalent on/off into true/false
func parseOnOff(s string) (bool, bool) {
	val := strings.ToLower(s)
	switch val {
	case "on":
		return true, true
	case "off":
		return false, true
	default:
		return false, false
	}
}

func (a *ctlFn) Evaluate(_ rules.RuleMetadata, txS rules.TransactionState) {
	tx := txS.(*corazawaf.Transaction)
	switch a.action {
	case ctlRuleRemoveTargetByID:
		ran, err := rangeToInts(tx.WAF.Rules.GetRules(), a.value)
		if err != nil {
			tx.DebugLogger().Error().
				Str("ctl", "RuleRemoveTargetByID").
				Err(err).
				Msg("Invalid range")
			return
		}
		for _, id := range ran {
			tx.RemoveRuleTargetByID(id, a.collection, a.colKey)
		}
	case ctlRuleRemoveTargetByTag:
		rules := tx.WAF.Rules.GetRules()
		for _, r := range rules {
			if utils.InSlice(a.value, r.Tags_) {
				tx.RemoveRuleTargetByID(r.ID(), a.collection, a.colKey)
			}
		}
	case ctlRuleRemoveTargetByMsg:
		rules := tx.WAF.Rules.GetRules()
		for _, r := range rules {
			if r.Msg != nil && r.Msg.String() == a.value {
				tx.RemoveRuleTargetByID(r.ID(), a.collection, a.colKey)
			}
		}
	case ctlAuditEngine:
		ae, err := types.ParseAuditEngineStatus(a.value)
		if err != nil {
			tx.DebugLogger().Error().
				Str("ctl", "AuditEngine").
				Str("value", a.value).
				Err(err).
				Msg("Invalid status")
			return
		}
		tx.AuditEngine = ae
	case ctlAuditLogParts:
		// TODO lets switch it to a string
		tx.AuditLogParts = types.AuditLogParts(a.value)
	case ctlForceRequestBodyVariable:
		val, ok := parseOnOff(a.value)
		if !ok {
			tx.DebugLogger().Error().
				Str("ctl", "ForceRequestBodyVariable").
				Str("value", a.value).
				Msg("Unknown toggle")
			return
		}
		tx.ForceRequestBodyVariable = val
		tx.DebugLogger().Debug().
			Str("ctl", "ForceRequestBodyVariable").
			Bool("value", val).
			Msg("Forcing request body var")
	case ctlRequestBodyAccess:
		if tx.LastPhase() <= types.PhaseRequestHeaders {

			val, ok := parseOnOff(a.value)
			if !ok {
				tx.DebugLogger().Error().
					Str("ctl", "RequestBodyAccess").
					Str("value", a.value).
					Msg("Unknown toggle")
				return
			}
			tx.RequestBodyAccess = val
		} else {
			tx.DebugLogger().Warn().
				Str("ctl", "RequestBodyAccess").
				Msg("Cannot change request body access after request headers phase")
			return
		}
	case ctlRequestBodyLimit:
		if tx.LastPhase() <= types.PhaseRequestHeaders {
			limit, err := strconv.ParseInt(a.value, 10, 64)
			if err != nil {
				tx.DebugLogger().Error().
					Str("ctl", "RequestBodyLimit").
					Str("value", a.value).
					Err(err).
					Msg("Invalid limit")
				return
			}
			tx.RequestBodyLimit = limit
		} else {
			tx.DebugLogger().Warn().
				Str("ctl", "RequestBodyLimit").
				Msg("Cannot change request body limit after request headers phase")
			return
		}
	case ctlRequestBodyProcessor:
		if tx.LastPhase() <= types.PhaseRequestHeaders {
			tx.Variables().RequestBodyProcessor().Set(strings.ToUpper(a.value))
		} else {
			tx.DebugLogger().Warn().
				Str("ctl", "RequestBodyProcessor").
				Msg("Cannot change request body processor after request headers phase")
		}
	case ctlRuleEngine:
		re, err := types.ParseRuleEngineStatus(a.value)
		if err != nil {
			tx.DebugLogger().Error().
				Str("ctl", "RuleEngine").
				Str("value", a.value).
				Err(err).
				Msg("Invalid status")
			return
		}
		tx.RuleEngine = re
	case ctlRuleRemoveByID:
		id, err := strconv.Atoi(a.value)
		if err != nil {
			tx.DebugLogger().Error().
				Str("ctl", "RuleRemoveByID").
				Str("value", a.value).
				Err(err).
				Msg("Invalid rule ID")
			return
		}
		tx.RemoveRuleByID(id)
	case ctlRuleRemoveByMsg:
		rules := tx.WAF.Rules.GetRules()
		for _, r := range rules {
			if r.Msg != nil && r.Msg.String() == a.value {
				tx.RemoveRuleByID(r.ID_)
			}
		}
	case ctlRuleRemoveByTag:
		rules := tx.WAF.Rules.GetRules()
		for _, r := range rules {
			if utils.InSlice(a.value, r.Tags_) {
				tx.RemoveRuleByID(r.ID_)
			}
		}

	case ctlResponseBodyAccess:
		if tx.LastPhase() <= types.PhaseResponseHeaders {
			val, ok := parseOnOff(a.value)
			if !ok {
				tx.DebugLogger().Error().
					Str("ctl", "ResponseBodyAccess").
					Str("value", a.value).
					Msg("Unknown toggle")
				return
			}
			tx.ResponseBodyAccess = val
		} else {
			tx.DebugLogger().Warn().
				Str("ctl", "ResponseBodyAccess").
				Msg("Cannot change response body access after response headers phase")
			return
		}

	case ctlResponseBodyLimit:
		if tx.LastPhase() <= types.PhaseResponseHeaders {
			limit, err := strconv.ParseInt(a.value, 10, 64)
			if err != nil {
				tx.DebugLogger().Error().
					Str("ctl", "ResponseBodyLimit").
					Str("value", a.value).
					Err(err).
					Msg("Invalid limit")
				return
			}
			tx.ResponseBodyLimit = limit
		} else {
			tx.DebugLogger().Warn().
				Str("ctl", "ResponseBodyLimit").
				Msg("Cannot change response body access after response headers phase")
			return
		}

	case ctlForceResponseBodyVariable:
		val, ok := parseOnOff(a.value)
		if !ok {
			tx.DebugLogger().Error().
				Str("ctl", "ForceResponseBodyVariable").
				Str("value", a.value).
				Msg("Unknown toggle")
			return
		}
		tx.ForceResponseBodyVariable = val
		tx.WAF.Logger.Debug().
			Str("ctl", "ForceResponseBodyVariable").
			Bool("value", val).
			Msg("Forcing response body var")
	case ctlResponseBodyProcessor:
		if tx.LastPhase() <= types.PhaseResponseHeaders {
			// We are still in time to set the response body processor
			// TODO(jcchavezs): Who should hold this knowledge?
			// TODO(jcchavezs): Shall we validate such body processor exists or is it
			// too ambitious as plugins might register their own at some point in the
			// lifecycle which does not have to happen before this.
			tx.Variables().ResponseBodyProcessor().Set(strings.ToUpper(a.value))
		} else {
			tx.DebugLogger().Warn().
				Str("ctl", "ResponseBodyLimit").
				Msg("Cannot change response body access after response headers phase")
			return
		}
	case ctlHashEngine:
		// Not supported yet
	case ctlHashEnforcement:
		// Not supported yet
	case ctlDebugLogLevel:
		lvl, err := strconv.ParseInt(a.value, 10, 8)
		if err != nil {
			tx.DebugLogger().Error().
				Str("ctl", "DebugLogLevel").
				Str("value", a.value).
				Err(err).
				Msg("Invalid log level")
			return
		}

		tx.SetDebugLogLevel(debuglog.Level(lvl))
	}
}

func (a *ctlFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func parseCtl(data string) (ctlFunctionType, string, variables.RuleVariable, string, error) {
	action, ctlVal, ok := strings.Cut(data, "=")
	if !ok {
		return ctlUnknown, "", 0, "", errors.New("invalid syntax")
	}
	value, col, ok := strings.Cut(ctlVal, ";")
	var colkey, colname string
	if ok {
		colname, colkey, _ = strings.Cut(col, ":")
	}
	collection, _ := variables.Parse(strings.TrimSpace(colname))
	colkey = strings.ToLower(colkey)
	var act ctlFunctionType
	switch action {
	case "auditEngine":
		act = ctlAuditEngine
	case "auditLogParts":
		act = ctlAuditLogParts
	case "requestBodyAccess":
		act = ctlRequestBodyAccess
	case "requestBodyLimit":
		act = ctlRequestBodyLimit
	case "requestBodyProcessor":
		act = ctlRequestBodyProcessor
	case "forceRequestBodyVariable":
		act = ctlForceRequestBodyVariable
	case "responseBodyProcessor":
		act = ctlResponseBodyProcessor
	case "responseBodyAccess":
		act = ctlResponseBodyAccess
	case "responseBodyLimit":
		act = ctlResponseBodyLimit
	case "forceResponseBodyVariable":
		act = ctlForceResponseBodyVariable
	case "ruleEngine":
		act = ctlRuleEngine
	case "ruleRemoveById":
		act = ctlRuleRemoveByID
	case "ruleRemoveByMsg":
		act = ctlRuleRemoveByMsg
	case "ruleRemoveByTag":
		act = ctlRuleRemoveByTag
	case "ruleRemoveTargetById":
		act = ctlRuleRemoveTargetByID
	case "ruleRemoveTargetByMsg":
		act = ctlRuleRemoveTargetByMsg
	case "ruleRemoveTargetByTag":
		act = ctlRuleRemoveTargetByTag
	case "hashEngine":
		act = ctlHashEngine
	case "hashEnforcement":
		act = ctlHashEnforcement
	case "debugLogLevel":
		act = ctlDebugLogLevel
	default:
		return ctlUnknown, "", 0x00, "", fmt.Errorf("unknown ctl action %q", action)
	}
	return act, value, collection, strings.TrimSpace(colkey), nil
}

func rangeToInts(rules []corazawaf.Rule, input string) ([]int, error) {
	if len(input) == 0 {
		return nil, errors.New("empty input")
	}

	var (
		ids        []int
		start, end int
		err        error
	)

	if in0, in1, ok := strings.Cut(input, "-"); ok {
		start, err = strconv.Atoi(in0)
		if err != nil {
			return nil, err
		}
		end, err = strconv.Atoi(in1)
		if err != nil {
			return nil, err
		}
	} else {
		id, err := strconv.Atoi(input)
		if err != nil {
			return nil, err
		}
		start, end = id, id
	}

	for _, r := range rules {
		if r.ID_ >= start && r.ID_ <= end {
			ids = append(ids, r.ID_)
		}
	}
	return ids, nil
}

func ctl() rules.Action {
	return &ctlFn{}
}

var (
	_ rules.Action      = &ctlFn{}
	_ ruleActionWrapper = ctl
)
