// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
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

// Action Group: Non-disruptive
//
// Description:
// Change Coraza configuration on transient, per-transaction basis.
// Any changes made using this action will affect only the transaction in which the action is executed.
// The default configuration, as well as the other transactions running in parallel, will be unaffected.
//
// The following configuration options are supported:
// - `auditEngine`
// - `auditLogParts`
// - `debugLogLevel`
// - `forceRequestBodyVariable`
// - `requestBodyAccess`
// - `requestBodyLimit`
// - `requestBodyProcessor`
// - `responseBodyAccess`
// - `responseBodyLimit`
// - `ruleEngine`
// - `ruleRemoveById`
// - `ruleRemoveByMsg`
// - `ruleRemoveByTag`
// - `ruleRemoveTargetById`
// - `ruleRemoveTargetByMsg`
// - `ruleRemoveTargetByTag`
// - `hashEngine` (**Not Supported in Coraza (TBI)**)
// - `hashEnforcement` (**Not supported in Coraza (TBI)**)
//
// Here are some notes about the options:
//
//  1. Option `ruleRemoveTargetById`, `ruleRemoveTargetByMsg`, and `ruleRemoveTargetByTag`, users don't need to use the char ! before the target list.
//
//  2. Option `ruleRemoveById` is triggered at run time and should be specified before the rule in which it is disabling.
//
//  3. Option `requestBodyProcessor` allows you to configure the request body processor.
//     By default, Coraza will use the `URLENCODED` and `MULTIPART` processors to process an `application/x-www-form-urlencoded` and a `multipart/form-data` body respectively.
//     Other processors also supported: `JSON` and `XML`, but they are never used implicitly.
//     Instead, you must tell Coraza to use it by placing a few rules in the `REQUEST_HEADERS` processing phase.
//     After the request body is processed as XML, you will be able to use the XML-related features to inspect it.
//     Request body processors will not interrupt a transaction if an error occurs during parsing.
//     Instead, they will set the variables `REQBODY_PROCESSOR_ERROR` and `REQBODY_PROCESSOR_ERROR_MSG`.
//     These variables should be inspected in the `REQUEST_BODY` phase and an appropriate action taken.
//
//  4. Option `forceRequestBodyVariable“ allows you to configure the `REQUEST_BODY` variable to be set when there is no request body processor configured.
//     This allows for inspection of request bodies of unknown types.
//
// Example:
// ```
// # Parse requests with Content-Type "text/xml" as XML
// SecRule REQUEST_CONTENT_TYPE ^text/xml "nolog,pass,id:106,phase:1,ctl:requestBodyProcessor=XML"
//
// # white-list the user parameter for rule #981260 when the REQUEST_URI is /index.php
//
//		SecRule REQUEST_URI "@beginsWith /index.php" "phase:1,t:none,pass,\
//	 	nolog,ctl:ruleRemoveTargetById=981260;ARGS:user"
//
// ```
type ctlFn struct {
	action     ctlFunctionType
	value      string
	collection variables.RuleVariable
	colKey string
	// colKeyRx holds the compiled regex pattern when the collection key is specified as a regex (e.g., "/pattern/").
	// It is nil otherwise. The regex is compiled during rule initialization and used during rule evaluation
	// to match against collection keys dynamically.
	colKeyRx *regexp.Regexp
}

func (a *ctlFn) Init(_ plugintypes.RuleMetadata, data string) error {
	var err error
	a.action, a.value, a.collection, a.colKey, a.colKeyRx, err = parseCtl(data)
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

func (a *ctlFn) Evaluate(_ plugintypes.RuleMetadata, txS plugintypes.TransactionState) {
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
			tx.RemoveRuleTargetByID(id, a.collection, a.colKey, a.colKeyRx)
		}
	case ctlRuleRemoveTargetByTag:
		rules := tx.WAF.Rules.GetRules()
		for _, r := range rules {
			if utils.InSlice(a.value, r.Tags_) {
				tx.RemoveRuleTargetByID(r.ID(), a.collection, a.colKey, a.colKeyRx)
			}
		}
	case ctlRuleRemoveTargetByMsg:
		rules := tx.WAF.Rules.GetRules()
		for _, r := range rules {
			if r.Msg != nil && r.Msg.String() == a.value {
				tx.RemoveRuleTargetByID(r.ID(), a.collection, a.colKey, a.colKeyRx)
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
		AuditLogParts, err := types.ApplyAuditLogParts(tx.AuditLogParts, a.value)
		if err != nil {
			tx.DebugLogger().Error().
				Str("ctl", "AuditLogParts").
				Str("value", a.value).
				Err(err).
				Msg("Invalid audit log part")
			return
		}
		tx.AuditLogParts = AuditLogParts
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
			tx.Variables().RequestBodyProcessor().(*collections.Single).Set(strings.ToUpper(a.value))
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
		if idx := strings.Index(a.value, "-"); idx == -1 {
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
		} else {
			ran, err := rangeToInts(tx.WAF.Rules.GetRules(), a.value)
			if err != nil {
				tx.DebugLogger().Error().
					Str("ctl", "RuleRemoveByID").
					Err(err).
					Msg("Invalid range")
				return
			}
			for _, id := range ran {
				tx.RemoveRuleByID(id)
			}
		}
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
			tx.Variables().ResponseBodyProcessor().(*collections.Single).Set(strings.ToUpper(a.value))
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

func (a *ctlFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func parseCtl(data string) (ctlFunctionType, string, variables.RuleVariable, string, *regexp.Regexp, error) {
	action, ctlVal, ok := strings.Cut(data, "=")
	if !ok {
		return ctlUnknown, "", 0, "", nil, errors.New("invalid syntax")
	}
	value, col, ok := strings.Cut(ctlVal, ";")
	var colkey, colname string
	if ok {
		colname, colkey, _ = strings.Cut(col, ":")
	}
	collection, _ := variables.Parse(strings.TrimSpace(colname))
	
	// Parse regex pattern if present
	// Note: Regex patterns can be user-controlled through WAF rules, which may introduce
	// ReDoS (Regular Expression Denial of Service) risks if malicious or poorly written patterns
	// are used. Rule authors should carefully validate regex patterns to avoid performance issues.
	var re *regexp.Regexp
	colkey = strings.TrimSpace(colkey)
	if isRegex, pattern := utils.HasRegex(colkey); isRegex {
		// Validate that the pattern is not empty
		if len(pattern) == 0 {
			return ctlUnknown, "", 0, "", nil, errors.New("empty regex pattern")
		}
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return ctlUnknown, "", 0x00, "", nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	} else if colkey != "" {
		// Apply lowercase normalization only for non-regex keys
		colkey = strings.ToLower(colkey)
	}
	
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
		return ctlUnknown, "", 0x00, "", nil, fmt.Errorf("unknown ctl action %q", action)
	}
	
	return act, value, collection, colkey, re, nil
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

		if start > end {
			return nil, errors.New("invalid range, start > end")
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

func ctl() plugintypes.Action {
	return &ctlFn{}
}

var (
	_ plugintypes.Action = &ctlFn{}
	_ ruleActionWrapper  = ctl
)
