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
//  1. Option `ruleRemoveTargetById`, `ruleRemoveTargetByMsg`, and `ruleRemoveTargetByTag` accept a collection key in two forms:
//     - **Exact string**: `ARGS:user` — removes only the variable whose name is exactly `user`.
//     - **Regular expression** (delimited by `/`): `ARGS:/^json\.\d+\.field$/` — removes all variables whose
//     names match the pattern. The closing `/` must not be preceded by an odd number of backslashes
//     (e.g. `/foo\/` is treated as the literal string `/foo\/`, not a regex). An empty pattern (`//`) is rejected.
//     Pattern matching is always case-insensitive because variable names are lowercased before comparison.
//     Users do not need to use the `!` character before the target list.
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
// # white-list all JSON array fields matching a pattern for rule #932125 when the REQUEST_URI begins with /api/jobs
//
//		SecRule REQUEST_URI "@beginsWith /api/jobs" "phase:1,t:none,pass,\
//	 	nolog,ctl:ruleRemoveTargetById=932125;ARGS:/^json\.\d+\.jobdescription$/"
//
// ```
type ctlFn struct {
	action     ctlFunctionType
	value      string
	collection variables.RuleVariable
	colKey     string
	colKeyRx   *regexp.Regexp
}

func (a *ctlFn) Init(m plugintypes.RuleMetadata, data string) error {
	// Type-assert RuleMetadata to *corazawaf.Rule to access the rule's memoizer.
	// When the assertion fails (e.g., in tests using a stub RuleMetadata), the
	// memoizer remains nil and regex compilation proceeds without caching.
	var memoizer plugintypes.Memoizer
	if r, ok := m.(*corazawaf.Rule); ok {
		memoizer = r.Memoizer()
	}
	var err error
	a.action, a.value, a.collection, a.colKey, a.colKeyRx, err = parseCtl(data, memoizer)
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
		start, end, err := parseIDOrRange(a.value)
		if err != nil {
			tx.DebugLogger().Error().
				Str("ctl", "RuleRemoveTargetByID").
				Err(err).
				Msg("Invalid range")
			return
		}
		for _, r := range tx.WAF.Rules.GetRules() {
			if r.ID_ >= start && r.ID_ <= end {
				tx.RemoveRuleTargetByID(r.ID_, a.collection, a.colKey, a.colKeyRx)
			}
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
			start, end, err := parseRange(a.value)
			if err != nil {
				tx.DebugLogger().Error().
					Str("ctl", "RuleRemoveByID").
					Err(err).
					Msg("Invalid range")
				return
			}
			tx.RemoveRuleByIDRange(start, end)
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

func parseCtl(data string, memoizer plugintypes.Memoizer) (ctlFunctionType, string, variables.RuleVariable, string, *regexp.Regexp, error) {
	action, ctlVal, ok := strings.Cut(data, "=")
	if !ok {
		return ctlUnknown, "", 0, "", nil, errors.New("invalid syntax")
	}
	value, col, ok := strings.Cut(ctlVal, ";")
	var colkey, colname string
	if ok {
		colname, colkey, _ = strings.Cut(col, ":")
		colkey = strings.TrimSpace(colkey)
	}
	collection, _ := variables.Parse(strings.TrimSpace(colname))
	var keyRx *regexp.Regexp
	if isRegex, rxPattern := utils.HasRegex(colkey); isRegex {
		if len(rxPattern) == 0 {
			return ctlUnknown, "", 0, "", nil, errors.New("empty regex pattern in ctl collection key")
		}
		var err error
		if memoizer != nil {
			re, compileErr := memoizer.Do(rxPattern, func() (any, error) { return regexp.Compile(rxPattern) })
			if compileErr != nil {
				return ctlUnknown, "", 0, "", nil, fmt.Errorf("invalid regex in ctl collection key: %w", compileErr)
			}
			keyRx = re.(*regexp.Regexp)
		} else {
			keyRx, err = regexp.Compile(rxPattern)
			if err != nil {
				return ctlUnknown, "", 0, "", nil, fmt.Errorf("invalid regex in ctl collection key: %w", err)
			}
		}
		colkey = ""
	} else {
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
	return act, value, collection, colkey, keyRx, nil
}

// parseRange parses a range string of the form "start-end" and returns the start and end
// values as integers. It returns an error if the input is not a valid range.
func parseRange(input string) (start, end int, err error) {
	in0, in1, ok := strings.Cut(input, "-")
	if !ok {
		return 0, 0, errors.New("no range separator found")
	}
	start, err = strconv.Atoi(in0)
	if err != nil {
		return 0, 0, err
	}
	end, err = strconv.Atoi(in1)
	if err != nil {
		return 0, 0, err
	}
	if start > end {
		return 0, 0, errors.New("invalid range, start > end")
	}
	return start, end, nil
}

// parseIDOrRange parses either a single integer ID or a range string of the form "start-end".
// For a single ID, start and end are equal.
func parseIDOrRange(input string) (start, end int, err error) {
	if len(input) == 0 {
		return 0, 0, errors.New("empty input")
	}
	if _, _, ok := strings.Cut(input, "-"); ok {
		return parseRange(input)
	}
	id, err := strconv.Atoi(input)
	if err != nil {
		return 0, 0, err
	}
	return id, id, nil
}

func ctl() plugintypes.Action {
	return &ctlFn{}
}

var (
	_ plugintypes.Action = &ctlFn{}
	_ ruleActionWrapper  = ctl
)
