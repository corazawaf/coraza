// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/auditlog"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/cookies"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/corazatypes"
	"github.com/corazawaf/coraza/v3/internal/environment"
	stringsutil "github.com/corazawaf/coraza/v3/internal/strings"
	urlutil "github.com/corazawaf/coraza/v3/internal/url"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Transaction is created from a WAF instance to handle web requests and responses,
// it contains a copy of most WAF configurations that can be safely changed.
// Transactions are used to store all data like URLs, request and response
// headers. Transactions are used to evaluate rules by phase and generate disruptive
// actions. Disruptive actions can be read from *tx.Interruption.
// It is safe to manage multiple transactions but transactions themself are not
// thread safe
type Transaction struct {
	// Transaction ID
	id string

	// The context associated to the transaction.
	context context.Context

	// Contains the list of matched rules and associated match information
	matchedRules []types.MatchedRule

	// True if the transaction has been disrupted by any rule
	interruption *types.Interruption

	// This is used to store detected interruptions that are not disruptive
	detectedInterruption *types.Interruption

	// This is used to store log messages
	// Deprecated since Coraza 3.0.5: this variable is not used, logdata values are stored in the matched rules
	Logdata string

	// Rules will be skipped after a rule with this SecMarker is found
	SkipAfter string

	// AllowType is used by the allow disruptive action to skip evaluating rules after being allowed
	AllowType corazatypes.AllowType

	// Copies from the WAF instance that may be overwritten by the ctl action
	AuditEngine               types.AuditEngineStatus
	AuditLogParts             types.AuditLogParts
	AuditLogFormat            string
	ForceRequestBodyVariable  bool
	RequestBodyAccess         bool
	RequestBodyLimit          int64
	ForceResponseBodyVariable bool
	ResponseBodyAccess        bool
	ResponseBodyLimit         int64
	RuleEngine                types.RuleEngineStatus
	HashEngine                bool
	HashEnforcement           bool

	// Stores the last phase that was evaluated
	// Used by allow to skip phases
	lastPhase types.RulePhase

	// Handles request body buffers
	requestBodyBuffer *BodyBuffer

	// Handles response body buffers
	responseBodyBuffer *BodyBuffer

	// Rules with this id are going to be skipped while processing a phase
	ruleRemoveByID []int

	// ruleRemoveTargetByID is used by ctl to remove rule targets by id during the
	// transaction. All other "target removers" like "ByTag" are an abstraction of "ById"
	// For example, if you want to remove REQUEST_HEADERS:User-Agent from rule 85:
	// {85: {variables.RequestHeaders, "user-agent"}}
	ruleRemoveTargetByID map[int][]ruleVariableParams

	// Will skip this number of rules, this value will be decreased on each skip
	Skip int

	// Actions with capture features will read the capture state from this field
	// We have currently removed this feature as Capture will always run
	// We must reuse it in the future
	Capture bool

	// Contains duration in useconds per phase
	stopWatches map[types.RulePhase]int64

	// Contains a WAF instance for the current transaction
	WAF *WAF

	debugLogger debuglog.Logger

	// Timestamp of the request
	Timestamp int64

	// When a rule matches and contains r.Audit = true, this will be set to true
	// it will write to the audit log
	audit bool

	variables TransactionVariables

	transformationCache map[transformationKey]*transformationValue
}

func (tx *Transaction) ID() string {
	return tx.id
}

func (tx *Transaction) Variables() plugintypes.TransactionVariables {
	return &tx.variables
}

func (tx *Transaction) Collection(idx variables.RuleVariable) collection.Collection {
	switch idx {
	case variables.ResponseContentType:
		return tx.variables.responseContentType
	case variables.UniqueID:
		return tx.variables.uniqueID
	case variables.ArgsCombinedSize:
		return tx.variables.argsCombinedSize
	case variables.FilesCombinedSize:
		return tx.variables.filesCombinedSize
	case variables.FullRequestLength:
		return tx.variables.fullRequestLength
	case variables.InboundDataError:
		return tx.variables.inboundDataError
	case variables.MatchedVar:
		return tx.variables.matchedVar
	case variables.MatchedVarName:
		return tx.variables.matchedVarName
	case variables.MultipartDataAfter:
		return tx.variables.multipartDataAfter
	case variables.OutboundDataError:
		return tx.variables.outboundDataError
	case variables.QueryString:
		return tx.variables.queryString
	case variables.RemoteAddr:
		return tx.variables.remoteAddr
	case variables.RemoteHost:
		return tx.variables.remoteHost
	case variables.RemotePort:
		return tx.variables.remotePort
	case variables.ReqbodyError:
		return tx.variables.reqbodyError
	case variables.ReqbodyErrorMsg:
		return tx.variables.reqbodyErrorMsg
	case variables.ReqbodyProcessorError:
		return tx.variables.reqbodyProcessorError
	case variables.ReqbodyProcessorErrorMsg:
		return tx.variables.reqbodyProcessorErrorMsg
	case variables.ReqbodyProcessor:
		return tx.variables.reqbodyProcessor
	case variables.RequestBasename:
		return tx.variables.requestBasename
	case variables.RequestBody:
		return tx.variables.requestBody
	case variables.RequestBodyLength:
		return tx.variables.requestBodyLength
	case variables.RequestFilename:
		return tx.variables.requestFilename
	case variables.RequestLine:
		return tx.variables.requestLine
	case variables.RequestMethod:
		return tx.variables.requestMethod
	case variables.RequestProtocol:
		return tx.variables.requestProtocol
	case variables.RequestURI:
		return tx.variables.requestURI
	case variables.RequestURIRaw:
		return tx.variables.requestURIRaw
	case variables.ResponseBody:
		return tx.variables.responseBody
	case variables.ResponseContentLength:
		return tx.variables.responseContentLength
	case variables.ResponseProtocol:
		return tx.variables.responseProtocol
	case variables.ResponseStatus:
		return tx.variables.responseStatus
	case variables.ServerAddr:
		return tx.variables.serverAddr
	case variables.ServerName:
		return tx.variables.serverName
	case variables.ServerPort:
		return tx.variables.serverPort
	case variables.HighestSeverity:
		return tx.variables.highestSeverity
	case variables.StatusLine:
		return tx.variables.statusLine
	case variables.Duration:
		return tx.variables.duration
	case variables.ResponseHeadersNames:
		return tx.variables.responseHeadersNames
	case variables.RequestHeadersNames:
		return tx.variables.requestHeadersNames
	case variables.Args:
		return tx.variables.args
	case variables.ArgsGet:
		return tx.variables.argsGet
	case variables.ArgsPost:
		return tx.variables.argsPost
	case variables.ArgsPath:
		return tx.variables.argsPath
	case variables.FilesSizes:
		return tx.variables.filesSizes
	case variables.FilesNames:
		return tx.variables.filesNames
	case variables.FilesTmpContent:
		return tx.variables.filesTmpContent
	case variables.MultipartFilename:
		return tx.variables.multipartFilename
	case variables.MultipartName:
		return tx.variables.multipartName
	case variables.MatchedVarsNames:
		return tx.variables.matchedVarsNames
	case variables.MatchedVars:
		return tx.variables.matchedVars
	case variables.Files:
		return tx.variables.files
	case variables.RequestCookies:
		return tx.variables.requestCookies
	case variables.RequestHeaders:
		return tx.variables.requestHeaders
	case variables.ResponseHeaders:
		return tx.variables.responseHeaders
	case variables.Geo:
		return tx.variables.geo
	case variables.RequestCookiesNames:
		return tx.variables.requestCookiesNames
	case variables.FilesTmpNames:
		return tx.variables.filesTmpNames
	case variables.ArgsNames:
		return tx.variables.argsNames
	case variables.ArgsGetNames:
		return tx.variables.argsGetNames
	case variables.ArgsPostNames:
		return tx.variables.argsPostNames
	case variables.ResBodyProcessor:
		return tx.variables.resBodyProcessor
	case variables.TX:
		return tx.variables.tx
	case variables.Rule:
		return tx.variables.rule
	case variables.JSON:
		// TODO(anuraaga): This collection seems to be missing.
		return nil
	case variables.Env:
		return tx.variables.env
	case variables.UrlencodedError:
		return tx.variables.urlencodedError
	case variables.ResponseArgs:
		return tx.variables.responseArgs
	case variables.ResponseXML:
		return tx.variables.responseXML
	case variables.RequestXML:
		return tx.variables.requestXML
	case variables.XML:
		return tx.variables.xml
	case variables.MultipartPartHeaders:
		return tx.variables.multipartPartHeaders
	case variables.MultipartStrictError:
		return tx.variables.multipartStrictError
	case variables.Time:
		return tx.variables.time
	case variables.TimeDay:
		return tx.variables.timeDay
	case variables.TimeEpoch:
		return tx.variables.timeEpoch
	case variables.TimeHour:
		return tx.variables.timeHour
	case variables.TimeMin:
		return tx.variables.timeMin
	case variables.TimeMon:
		return tx.variables.timeMon
	case variables.TimeSec:
		return tx.variables.timeSec
	case variables.TimeWday:
		return tx.variables.timeWday
	case variables.TimeYear:
		return tx.variables.timeYear
	}

	return collections.Noop
}

func (tx *Transaction) Interrupt(interruption *types.Interruption) {
	if tx.RuleEngine == types.RuleEngineOn {
		tx.interruption = interruption
	} else if tx.RuleEngine == types.RuleEngineDetectionOnly {
		// Do not actually interrupt the transaction but still log it in the audit log
		tx.detectedInterruption = interruption
	}
}

func (tx *Transaction) DebugLogger() debuglog.Logger {
	return tx.debugLogger
}

func (tx *Transaction) SetDebugLogLevel(lvl debuglog.Level) {
	tx.debugLogger = tx.debugLogger.WithLevel(lvl)
}

func (tx *Transaction) ResponseBodyReader() (io.Reader, error) {
	return tx.responseBodyBuffer.Reader()
}

func (tx *Transaction) RequestBodyReader() (io.Reader, error) {
	return tx.requestBodyBuffer.Reader()
}

// AddRequestHeader Adds a request header
//
// With this method it is possible to feed Coraza with a request header.
// Note: Golang's *http.Request object will not contain a "Host" header,
// and you might have to force it
func (tx *Transaction) AddRequestHeader(key string, value string) {
	if key == "" {
		return
	}
	keyl := strings.ToLower(key)
	tx.variables.requestHeaders.Add(key, value)

	switch keyl {
	case "content-type":
		val := strings.ToLower(value)
		if val == "application/x-www-form-urlencoded" {
			tx.variables.reqbodyProcessor.Set("URLENCODED")
		} else if strings.HasPrefix(val, "multipart/form-data") {
			tx.variables.reqbodyProcessor.Set("MULTIPART")
		}
	case "cookie":
		// 4.2.  Cookie
		//
		// 4.2.1.  Syntax
		//
		//   The user agent sends stored cookies to the origin server in the
		//   Cookie header.  If the server conforms to the requirements in
		//   Section 4.1 (and the user agent conforms to the requirements in
		//   Section 5), the user agent will send a Cookie header that conforms to
		//   the following grammar:
		//
		//   cookie-header = "Cookie:" OWS cookie-string OWS
		//   cookie-string = cookie-pair *( ";" SP cookie-pair )
		//
		// There is no URL Decode performed no the cookies
		values := cookies.ParseCookies(value)
		for k, vr := range values {
			for _, v := range vr {
				tx.variables.requestCookies.Add(k, v)
			}
		}
	}
}

// AddResponseHeader Adds a response header variable
//
// With this method it is possible to feed Coraza with a response header.
func (tx *Transaction) AddResponseHeader(key string, value string) {
	if key == "" {
		return
	}
	keyl := strings.ToLower(key)
	tx.variables.responseHeaders.Add(key, value)

	// Most headers can be managed like that
	if keyl == "content-type" {
		name, _, _ := strings.Cut(value, ";")
		tx.variables.responseContentType.Set(name)
	}
}

func (tx *Transaction) Capturing() bool {
	return tx.Capture
}

// CaptureField is used to set the TX:[index] variables by operators
// that supports capture, like @rx
func (tx *Transaction) CaptureField(index int, value string) {
	if tx.Capture {
		tx.debugLogger.Debug().
			Int("field", index).
			Str("value", value).
			Msg("Capturing field")
		i := strconv.Itoa(index)
		tx.variables.tx.SetIndex(i, 0, value)
	}
}

// this function is used to control which variables are reset after a new rule is evaluated
func (tx *Transaction) resetCaptures() {
	tx.debugLogger.Debug().
		Msg("Reseting captured variables")
	// We reset capture 0-9
	ctx := tx.variables.tx
	// RUNE 48 = 0
	// RUNE 57 = 9
	for i := rune(48); i <= 57; i++ {
		ctx.SetIndex(string(i), 0, "")
	}
}

// ParseRequestReader Parses binary request including body,
// it does only support http/1.1 and http/1.0
// This function does not run ProcessConnection
// This function will store in memory the whole reader,
// DON't USE IT FOR PRODUCTION yet
func (tx *Transaction) ParseRequestReader(data io.Reader) (*types.Interruption, error) {
	// For dumb reasons we must read the headers and look for the Host header,
	// this function is intended for proxies and the RFC says that a Host must not be parsed...
	// Maybe some time I will create a prettier fix
	scanner := bufio.NewScanner(data)
	// read request line
	scanner.Scan()
	spl := strings.SplitN(scanner.Text(), " ", 3)
	if len(spl) != 3 {
		return nil, fmt.Errorf("invalid request line")
	}
	tx.ProcessURI(spl[1], spl[0], spl[2])
	for scanner.Scan() {
		l := scanner.Text()
		if l == "" {
			// It should mean we are now in the request body...
			break
		}
		key, val, ok := strings.Cut(l, ":")
		if !ok {
			return nil, fmt.Errorf("invalid request header")
		}
		k := strings.Trim(key, " ")
		v := strings.Trim(val, " ")
		tx.AddRequestHeader(k, v)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}
	ctcol := tx.variables.requestHeaders.Get("content-type")
	ct := ""
	if len(ctcol) > 0 {
		ct, _, _ = strings.Cut(ctcol[0], ";")
	}
	for scanner.Scan() {
		it, _, err := tx.WriteRequestBody(scanner.Bytes())
		if err != nil {
			return nil, fmt.Errorf("cannot write to request body to buffer: %s", err.Error())
		}

		if it != nil {
			return it, nil
		}

		// urlencoded cannot end with CRLF
		if ct != "application/x-www-form-urlencoded" {
			it, _, err := tx.WriteRequestBody([]byte{'\r', '\n'})
			if err != nil {
				return nil, fmt.Errorf("cannot write to request body to buffer: %s", err.Error())
			}

			if it != nil {
				return it, nil
			}
		}
	}
	return tx.ProcessRequestBody()
}

// matchVariable creates MATCHED_* variables required by chains and macro expansions
// MATCHED_VARS, MATCHED_VAR, MATCHED_VAR_NAME, MATCHED_VARS_NAMES
func (tx *Transaction) matchVariable(match *corazarules.MatchData) {
	var varName string
	if match.Key_ != "" {
		varName = match.Variable().Name() + ":" + match.Key_
	} else {
		varName = match.Variable().Name()
	}
	// Array of values
	matchedVars := tx.variables.matchedVars
	// Last key
	matchedVarName := tx.variables.matchedVarName
	matchedVarName.Reset()

	matchedVars.Add(varName, match.Value_)
	tx.variables.matchedVar.Set(match.Value_)

	matchedVarName.Set(varName)
}

// MatchRule Matches a rule to be logged
func (tx *Transaction) MatchRule(r *Rule, mds []types.MatchData) {
	tx.debugLogger.Debug().Int("rule_id", r.ID_).Msg("Rule matched")
	// tx.MatchedRules = append(tx.MatchedRules, mr)

	// If the rule is set to audit, we log the transaction to the audit log
	if r.Audit {
		tx.audit = true
	}

	// set highest_severity
	hs := tx.variables.highestSeverity
	maxSeverity, _ := types.ParseRuleSeverity(hs.Get())
	if r.Severity_ > maxSeverity {
		hs.Set(strconv.Itoa(r.Severity_.Int()))
	}

	mr := &corazarules.MatchedRule{
		URI_:             tx.variables.requestURI.Get(),
		TransactionID_:   tx.id,
		ServerIPAddress_: tx.variables.serverAddr.Get(),
		ClientIPAddress_: tx.variables.remoteAddr.Get(),
		Rule_:            &r.RuleMetadata,
		Log_:             r.Log,
		MatchedDatas_:    mds,
		Context_:         tx.context,
	}
	// Populate MatchedRule disruption related fields only if the Engine is capable of performing disruptive actions
	if tx.RuleEngine == types.RuleEngineOn {
		var exists bool
		for _, a := range r.actions {
			// There can be only at most one disruptive action per rule
			if a.Function.Type() == plugintypes.ActionTypeDisruptive {
				mr.DisruptiveAction_, exists = corazarules.DisruptiveActionMap[a.Name]
				if !exists {
					mr.DisruptiveAction_ = corazarules.DisruptiveActionUnknown
				}
				mr.Disruptive_ = true
				break
			}
		}
	}

	for _, md := range mds {
		// Use 1st set message of rule chain as message
		if md.Message() != "" {
			mr.Message_ = md.Message()
			mr.Data_ = md.Data()
			break
		}
	}

	tx.matchedRules = append(tx.matchedRules, mr)
	if tx.WAF.ErrorLogCb != nil && r.Log {
		tx.WAF.ErrorLogCb(mr)
	}

}

// GetStopWatch is used to debug phase durations
// Normally it should be named StopWatch() but it would be confusing
func (tx *Transaction) GetStopWatch() string {
	ts := tx.Timestamp
	sum := int64(0)
	for _, r := range tx.stopWatches {
		sum += r
	}
	diff := time.Now().UnixNano() - ts
	sw := fmt.Sprintf("%d %d; combined=%d, p1=%d, p2=%d, p3=%d, p4=%d, p5=%d",
		ts, diff, sum, tx.stopWatches[1], tx.stopWatches[2], tx.stopWatches[3], tx.stopWatches[4], tx.stopWatches[5])
	return sw
}

// GetField Retrieve data from collections applying exceptions
// In future releases we may remove the exceptions slice and
// make it easier to use
func (tx *Transaction) GetField(rv ruleVariableParams) []types.MatchData {
	col := tx.Collection(rv.Variable)
	if col == nil {
		return []types.MatchData{}
	}

	var matches []types.MatchData
	// Now that we have access to the collection, we can apply the exceptions
	switch {
	case rv.KeyRx != nil:
		if m, ok := col.(collection.Keyed); ok {
			matches = m.FindRegex(rv.KeyRx)
		} else {
			// This should probably never happen, selectability is checked at parsing time
			tx.debugLogger.Error().Str("collection", rv.Variable.Name()).Msg("attempted to use regex with non-selectable collection")
		}
	case rv.KeyStr != "":
		if m, ok := col.(collection.Keyed); ok {
			matches = m.FindString(rv.KeyStr)
		} else {
			// This should probably never happen, selectability is checked at parsing time
			tx.debugLogger.Error().Str("collection", rv.Variable.Name()).Msg("attempted to use string with non-selectable collection")
		}
	default:
		matches = col.FindAll()
	}

	// in the most common scenario filteredMatches length will be
	// the same as matches length, so we avoid allocating per result.
	// We reuse the matches slice to store filtered results avoiding extra allocation.
	filteredCount := 0
	for _, c := range matches {
		isException := false
		lkey := strings.ToLower(c.Key())
		for _, ex := range rv.Exceptions {
			if (ex.KeyRx != nil && ex.KeyRx.MatchString(lkey)) || strings.ToLower(ex.KeyStr) == lkey {
				isException = true
				break
			}
		}
		if !isException {
			matches[filteredCount] = c
			filteredCount++
		}
	}
	matches = matches[:filteredCount]

	if rv.Count {
		count := len(matches)
		matches = []types.MatchData{
			&corazarules.MatchData{
				Variable_: rv.Variable,
				Key_:      rv.KeyStr,
				Value_:    strconv.Itoa(count),
			},
		}
	}
	return matches
}

// RemoveRuleTargetByID Removes the VARIABLE:KEY from the rule ID
// It's mostly used by CTL to dynamically remove targets from rules
func (tx *Transaction) RemoveRuleTargetByID(id int, variable variables.RuleVariable, key string) {
	c := ruleVariableParams{
		Variable: variable,
		KeyStr:   key,
	}

	if multiphaseEvaluation && (variable == variables.Args || variable == variables.ArgsNames) {
		// ARGS and ARGS_NAMES have to be splitted into _GET and _POST
		switch variable {
		case variables.Args:
			c.Variable = variables.ArgsGet
			tx.ruleRemoveTargetByID[id] = append(tx.ruleRemoveTargetByID[id], c)
			c.Variable = variables.ArgsPost
			tx.ruleRemoveTargetByID[id] = append(tx.ruleRemoveTargetByID[id], c)
		case variables.ArgsNames:
			c.Variable = variables.ArgsGetNames
			tx.ruleRemoveTargetByID[id] = append(tx.ruleRemoveTargetByID[id], c)
			c.Variable = variables.ArgsPostNames
			tx.ruleRemoveTargetByID[id] = append(tx.ruleRemoveTargetByID[id], c)
		}
		return
	}
	tx.ruleRemoveTargetByID[id] = append(tx.ruleRemoveTargetByID[id], c)
}

// RemoveRuleByID Removes a rule from the transaction
// It does not affect the WAF rules
func (tx *Transaction) RemoveRuleByID(id int) {
	tx.ruleRemoveByID = append(tx.ruleRemoveByID, id)
}

// ProcessConnection should be called at very beginning of a request process, it is
// expected to be executed prior to the virtual host resolution, when the
// connection arrives on the server.
func (tx *Transaction) ProcessConnection(client string, cPort int, server string, sPort int) {
	p := strconv.Itoa(cPort)
	p2 := strconv.Itoa(sPort)

	// Modsecurity removed this, so maybe we do the same, such a copycat
	// addr, err := net.LookupAddr(client)
	// if err == nil {
	// 	tx.Variables.VARIABLE_REMOTE_HOST.Set(addr[0])
	// }else{
	// 	tx.Variables.VARIABLE_REMOTE_HOST.Set(client)
	// }

	tx.variables.remoteAddr.Set(client)
	tx.variables.remotePort.Set(p)
	tx.variables.serverAddr.Set(server)
	tx.variables.serverPort.Set(p2)
}

// ExtractGetArguments transforms an url encoded string to a map and creates ARGS_GET
func (tx *Transaction) ExtractGetArguments(uri string) {
	data := urlutil.ParseQuery(uri, '&')
	for k, vs := range data {
		for _, v := range vs {
			tx.AddGetRequestArgument(k, v)
		}
	}
}

// AddGetRequestArgument
func (tx *Transaction) AddGetRequestArgument(key string, value string) {
	if tx.checkArgumentLimit(tx.variables.argsGet) {
		tx.debugLogger.Warn().Msg("skipping get request argument, over limit")
		return
	}
	tx.variables.argsGet.Add(key, value)
}

// AddPostRequestArgument
func (tx *Transaction) AddPostRequestArgument(key string, value string) {
	if tx.checkArgumentLimit(tx.variables.argsPost) {
		tx.debugLogger.Warn().Msg("skipping post request argument, over limit")
		return
	}
	tx.variables.argsPost.Add(key, value)
}

// AddPathRequestArgument
func (tx *Transaction) AddPathRequestArgument(key string, value string) {
	if tx.checkArgumentLimit(tx.variables.argsPath) {
		tx.debugLogger.Warn().Msg("skipping path request argument, over limit")
		return
	}
	tx.variables.argsPath.Add(key, value)
}

func (tx *Transaction) checkArgumentLimit(c *collections.NamedCollection) bool {
	return c.Len() >= tx.WAF.ArgumentLimit
}

// AddResponseArgument
func (tx *Transaction) AddResponseArgument(key string, value string) {
	if tx.variables.responseArgs.Len() >= tx.WAF.ArgumentLimit {
		tx.debugLogger.Warn().Msg("skipping response argument, over limit")
		return
	}
	tx.variables.responseArgs.Add(key, value)
}

// ProcessURI Performs the analysis on the URI and all the query string variables.
// This method should be called at very beginning of a request process, it is
// expected to be executed prior to the virtual host resolution, when the
// connection arrives on the server.
// note: There is no direct connection between this function and any phase of the
// SecLanguages phases. It is something that may occur between the SecLanguage
// phase 1 and 2.
//
// note: This function won't add GET arguments, they must be added with AddArgument
func (tx *Transaction) ProcessURI(uri string, method string, httpVersion string) {
	tx.variables.requestMethod.Set(method)
	tx.variables.requestProtocol.Set(httpVersion)
	tx.variables.requestURIRaw.Set(uri)

	// TODO modsecurity uses HTTP/${VERSION} instead of just version, let's check it out
	tx.variables.requestLine.Set(fmt.Sprintf("%s %s %s", method, uri, httpVersion))

	var err error

	// we remove anchors
	if in := strings.Index(uri, "#"); in != -1 {
		uri = uri[:in]
	}
	path := ""
	parsedURL, err := url.ParseRequestURI(uri)
	query := ""
	if err != nil {
		tx.variables.urlencodedError.Set(err.Error())
		path = uri
		tx.variables.requestURI.Set(uri)
		/*
			tx.Variables.VARIABLE_URI_PARSE_ERROR.Set("1")
			posRawQuery := strings.Index(uri, "?")
			if posRawQuery != -1 {
				tx.ExtractArguments("GET", uri[posRawQuery+1:])
				path = uri[:posRawQuery]
				query = uri[posRawQuery+1:]
			} else {
				path = uri
			}
			tx.Variables.RequestUri.Set(uri)
		*/
	} else {
		tx.ExtractGetArguments(parsedURL.RawQuery)
		tx.variables.requestURI.Set(parsedURL.String())
		path = parsedURL.Path
		query = parsedURL.RawQuery
	}
	offset := strings.LastIndexAny(path, "/\\")
	if offset != -1 && len(path) > offset+1 {
		tx.variables.requestBasename.Set(path[offset+1:])
	} else {
		tx.variables.requestBasename.Set(path)
	}
	tx.variables.requestFilename.Set(path)

	tx.variables.queryString.Set(query)
}

// SetServerName allows to set server name details.
//
// The API consumer is in charge of retrieving the value (e.g. from the host header).
// It is expected to be executed before calling ProcessRequestHeaders.
func (tx *Transaction) SetServerName(serverName string) {
	if tx.lastPhase >= types.PhaseRequestHeaders {
		tx.debugLogger.Warn().Msg("SetServerName has been called after ProcessRequestHeaders")
	}
	tx.variables.serverName.Set(serverName)
}

// ProcessRequestHeaders Performs the analysis on the request readers.
//
// This method perform the analysis on the request headers, notice however
// that the headers should be added prior to the execution of this function.
//
// note: Remember to check for a possible intervention.
func (tx *Transaction) ProcessRequestHeaders() *types.Interruption {
	if tx.RuleEngine == types.RuleEngineOff {
		// Rule engine is disabled
		return nil
	}
	if tx.lastPhase >= types.PhaseRequestHeaders {
		// Phase already evaluated
		tx.debugLogger.Error().Msg("ProcessRequestHeaders has already been called")
		return tx.interruption
	}

	if tx.interruption != nil {
		tx.debugLogger.Error().Msg("Calling ProcessRequestHeaders but there is a preexisting interruption")
		return tx.interruption
	}

	tx.WAF.Rules.Eval(types.PhaseRequestHeaders, tx)
	return tx.interruption
}

func setAndReturnBodyLimitInterruption(tx *Transaction, status int) (*types.Interruption, int, error) {
	tx.debugLogger.Warn().Msg("Disrupting transaction with body size above the configured limit (Action Reject)")
	tx.interruption = &types.Interruption{
		Status: status,
		Action: "deny",
	}
	return tx.interruption, 0, nil
}

// WriteRequestBody writes bytes from a slice of bytes into the request body,
// it returns an interruption if the writing bytes go beyond the request body limit.
// It won't copy the bytes if the body access isn't accessible.
func (tx *Transaction) WriteRequestBody(b []byte) (*types.Interruption, int, error) {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil, 0, nil
	}

	if !tx.RequestBodyAccess {
		return nil, 0, nil
	}

	if tx.RequestBodyLimit == tx.requestBodyBuffer.length {
		// tx.RequestBodyLimit will never be zero so if this happened, we have an
		// interruption (that has been previously raised, but ignored by the connector) for sure.
		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionReject {
			return tx.interruption, 0, nil
		}

		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionProcessPartial {
			return nil, 0, nil
		}
	}

	var (
		writingBytes          = int64(len(b))
		runProcessRequestBody = false
	)
	// Overflow check
	if tx.requestBodyBuffer.length >= (math.MaxInt64 - writingBytes) {
		// Overflow, failing. MaxInt64 is not a realistic payload size. Furthermore, it has been tested that
		// bytes.Buffer does not work with this kind of sizes. See comments in BodyBuffer Write(data []byte)
		return nil, 0, errors.New("overflow reached while writing request body")
	}

	if tx.requestBodyBuffer.length+writingBytes >= tx.RequestBodyLimit {
		tx.variables.inboundDataError.Set("1")
		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionReject {
			// We interrupt this transaction in case RequestBodyLimitAction is Reject
			return setAndReturnBodyLimitInterruption(tx, 413)
		}

		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionProcessPartial {
			writingBytes = tx.RequestBodyLimit - tx.requestBodyBuffer.length
			runProcessRequestBody = true
		}
	}

	w, err := tx.requestBodyBuffer.Write(b[:writingBytes])
	if err != nil {
		return nil, 0, err
	}

	if runProcessRequestBody {
		tx.debugLogger.Warn().Msg("Processing request body whose size reached the configured limit (Action ProcessPartial)")
		_, err = tx.ProcessRequestBody()
	}
	return tx.interruption, int(w), err
}

// ByteLenger returns the length in bytes of a data stream.
type ByteLenger interface {
	Len() int
}

// ReadRequestBodyFrom writes bytes from a reader into the request body
// it returns an interruption if the writing bytes go beyond the request body limit.
// It won't read the reader if the body access isn't accessible.
func (tx *Transaction) ReadRequestBodyFrom(r io.Reader) (*types.Interruption, int, error) {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil, 0, nil
	}

	if !tx.RequestBodyAccess {
		return nil, 0, nil
	}

	if tx.RequestBodyLimit == tx.requestBodyBuffer.length {
		// tx.RequestBodyLimit will never be zero so if this happened, we have an
		// interruption (that has been previously raised, but ignored by the connector) for sure.
		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionReject {
			return tx.interruption, 0, nil
		}

		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionProcessPartial {
			return nil, 0, nil
		}
	}

	var (
		writingBytes          int64
		runProcessRequestBody = false
	)
	if l, ok := r.(ByteLenger); ok {
		writingBytes = int64(l.Len())
		// Overflow check
		if tx.requestBodyBuffer.length >= (math.MaxInt64 - writingBytes) {
			// Overflow, failing. MaxInt64 is not a realistic payload size. Furthermore, it has been tested that
			// bytes.Buffer does not work with this kind of sizes. See comments in BodyBuffer Write(data []byte)
			return nil, 0, errors.New("overflow reached while writing request body")
		}
		if tx.requestBodyBuffer.length+writingBytes >= tx.RequestBodyLimit {
			tx.variables.inboundDataError.Set("1")
			if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionReject {
				return setAndReturnBodyLimitInterruption(tx, 413)
			}

			if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionProcessPartial {
				writingBytes = tx.RequestBodyLimit - tx.requestBodyBuffer.length
				runProcessRequestBody = true
			}
		}
	} else {
		writingBytes = tx.RequestBodyLimit - tx.requestBodyBuffer.length
	}

	w, err := io.CopyN(tx.requestBodyBuffer, r, writingBytes)
	if err != nil && err != io.EOF {
		return nil, int(w), err
	}

	if tx.requestBodyBuffer.length == tx.RequestBodyLimit {
		tx.variables.inboundDataError.Set("1")
		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionReject {
			return setAndReturnBodyLimitInterruption(tx, 413)
		}

		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionProcessPartial {
			runProcessRequestBody = true
		}
	}

	err = nil
	if runProcessRequestBody {
		tx.debugLogger.Warn().Msg("Processing request body whose size reached the configured limit (Action ProcessPartial)")
		_, err = tx.ProcessRequestBody()
	}
	return tx.interruption, int(w), err
}

// ProcessRequestBody Performs the analysis of the request body (if any)
//
// It is recommended to call this method even if it is not expected to have a body.
// It permits to execute rules belonging to request body phase, but not necessarily
// processing the request body.
//
// Remember to check for a possible intervention.
func (tx *Transaction) ProcessRequestBody() (*types.Interruption, error) {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil, nil
	}

	if tx.interruption != nil {
		tx.debugLogger.Error().Msg("Calling ProcessRequestBody but there is a preexisting interruption")
		return tx.interruption, nil
	}

	if tx.lastPhase != types.PhaseRequestHeaders {
		switch {
		case tx.lastPhase == types.PhaseRequestBody:
			// This condition can happen quite often when ProcessPartial is used as the write body functions call ProcessRequestBody when
			// the limit is reached
			tx.debugLogger.Debug().Msg("Request body processing has been already performed")
		case tx.lastPhase > types.PhaseRequestBody:
			tx.debugLogger.Warn().Msg("Skipping anomalous call to ProcessRequestBody. It should have already been called")
		default:
			tx.debugLogger.Warn().Msg("Skipping anomalous call to ProcessRequestBody. It has been called before request headers evaluation")
		}
		return nil, nil
	}

	// we won't process empty request bodies or disabled RequestBodyAccess
	if !tx.RequestBodyAccess || tx.requestBodyBuffer.length == 0 {
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.interruption, nil
	}
	mime := ""
	if m := tx.variables.requestHeaders.Get("content-type"); len(m) > 0 {
		mime = m[0]
	}

	reader, err := tx.requestBodyBuffer.Reader()
	if err != nil {
		return nil, err
	}

	rbp := tx.variables.reqbodyProcessor.Get()

	// Default variables.ReqbodyProcessor values
	// XML and JSON must be forced with ctl:requestBodyProcessor=JSON
	if tx.ForceRequestBodyVariable {
		// We force URLENCODED if mime is x-www... or we have an empty RBP and ForceRequestBodyVariable
		if rbp == "" {
			rbp = "URLENCODED"
		}
		tx.variables.reqbodyProcessor.Set(rbp)
	}
	rbp = strings.ToLower(rbp)
	if rbp == "" {
		// so there is no bodyprocessor, we don't want to generate an error
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.interruption, nil
	}
	bodyprocessor, err := bodyprocessors.GetBodyProcessor(rbp)
	if err != nil {
		tx.generateRequestBodyError(errors.New("invalid body processor"))
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.interruption, nil
	}

	tx.debugLogger.Debug().
		Str("body_processor", rbp).
		Msg("Attempting to process request body")

	if err := bodyprocessor.ProcessRequest(reader, tx.Variables(), plugintypes.BodyProcessorOptions{
		Mime:        mime,
		StoragePath: tx.WAF.UploadDir,
	}); err != nil {
		tx.debugLogger.Error().Err(err).Msg("Failed to process request body")
		tx.generateRequestBodyError(err)
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.interruption, nil
	}

	tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
	return tx.interruption, nil
}

// ProcessResponseHeaders performs the analysis on the response headers.
//
// This method performs the analysis on the response headers. Note, however,
// that the headers should be added prior to the execution of this function.
//
// Note: Remember to check for a possible intervention.
func (tx *Transaction) ProcessResponseHeaders(code int, proto string) *types.Interruption {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil
	}

	if tx.lastPhase >= types.PhaseResponseHeaders {
		// Phase already evaluated
		tx.debugLogger.Error().Msg("ProcessResponseHeaders has already been called")
		return tx.interruption
	}

	if tx.interruption != nil {
		tx.debugLogger.Error().Msg("Calling ProcessResponseHeaders but there is a preexisting interruption")
		return tx.interruption
	}

	c := strconv.Itoa(code)
	tx.variables.responseStatus.Set(c)
	tx.variables.responseProtocol.Set(proto)

	tx.WAF.Rules.Eval(types.PhaseResponseHeaders, tx)
	return tx.interruption
}

// IsResponseBodyProcessable returns true if the response body meets the
// criteria to be processed, response headers must be set before this.
// The content-type response header must be in the SecResponseBodyMimeType
// This is used by webservers to choose whether to stream response buffers
// directly to the client or write them to Coraza's buffer.
func (tx *Transaction) IsResponseBodyProcessable() bool {
	// TODO add more validations
	if tx.ForceResponseBodyVariable {
		// we force the response body to be processed because of the ctl:forceResponseBodyVariable
		return true
	}
	ct := tx.variables.responseContentType.Get()
	return stringsutil.InSlice(ct, tx.WAF.ResponseBodyMimeTypes)
}

// WriteResponseBody writes bytes from a slice of bytes into the response body,
// it returns an interruption if the writing bytes go beyond the response body limit.
// It won't copy the bytes if the body access isn't accessible.
func (tx *Transaction) WriteResponseBody(b []byte) (*types.Interruption, int, error) {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil, 0, nil
	}

	if !tx.ResponseBodyAccess {
		return nil, 0, nil
	}

	if tx.ResponseBodyLimit == tx.responseBodyBuffer.length {
		// tx.ResponseBodyLimit will never be zero so if this happened, we have an
		// interruption for sure.
		if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionReject {
			return tx.interruption, 0, nil
		}

		if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionProcessPartial {
			return nil, 0, nil
		}
	}

	var (
		writingBytes           = int64(len(b))
		runProcessResponseBody = false
	)
	if tx.responseBodyBuffer.length+writingBytes >= tx.ResponseBodyLimit {
		tx.variables.outboundDataError.Set("1")
		if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionReject {
			// We interrupt this transaction in case ResponseBodyLimitAction is Reject
			return setAndReturnBodyLimitInterruption(tx, 500)
		}

		if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionProcessPartial {
			writingBytes = tx.ResponseBodyLimit - tx.responseBodyBuffer.length
			runProcessResponseBody = true
		}
	}
	w, err := tx.responseBodyBuffer.Write(b[:writingBytes])
	if err != nil {
		return nil, 0, err
	}

	if runProcessResponseBody {
		_, err = tx.ProcessResponseBody()
	}
	return tx.interruption, int(w), err
}

// ReadResponseBodyFrom writes bytes from a reader into the response body
// it returns an interruption if the writing bytes go beyond the response body limit.
// It won't read the reader if the body access isn't accessible.
func (tx *Transaction) ReadResponseBodyFrom(r io.Reader) (*types.Interruption, int, error) {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil, 0, nil
	}

	if !tx.ResponseBodyAccess {
		return nil, 0, nil
	}

	if tx.ResponseBodyLimit == tx.responseBodyBuffer.length {
		if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionReject {
			return tx.interruption, 0, nil
		}

		if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionProcessPartial {
			return nil, 0, nil
		}
	}

	var (
		writingBytes           int64
		runProcessResponseBody = false
	)
	if l, ok := r.(ByteLenger); ok {
		writingBytes = int64(l.Len())
		if tx.responseBodyBuffer.length+writingBytes >= tx.ResponseBodyLimit {
			tx.variables.outboundDataError.Set("1")
			if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionReject {
				return setAndReturnBodyLimitInterruption(tx, 500)
			}

			if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionProcessPartial {
				writingBytes = tx.ResponseBodyLimit - tx.responseBodyBuffer.length
				runProcessResponseBody = true
			}
		}
	} else {
		writingBytes = tx.ResponseBodyLimit - tx.responseBodyBuffer.length
	}

	w, err := io.CopyN(tx.responseBodyBuffer, r, writingBytes)
	if err != nil && err != io.EOF {
		return nil, int(w), err
	}

	if tx.responseBodyBuffer.length == tx.ResponseBodyLimit {
		tx.variables.outboundDataError.Set("1")
		if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionReject {
			return setAndReturnBodyLimitInterruption(tx, 500)
		}

		if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionProcessPartial {
			runProcessResponseBody = true
		}
	}

	err = nil
	if runProcessResponseBody {
		_, err = tx.ProcessResponseBody()
	}
	return tx.interruption, int(w), err
}

// ProcessResponseBody Perform the analysis of the the response body (if any)
//
// It is recommended to call this method even if it is not expected to have a body.
// It permits to execute rules belonging to request body phase, but not necessarily
// processing the response body.
//
// note Remember to check for a possible intervention.
func (tx *Transaction) ProcessResponseBody() (*types.Interruption, error) {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil, nil
	}

	if tx.interruption != nil {
		tx.debugLogger.Error().Msg("Calling ProcessResponseBody but there is a preexisting interruption")
		return tx.interruption, nil
	}

	if tx.lastPhase != types.PhaseResponseHeaders {
		switch {
		case tx.lastPhase == types.PhaseResponseBody:
			// This condition can happen quite often when ProcessPartial is used as the write body functions call ProcessResponseBody when
			// the limit is reached
			tx.debugLogger.Debug().Msg("Response body processing has been already performed")
		case tx.lastPhase > types.PhaseResponseBody:
			tx.debugLogger.Warn().Msg("Skipping anomalous call to ProcessResponseBody. It should have already been called")
		default:
			// Prevents evaluating response body rules if last phase has not been response headers. It may happen
			// when a server returns an error prior to evaluating WAF rules, but ResponseBody is still called at
			// the end of http stream
			tx.debugLogger.Warn().Msg("Skipping anomalous call to ProcessResponseBody. It has been called before response headers evaluation")
		}
		return nil, nil
	}

	if !tx.ResponseBodyAccess || !tx.IsResponseBodyProcessable() {
		tx.debugLogger.Debug().
			Bool("response_body_access", tx.ResponseBodyAccess).
			Msg("Skipping response body processing")
		tx.WAF.Rules.Eval(types.PhaseResponseBody, tx)
		return tx.interruption, nil
	}

	reader, err := tx.responseBodyBuffer.Reader()
	if err != nil {
		return tx.interruption, err
	}

	if bp := tx.variables.resBodyProcessor.Get(); bp != "" {
		b, err := bodyprocessors.GetBodyProcessor(bp)
		if err != nil {
			tx.generateResponseBodyError(errors.New("invalid body processor"))
			tx.WAF.Rules.Eval(types.PhaseResponseBody, tx)
			return tx.interruption, err
		}

		tx.debugLogger.Debug().Str("body_processor", bp).Msg("Attempting to process response body")

		if err := b.ProcessResponse(reader, tx.Variables(), plugintypes.BodyProcessorOptions{}); err != nil {
			tx.debugLogger.Error().Err(err).Msg("Failed to process response body")
			tx.generateResponseBodyError(err)
		}
	} else {
		buf := new(strings.Builder)
		length, err := io.Copy(buf, reader)
		if err != nil {
			return tx.interruption, err
		}
		tx.variables.responseContentLength.Set(strconv.FormatInt(length, 10))
		tx.variables.responseBody.Set(buf.String())
	}
	tx.WAF.Rules.Eval(types.PhaseResponseBody, tx)
	return tx.interruption, nil
}

// ProcessLogging logs all information relative to this transaction.
// At this point there is not need to hold the connection, the response can be
// delivered prior to the execution of this method.
func (tx *Transaction) ProcessLogging() {
	// If Rule engine is disabled, Log phase rules are not going to be evaluated.
	// This avoids trying to rely on variables not set by previous rules that
	// have not been executed
	if tx.RuleEngine != types.RuleEngineOff {
		tx.WAF.Rules.Eval(types.PhaseLogging, tx)
	}

	if tx.AuditEngine == types.AuditEngineOff {
		// Audit engine disabled
		tx.debugLogger.Debug().
			Msg("Transaction not marked for audit logging, AuditEngine is disabled")
		return
	}

	if tx.AuditEngine == types.AuditEngineRelevantOnly && !tx.audit {
		// Transaction marked not for audit logging
		tx.debugLogger.Debug().
			Msg("Transaction not marked for audit logging, AuditEngine is RelevantOnly and we got noauditlog")
		return
	}

	if tx.AuditEngine == types.AuditEngineRelevantOnly && tx.audit {
		re := tx.WAF.AuditLogRelevantStatus
		status := tx.variables.responseStatus.Get()
		if tx.IsInterrupted() {
			status = strconv.Itoa(tx.interruption.Status)
		} else if tx.detectedInterruption != nil {
			status = strconv.Itoa(tx.detectedInterruption.Status)
		}
		if re != nil && !re.Match([]byte(status)) {
			// Not relevant status
			tx.debugLogger.Debug().
				Msg("Transaction status not marked for audit logging")
			return
		}
	}

	tx.debugLogger.Debug().
		Msg("Transaction marked for audit logging")

	// We don't log if there is an empty audit logger
	if err := tx.WAF.AuditLogWriter().Write(tx.AuditLog()); err != nil {
		tx.debugLogger.Error().
			Err(err).
			Msg("Failed to write audit log")
	}
}

// IsRuleEngineOff will return true if RuleEngine is set to Off
func (tx *Transaction) IsRuleEngineOff() bool {
	return tx.RuleEngine == types.RuleEngineOff
}

// IsRequestBodyAccessible will return true if RequestBody access has been enabled by RequestBodyAccess
func (tx *Transaction) IsRequestBodyAccessible() bool {
	return tx.RequestBodyAccess
}

// IsResponseBodyAccessible will return true if ResponseBody access has been enabled by ResponseBodyAccess
func (tx *Transaction) IsResponseBodyAccessible() bool {
	return tx.ResponseBodyAccess
}

// IsInterrupted will return true if the transaction was interrupted
func (tx *Transaction) IsInterrupted() bool {
	return tx.interruption != nil
}

func (tx *Transaction) Interruption() *types.Interruption {
	return tx.interruption
}

func (tx *Transaction) MatchedRules() []types.MatchedRule {
	return tx.matchedRules
}

func (tx *Transaction) LastPhase() types.RulePhase {
	return tx.lastPhase
}

// AuditLog returns an AuditLog struct, used to write audit logs.
// It implies the log parts starts with A and ends with Z as in the
// types.ParseAuditLogParts.
func (tx *Transaction) AuditLog() *auditlog.Log {
	al := &auditlog.Log{}
	al.Parts_ = tx.AuditLogParts

	clientPort, _ := strconv.Atoi(tx.variables.remotePort.Get())
	hostPort, _ := strconv.Atoi(tx.variables.serverPort.Get())

	// Convert the transaction fullRequestLength to Int32
	requestLength, err := strconv.ParseInt(tx.variables.fullRequestLength.Get(), 10, 32)
	if err != nil {
		requestLength = 0
		tx.DebugLogger().Error().
			Str("transaction", "AuditLog").
			Str("value", tx.variables.fullRequestLength.Get()).
			Err(err).
			Msg("Error converting request length to integer")
	}

	// YYYY/MM/DD HH:mm:ss
	ts := time.Unix(0, tx.Timestamp).Format("2006/01/02 15:04:05")
	al.Transaction_ = auditlog.Transaction{
		Timestamp_:     ts,
		UnixTimestamp_: tx.Timestamp,
		ID_:            tx.id,
		ClientIP_:      tx.variables.remoteAddr.Get(),
		ClientPort_:    clientPort,
		HostIP_:        tx.variables.serverAddr.Get(),
		HostPort_:      hostPort,
		ServerID_:      tx.variables.serverName.Get(), // TODO check
		Request_: &auditlog.TransactionRequest{
			Method_:   tx.variables.requestMethod.Get(),
			URI_:      tx.variables.requestURI.Get(),
			Protocol_: tx.variables.requestProtocol.Get(),
			Args_:     tx.variables.args,
			Length_:   int32(requestLength),
		},
		IsInterrupted_: tx.IsInterrupted(),
	}

	var auditLogPartAuditLogTrailerSet, auditLogPartRulesMatchedSet bool
	for _, part := range tx.AuditLogParts {
		switch part {
		case types.AuditLogPartRequestHeaders:
			al.Transaction_.Request_.Headers_ = tx.variables.requestHeaders.Data()
		case types.AuditLogPartRequestBody:
			reader, err := tx.requestBodyBuffer.Reader()
			if err == nil {
				content, err := io.ReadAll(reader)
				if err == nil {
					al.Transaction_.Request_.Body_ = string(content)
				}
			}

			/*
			* TODO:
			* This part is a replacement for part C. It will log the same data as C in
			* all cases except when multipart/form-data encoding in used. In this case,
			* it will log a fake application/x-www-form-urlencoded body that contains
			* the information about parameters but not about the files. This is handy
			* if you don’t want to have (often large) files stored in your audit logs.
			 */
			// upload data
			var files []plugintypes.AuditLogTransactionRequestFiles
			al.Transaction_.Request_.Files_ = nil
			for _, file := range tx.variables.files.Get("") {
				var size int64
				if fs := tx.variables.filesSizes.Get(file); len(fs) > 0 {
					size, _ = strconv.ParseInt(fs[0], 10, 64)
					// we ignore the error as it defaults to 0
				}
				ext := filepath.Ext(file)
				at := auditlog.TransactionRequestFiles{
					Size_: size,
					Name_: file,
					Mime_: mime.TypeByExtension(ext),
				}
				files = append(files, at)
			}
			al.Transaction_.Request_.Files_ = files
		case types.AuditLogPartIntermediaryResponseBody:
			if al.Transaction_.Response_ == nil {
				al.Transaction_.Response_ = &auditlog.TransactionResponse{}
			}
			al.Transaction_.Response_.Body_ = tx.variables.responseBody.Get()
		case types.AuditLogPartResponseHeaders:
			if al.Transaction_.Response_ == nil {
				al.Transaction_.Response_ = &auditlog.TransactionResponse{}
			}
			status, _ := strconv.Atoi(tx.variables.responseStatus.Get())
			al.Transaction_.Response_.Status_ = status
			al.Transaction_.Response_.Headers_ = tx.variables.responseHeaders.Data()
		case types.AuditLogPartAuditLogTrailer:
			auditLogPartAuditLogTrailerSet = true
			al.Transaction_.Producer_ = &auditlog.TransactionProducer{
				Connector_:  tx.WAF.ProducerConnector,
				Version_:    tx.WAF.ProducerConnectorVersion,
				Server_:     "",
				RuleEngine_: tx.RuleEngine.String(),
				Stopwatch_:  tx.GetStopWatch(),
				Rulesets_:   tx.WAF.ComponentNames,
			}
		case types.AuditLogPartRulesMatched:
			auditLogPartRulesMatchedSet = true
			for _, mr := range tx.matchedRules {
				// Log action is required to log a matched rule on both error log and audit log
				// An assertion has to be done to check if the MatchedRule implements the Log() function before calling Log()
				// It is performed to avoid breaking the Coraza v3.* API adding a Log() method to the MatchedRule interface
				mrWithlog, ok := mr.(*corazarules.MatchedRule)
				if ok && mrWithlog.Log() {
					r := mr.Rule()
					for _, matchData := range mr.MatchedDatas() {
						newAlEntry := auditlog.Message{
							Actionset_: strings.Join(tx.WAF.ComponentNames, " "),
							Message_:   matchData.Message(),
							Data_: &auditlog.MessageData{
								File_:     mr.Rule().File(),
								Line_:     mr.Rule().Line(),
								ID_:       r.ID(),
								Rev_:      r.Revision(),
								Msg_:      matchData.Message(),
								Data_:     matchData.Data(),
								Severity_: r.Severity(),
								Ver_:      r.Version(),
								Maturity_: r.Maturity(),
								Accuracy_: r.Accuracy(),
								Tags_:     r.Tags(),
								Raw_:      r.Raw(),
							},
						}
						// If AuditLogPartAuditLogTrailer (H) is set, we expect to log the error messages emitted by the rules
						// in the audit log
						if auditLogPartAuditLogTrailerSet {
							newAlEntry.ErrorMessage_ = mr.ErrorLog()
						}
						al.Messages_ = append(al.Messages_, newAlEntry)
					}
				}
			}
		}
	}

	// If AuditLogPartRulesMatched (K) is not set, but AuditLogPartAuditLogTrailer (H) is set, we still expect to
	// log the error messages emitted by the rules (if the rule has Log set to true)
	if !auditLogPartRulesMatchedSet && auditLogPartAuditLogTrailerSet {
		for _, mr := range tx.matchedRules {
			mrWithlog, ok := mr.(*corazarules.MatchedRule)
			if ok && mrWithlog.Log() {
				al.Messages_ = append(al.Messages_, auditlog.Message{
					ErrorMessage_: mr.ErrorLog(),
				})
			}
		}

	}

	return al
}

// Close closes the transaction after phase 5
// This method helps the GC to clean up the transaction faster and release resources
// It also allows caches the transaction back into the sync.Pool
func (tx *Transaction) Close() error {
	defer tx.WAF.txPool.Put(tx)

	var errs []error
	if environment.HasAccessToFS {
		// TODO(jcchavezs): filesTmpNames should probably be a new kind of collection that
		// is aware of the files and then attempt to delete them when the collection
		// is resetted or an item is removed.
		for _, file := range tx.variables.filesTmpNames.Get("") {
			if err := os.Remove(file); err != nil {
				errs = append(errs, fmt.Errorf("removing temporary file: %v", err))
			}
		}
	}

	tx.variables.reset()
	if err := tx.requestBodyBuffer.Reset(); err != nil {
		errs = append(errs, fmt.Errorf("reseting request body buffer: %v", err))
	}
	if err := tx.responseBodyBuffer.Reset(); err != nil {
		errs = append(errs, fmt.Errorf("reseting response body buffer: %v", err))
	}

	if tx.IsInterrupted() {
		tx.debugLogger.Debug().
			Bool("is_interrupted", tx.IsInterrupted()).
			Int("status", tx.interruption.Status).
			Int("rule_id", tx.interruption.RuleID).
			Msg("Transaction finished")
	} else {
		tx.debugLogger.Debug().
			Bool("is_interrupted", false).
			Msg("Transaction finished")
	}

	if len(errs) == 0 {
		return nil
	}

	return fmt.Errorf("transaction close failed: %v", errors.Join(errs...))
}

// String will return a string with the transaction debug information
func (tx *Transaction) String() string {
	res := strings.Builder{}
	res.WriteString("\n\n----------------------- ERRORLOG ----------------------\n")
	for _, mr := range tx.matchedRules {
		res.WriteString(mr.ErrorLog())
		res.WriteString("\n\n----------------------- MATCHDATA ---------------------\n")
		for _, md := range mr.MatchedDatas() {
			fmt.Fprintf(&res, "%+v\n", md)
		}
		res.WriteByte('\n')
	}

	res.WriteString("\n------------------------ DEBUG ------------------------\n")
	tx.variables.format(&res)
	return res.String()
}

// generateRequestBodyError generates all the error variables for the request body parser
func (tx *Transaction) generateRequestBodyError(err error) {
	tx.variables.reqbodyError.Set("1")
	tx.variables.reqbodyErrorMsg.Set(fmt.Sprintf("%s: %s", tx.variables.reqbodyProcessor.Get(), err.Error()))
	tx.variables.reqbodyProcessorError.Set("1")
	tx.variables.reqbodyProcessorErrorMsg.Set(err.Error())
}

// generateResponseBodyError generates all the error variables for the response body parser
func (tx *Transaction) generateResponseBodyError(err error) {
	tx.variables.resBodyError.Set("1")
	tx.variables.resBodyErrorMsg.Set(fmt.Sprintf("%s: %s", tx.variables.resBodyProcessor.Get(), err.Error()))
	tx.variables.resBodyProcessorError.Set("1")
	tx.variables.resBodyProcessorErrorMsg.Set(err.Error())
}

// setTimeVariables sets all the time variables
func (tx *Transaction) setTimeVariables() {
	timestamp := time.Unix(0, tx.Timestamp)
	tx.variables.timeEpoch.Set(strconv.FormatInt(timestamp.Unix(), 10))

	timeOnly := timestamp.Format(time.TimeOnly)
	tx.variables.time.Set(timeOnly)
	tx.variables.timeHour.Set(timeOnly[0:2])
	tx.variables.timeMin.Set(timeOnly[3:5])
	tx.variables.timeSec.Set(timeOnly[6:8])

	y, m, d := timestamp.Date()
	tx.variables.timeDay.Set(strconv.Itoa(d))
	tx.variables.timeMon.Set(strconv.Itoa(int(m)))
	tx.variables.timeYear.Set(strconv.Itoa(y))

	tx.variables.timeWday.Set(strconv.Itoa(int(timestamp.Weekday())))
}

// TransactionVariables has pointers to all the variables of the transaction
type TransactionVariables struct {
	args                     *collections.ConcatKeyed
	argsCombinedSize         *collections.SizeCollection
	argsGet                  *collections.NamedCollection
	argsGetNames             collection.Keyed
	argsNames                *collections.ConcatKeyed
	argsPath                 *collections.NamedCollection
	argsPost                 *collections.NamedCollection
	argsPostNames            collection.Keyed
	duration                 *collections.Single
	env                      *collections.Map
	files                    *collections.Map
	filesCombinedSize        *collections.Single
	filesNames               *collections.Map
	filesSizes               *collections.Map
	filesTmpContent          *collections.Map
	filesTmpNames            *collections.Map
	fullRequestLength        *collections.Single
	geo                      *collections.Map
	highestSeverity          *collections.Single
	inboundDataError         *collections.Single
	matchedVar               *collections.Single
	matchedVarName           *collections.Single
	matchedVars              *collections.NamedCollection
	matchedVarsNames         collection.Keyed
	multipartDataAfter       *collections.Single
	multipartFilename        *collections.Map
	multipartName            *collections.Map
	multipartPartHeaders     *collections.Map
	multipartStrictError     *collections.Single
	outboundDataError        *collections.Single
	queryString              *collections.Single
	remoteAddr               *collections.Single
	remoteHost               *collections.Single
	remotePort               *collections.Single
	reqbodyError             *collections.Single
	reqbodyErrorMsg          *collections.Single
	reqbodyProcessor         *collections.Single
	reqbodyProcessorError    *collections.Single
	reqbodyProcessorErrorMsg *collections.Single
	requestBasename          *collections.Single
	requestBody              *collections.Single
	requestBodyLength        *collections.Single
	requestCookies           *collections.NamedCollection
	requestCookiesNames      collection.Keyed
	requestFilename          *collections.Single
	requestHeaders           *collections.NamedCollection
	requestHeadersNames      collection.Keyed
	requestLine              *collections.Single
	requestMethod            *collections.Single
	requestProtocol          *collections.Single
	requestURI               *collections.Single
	requestURIRaw            *collections.Single
	requestXML               *collections.Map
	responseBody             *collections.Single
	responseContentLength    *collections.Single
	responseContentType      *collections.Single
	responseHeaders          *collections.NamedCollection
	responseHeadersNames     collection.Keyed
	responseProtocol         *collections.Single
	responseStatus           *collections.Single
	responseXML              *collections.Map
	responseArgs             *collections.Map
	resBodyProcessor         *collections.Single
	rule                     *collections.Map
	serverAddr               *collections.Single
	serverName               *collections.Single
	serverPort               *collections.Single
	statusLine               *collections.Single
	tx                       *collections.Map
	uniqueID                 *collections.Single
	urlencodedError          *collections.Single
	xml                      *collections.Map
	resBodyError             *collections.Single
	resBodyErrorMsg          *collections.Single
	resBodyProcessorError    *collections.Single
	resBodyProcessorErrorMsg *collections.Single
	time                     *collections.Single
	timeDay                  *collections.Single
	timeEpoch                *collections.Single
	timeHour                 *collections.Single
	timeMin                  *collections.Single
	timeMon                  *collections.Single
	timeSec                  *collections.Single
	timeWday                 *collections.Single
	timeYear                 *collections.Single
}

func NewTransactionVariables() *TransactionVariables {
	v := &TransactionVariables{}
	v.urlencodedError = collections.NewSingle(variables.UrlencodedError)
	v.responseContentType = collections.NewSingle(variables.ResponseContentType)
	v.uniqueID = collections.NewSingle(variables.UniqueID)
	v.filesCombinedSize = collections.NewSingle(variables.FilesCombinedSize)
	v.fullRequestLength = collections.NewSingle(variables.FullRequestLength)
	v.inboundDataError = collections.NewSingle(variables.InboundDataError)
	v.matchedVar = collections.NewSingle(variables.MatchedVar)
	v.matchedVarName = collections.NewSingle(variables.MatchedVarName)
	v.multipartDataAfter = collections.NewSingle(variables.MultipartDataAfter)
	v.outboundDataError = collections.NewSingle(variables.OutboundDataError)
	v.queryString = collections.NewSingle(variables.QueryString)
	v.remoteAddr = collections.NewSingle(variables.RemoteAddr)
	v.remoteHost = collections.NewSingle(variables.RemoteHost)
	v.remotePort = collections.NewSingle(variables.RemotePort)
	v.reqbodyError = collections.NewSingle(variables.ReqbodyError)
	v.reqbodyErrorMsg = collections.NewSingle(variables.ReqbodyErrorMsg)
	v.reqbodyProcessorError = collections.NewSingle(variables.ReqbodyProcessorError)
	v.reqbodyProcessorErrorMsg = collections.NewSingle(variables.ReqbodyProcessorErrorMsg)
	v.reqbodyProcessor = collections.NewSingle(variables.ReqbodyProcessor)
	v.requestBasename = collections.NewSingle(variables.RequestBasename)
	v.requestBody = collections.NewSingle(variables.RequestBody)
	v.requestBodyLength = collections.NewSingle(variables.RequestBodyLength)
	v.requestFilename = collections.NewSingle(variables.RequestFilename)
	v.requestLine = collections.NewSingle(variables.RequestLine)
	v.requestMethod = collections.NewSingle(variables.RequestMethod)
	v.requestProtocol = collections.NewSingle(variables.RequestProtocol)
	v.requestURI = collections.NewSingle(variables.RequestURI)
	v.requestURIRaw = collections.NewSingle(variables.RequestURIRaw)
	v.responseBody = collections.NewSingle(variables.ResponseBody)
	v.responseContentLength = collections.NewSingle(variables.ResponseContentLength)
	v.responseProtocol = collections.NewSingle(variables.ResponseProtocol)
	v.responseStatus = collections.NewSingle(variables.ResponseStatus)
	v.responseArgs = collections.NewMap(variables.ResponseArgs)
	v.serverAddr = collections.NewSingle(variables.ServerAddr)
	v.serverName = collections.NewSingle(variables.ServerName)
	v.serverPort = collections.NewSingle(variables.ServerPort)
	v.highestSeverity = collections.NewSingle(variables.HighestSeverity)
	v.statusLine = collections.NewSingle(variables.StatusLine)
	v.duration = collections.NewSingle(variables.Duration)
	v.resBodyError = collections.NewSingle(variables.ResBodyError)
	v.resBodyErrorMsg = collections.NewSingle(variables.ResBodyErrorMsg)
	v.resBodyProcessorError = collections.NewSingle(variables.ResBodyProcessorError)
	v.resBodyProcessorErrorMsg = collections.NewSingle(variables.ResBodyProcessorErrorMsg)

	v.filesSizes = collections.NewMap(variables.FilesSizes)
	v.filesTmpContent = collections.NewMap(variables.FilesTmpContent)
	v.multipartFilename = collections.NewMap(variables.MultipartFilename)
	v.multipartName = collections.NewMap(variables.MultipartName)
	v.matchedVars = collections.NewNamedCollection(variables.MatchedVars)
	v.matchedVarsNames = v.matchedVars.Names(variables.MatchedVarsNames)
	v.requestCookies = collections.NewNamedCollection(variables.RequestCookies)
	v.requestCookiesNames = v.requestCookies.Names(variables.RequestCookiesNames)
	v.requestHeaders = collections.NewNamedCollection(variables.RequestHeaders)
	v.requestHeadersNames = v.requestHeaders.Names(variables.RequestHeadersNames)
	v.responseHeaders = collections.NewNamedCollection(variables.ResponseHeaders)
	v.responseHeadersNames = v.responseHeaders.Names(variables.ResponseHeadersNames)
	v.resBodyProcessor = collections.NewSingle(variables.ResBodyProcessor)
	v.geo = collections.NewMap(variables.Geo)
	v.tx = collections.NewMap(variables.TX)
	v.rule = collections.NewMap(variables.Rule)
	v.env = collections.NewMap(variables.Env)
	v.files = collections.NewMap(variables.Files)
	v.filesNames = collections.NewMap(variables.FilesNames)
	v.filesTmpNames = collections.NewMap(variables.FilesTmpNames)
	v.responseXML = collections.NewMap(variables.ResponseXML)
	v.requestXML = collections.NewMap(variables.RequestXML)
	v.multipartPartHeaders = collections.NewMap(variables.MultipartPartHeaders)
	v.multipartStrictError = collections.NewSingle(variables.MultipartStrictError)
	v.time = collections.NewSingle(variables.Time)
	v.timeDay = collections.NewSingle(variables.TimeDay)
	v.timeEpoch = collections.NewSingle(variables.TimeEpoch)
	v.timeHour = collections.NewSingle(variables.TimeHour)
	v.timeMin = collections.NewSingle(variables.TimeMin)
	v.timeMon = collections.NewSingle(variables.TimeMon)
	v.timeSec = collections.NewSingle(variables.TimeSec)
	v.timeWday = collections.NewSingle(variables.TimeWday)
	v.timeYear = collections.NewSingle(variables.TimeYear)

	// XML is a pointer to RequestXML
	v.xml = v.requestXML

	if shouldUseCaseSensitiveNamedCollection {
		v.argsGet = collections.NewCaseSensitiveNamedCollection(variables.ArgsGet)
		v.argsPost = collections.NewCaseSensitiveNamedCollection(variables.ArgsPost)
		v.argsPath = collections.NewCaseSensitiveNamedCollection(variables.ArgsPath)
	} else {
		v.argsGet = collections.NewNamedCollection(variables.ArgsGet)
		v.argsPost = collections.NewNamedCollection(variables.ArgsPost)
		v.argsPath = collections.NewNamedCollection(variables.ArgsPath)
	}

	v.argsGetNames = v.argsGet.Names(variables.ArgsGetNames)
	v.argsPostNames = v.argsPost.Names(variables.ArgsPostNames)
	v.argsCombinedSize = collections.NewSizeCollection(variables.ArgsCombinedSize, v.argsGet, v.argsPost)
	v.args = collections.NewConcatKeyed(
		variables.Args,
		v.argsGet,
		v.argsPost,
		v.argsPath,
	)
	v.argsNames = collections.NewConcatKeyed(
		variables.ArgsNames,
		v.argsGetNames,
		v.argsPostNames,
		// Only used in a concatenating collection so variable name doesn't matter.
		v.argsPath.Names(variables.Unknown),
	)
	return v
}

func (v *TransactionVariables) UrlencodedError() collection.Single {
	return v.urlencodedError
}

func (v *TransactionVariables) ResponseContentType() collection.Single {
	return v.responseContentType
}

func (v *TransactionVariables) UniqueID() collection.Single {
	return v.uniqueID
}

func (v *TransactionVariables) ArgsCombinedSize() collection.Collection {
	return v.argsCombinedSize
}

func (v *TransactionVariables) FilesCombinedSize() collection.Single {
	return v.filesCombinedSize
}

func (v *TransactionVariables) FullRequestLength() collection.Single {
	return v.fullRequestLength
}

func (v *TransactionVariables) InboundDataError() collection.Single {
	return v.inboundDataError
}

func (v *TransactionVariables) MatchedVar() collection.Single {
	return v.matchedVar
}

func (v *TransactionVariables) MatchedVarName() collection.Single {
	return v.matchedVarName
}

func (v *TransactionVariables) MultipartDataAfter() collection.Single {
	return v.multipartDataAfter
}

func (v *TransactionVariables) MultipartPartHeaders() collection.Map {
	return v.multipartPartHeaders
}

func (v *TransactionVariables) OutboundDataError() collection.Single {
	return v.outboundDataError
}

func (v *TransactionVariables) QueryString() collection.Single {
	return v.queryString
}

func (v *TransactionVariables) RemoteAddr() collection.Single {
	return v.remoteAddr
}

func (v *TransactionVariables) RemoteHost() collection.Single {
	return v.remoteHost
}

func (v *TransactionVariables) RemotePort() collection.Single {
	return v.remotePort
}

func (v *TransactionVariables) RequestBodyError() collection.Single {
	return v.reqbodyError
}

func (v *TransactionVariables) RequestBodyErrorMsg() collection.Single {
	return v.reqbodyErrorMsg
}

func (v *TransactionVariables) RequestBodyProcessorError() collection.Single {
	return v.reqbodyProcessorError
}

func (v *TransactionVariables) RequestBodyProcessorErrorMsg() collection.Single {
	return v.reqbodyProcessorErrorMsg
}

func (v *TransactionVariables) RequestBodyProcessor() collection.Single {
	return v.reqbodyProcessor
}

func (v *TransactionVariables) RequestBasename() collection.Single {
	return v.requestBasename
}

func (v *TransactionVariables) RequestBody() collection.Single {
	return v.requestBody
}

func (v *TransactionVariables) RequestBodyLength() collection.Single {
	return v.requestBodyLength
}

func (v *TransactionVariables) RequestFilename() collection.Single {
	return v.requestFilename
}

func (v *TransactionVariables) RequestLine() collection.Single {
	return v.requestLine
}

func (v *TransactionVariables) RequestMethod() collection.Single {
	return v.requestMethod
}

func (v *TransactionVariables) RequestProtocol() collection.Single {
	return v.requestProtocol
}

func (v *TransactionVariables) RequestURI() collection.Single {
	return v.requestURI
}

func (v *TransactionVariables) RequestURIRaw() collection.Single {
	return v.requestURIRaw
}

func (v *TransactionVariables) ResponseBody() collection.Single {
	return v.responseBody
}

func (v *TransactionVariables) ResponseContentLength() collection.Single {
	return v.responseContentLength
}

func (v *TransactionVariables) ResponseProtocol() collection.Single {
	return v.responseProtocol
}

func (v *TransactionVariables) ResponseStatus() collection.Single {
	return v.responseStatus
}

func (v *TransactionVariables) ServerAddr() collection.Single {
	return v.serverAddr
}

func (v *TransactionVariables) ServerName() collection.Single {
	return v.serverName
}

func (v *TransactionVariables) ServerPort() collection.Single {
	return v.serverPort
}

func (v *TransactionVariables) HighestSeverity() collection.Single {
	return v.highestSeverity
}

func (v *TransactionVariables) StatusLine() collection.Single {
	return v.statusLine
}

func (v *TransactionVariables) Env() collection.Map {
	return v.env
}

func (v *TransactionVariables) TX() collection.Map {
	return v.tx
}

func (v *TransactionVariables) Rule() collection.Map {
	return v.rule
}

func (v *TransactionVariables) Duration() collection.Single {
	return v.duration
}

func (v *TransactionVariables) Args() collection.Keyed {
	return v.args
}

func (v *TransactionVariables) ArgsGet() collection.Map {
	return v.argsGet
}

func (v *TransactionVariables) ArgsPost() collection.Map {
	return v.argsPost
}

func (v *TransactionVariables) ArgsPath() collection.Map {
	return v.argsPath
}

func (v *TransactionVariables) FilesTmpNames() collection.Map {
	return v.filesTmpNames
}

func (v *TransactionVariables) Geo() collection.Map {
	return v.geo
}

func (v *TransactionVariables) Files() collection.Map {
	return v.files
}

func (v *TransactionVariables) RequestCookies() collection.Map {
	return v.requestCookies
}

func (v *TransactionVariables) RequestHeaders() collection.Map {
	return v.requestHeaders
}

func (v *TransactionVariables) ResponseHeaders() collection.Map {
	return v.responseHeaders
}

func (v *TransactionVariables) MultipartName() collection.Map {
	return v.multipartName
}

func (v *TransactionVariables) MatchedVarsNames() collection.Keyed {
	return v.matchedVarsNames
}

func (v *TransactionVariables) MultipartFilename() collection.Map {
	return v.multipartFilename
}

func (v *TransactionVariables) MatchedVars() collection.Map {
	return v.matchedVars
}

func (v *TransactionVariables) FilesSizes() collection.Map {
	return v.filesSizes
}

func (v *TransactionVariables) FilesNames() collection.Map {
	return v.filesNames
}

func (v *TransactionVariables) FilesTmpContent() collection.Map {
	return v.filesTmpContent
}

func (v *TransactionVariables) ResponseHeadersNames() collection.Keyed {
	return v.responseHeadersNames
}

func (v *TransactionVariables) ResponseArgs() collection.Map {
	return v.responseArgs
}

func (v *TransactionVariables) RequestHeadersNames() collection.Keyed {
	return v.requestHeadersNames
}

func (v *TransactionVariables) RequestCookiesNames() collection.Keyed {
	return v.requestCookiesNames
}

func (v *TransactionVariables) XML() collection.Map {
	return v.xml
}

func (v *TransactionVariables) RequestXML() collection.Map {
	return v.requestXML
}

func (v *TransactionVariables) ResponseXML() collection.Map {
	return v.responseXML
}

func (v *TransactionVariables) ResponseBodyProcessor() collection.Single {
	return v.resBodyProcessor
}

func (v *TransactionVariables) ArgsNames() collection.Keyed {
	return v.argsNames
}

func (v *TransactionVariables) ArgsGetNames() collection.Keyed {
	return v.argsGetNames
}

func (v *TransactionVariables) ArgsPostNames() collection.Keyed {
	return v.argsPostNames
}

func (v *TransactionVariables) ResBodyError() collection.Single {
	return v.resBodyError
}

func (v *TransactionVariables) ResBodyErrorMsg() collection.Single {
	return v.resBodyErrorMsg
}

func (v *TransactionVariables) ResBodyProcessorError() collection.Single {
	return v.resBodyProcessorError
}

func (v *TransactionVariables) ResBodyProcessorErrorMsg() collection.Single {
	return v.resBodyProcessorErrorMsg
}

func (v *TransactionVariables) MultipartStrictError() collection.Single {
	return v.multipartStrictError
}

// All iterates over the variables. We return both variable and its collection, i.e. key/value, to follow
// general range iteration in Go which always has a key and value (key is int index for slices). Notably,
// this is consistent with discussions for custom iterable types in a future language version
// https://github.com/golang/go/discussions/56413
func (v *TransactionVariables) All(f func(v variables.RuleVariable, col collection.Collection) bool) {
	if !f(variables.Args, v.args) {
		return
	}
	if !f(variables.ArgsCombinedSize, v.argsCombinedSize) {
		return
	}
	if !f(variables.ArgsGet, v.argsGet) {
		return
	}
	if !f(variables.ArgsGetNames, v.argsGetNames) {
		return
	}
	if !f(variables.ArgsNames, v.argsNames) {
		return
	}
	if !f(variables.ArgsPath, v.argsPath) {
		return
	}
	if !f(variables.ArgsPost, v.argsPost) {
		return
	}
	if !f(variables.ArgsPostNames, v.argsPostNames) {
		return
	}
	if !f(variables.Duration, v.duration) {
		return
	}
	if !f(variables.Env, v.env) {
		return
	}
	if !f(variables.Files, v.files) {
		return
	}
	if !f(variables.FilesCombinedSize, v.filesCombinedSize) {
		return
	}
	if !f(variables.FilesNames, v.filesNames) {
		return
	}
	if !f(variables.FilesSizes, v.filesSizes) {
		return
	}
	if !f(variables.FilesTmpContent, v.filesTmpContent) {
		return
	}
	if !f(variables.FilesTmpNames, v.filesTmpNames) {
		return
	}
	if !f(variables.FullRequestLength, v.fullRequestLength) {
		return
	}
	if !f(variables.Geo, v.geo) {
		return
	}
	if !f(variables.HighestSeverity, v.highestSeverity) {
		return
	}
	if !f(variables.InboundDataError, v.inboundDataError) {
		return
	}
	if !f(variables.MatchedVar, v.matchedVar) {
		return
	}
	if !f(variables.MatchedVarName, v.matchedVarName) {
		return
	}
	if !f(variables.MatchedVars, v.matchedVars) {
		return
	}
	if !f(variables.MatchedVarsNames, v.matchedVarsNames) {
		return
	}
	if !f(variables.MultipartDataAfter, v.multipartDataAfter) {
		return
	}
	if !f(variables.MultipartFilename, v.multipartFilename) {
		return
	}
	if !f(variables.MultipartName, v.multipartName) {
		return
	}
	if !f(variables.MultipartPartHeaders, v.multipartPartHeaders) {
		return
	}
	if !f(variables.MultipartStrictError, v.multipartStrictError) {
		return
	}
	if !f(variables.OutboundDataError, v.outboundDataError) {
		return
	}
	if !f(variables.QueryString, v.queryString) {
		return
	}
	if !f(variables.RemoteAddr, v.remoteAddr) {
		return
	}
	if !f(variables.RemoteHost, v.remoteHost) {
		return
	}
	if !f(variables.RemotePort, v.remotePort) {
		return
	}
	if !f(variables.ReqbodyError, v.reqbodyError) {
		return
	}
	if !f(variables.ReqbodyErrorMsg, v.reqbodyErrorMsg) {
		return
	}
	if !f(variables.ReqbodyProcessor, v.reqbodyProcessor) {
		return
	}
	if !f(variables.ReqbodyProcessorError, v.reqbodyProcessorError) {
		return
	}
	if !f(variables.ReqbodyProcessorErrorMsg, v.reqbodyProcessorErrorMsg) {
		return
	}
	if !f(variables.RequestBasename, v.requestBasename) {
		return
	}
	if !f(variables.RequestBody, v.requestBody) {
		return
	}
	if !f(variables.RequestBodyLength, v.requestBodyLength) {
		return
	}
	if !f(variables.RequestCookies, v.requestCookies) {
		return
	}
	if !f(variables.RequestCookiesNames, v.requestCookiesNames) {
		return
	}
	if !f(variables.RequestFilename, v.requestFilename) {
		return
	}
	if !f(variables.RequestHeaders, v.requestHeaders) {
		return
	}
	if !f(variables.RequestHeadersNames, v.requestHeadersNames) {
		return
	}
	if !f(variables.RequestLine, v.requestLine) {
		return
	}
	if !f(variables.RequestMethod, v.requestMethod) {
		return
	}
	if !f(variables.RequestProtocol, v.requestProtocol) {
		return
	}
	if !f(variables.RequestURI, v.requestURI) {
		return
	}
	if !f(variables.RequestURIRaw, v.requestURIRaw) {
		return
	}
	if !f(variables.RequestXML, v.requestXML) {
		return
	}
	if !f(variables.ResponseBody, v.responseBody) {
		return
	}
	if !f(variables.ResponseContentLength, v.responseContentLength) {
		return
	}
	if !f(variables.ResponseContentType, v.responseContentType) {
		return
	}
	if !f(variables.ResponseHeaders, v.responseHeaders) {
		return
	}
	if !f(variables.ResponseHeadersNames, v.responseHeadersNames) {
		return
	}
	if !f(variables.ResponseProtocol, v.responseProtocol) {
		return
	}
	if !f(variables.ResponseStatus, v.responseStatus) {
		return
	}
	if !f(variables.ResponseXML, v.responseXML) {
		return
	}
	if !f(variables.ResponseArgs, v.responseArgs) {
		return
	}
	if !f(variables.ResBodyProcessor, v.resBodyProcessor) {
		return
	}
	if !f(variables.Rule, v.rule) {
		return
	}
	if !f(variables.ServerAddr, v.serverAddr) {
		return
	}
	if !f(variables.ServerName, v.serverName) {
		return
	}
	if !f(variables.ServerPort, v.serverPort) {
		return
	}
	if !f(variables.StatusLine, v.statusLine) {
		return
	}
	if !f(variables.TX, v.tx) {
		return
	}
	if !f(variables.UniqueID, v.uniqueID) {
		return
	}
	if !f(variables.UrlencodedError, v.urlencodedError) {
		return
	}
	if !f(variables.XML, v.xml) {
		return
	}
	if !f(variables.Time, v.time) {
		return
	}
	if !f(variables.TimeDay, v.timeDay) {
		return
	}
	if !f(variables.TimeEpoch, v.timeEpoch) {
		return
	}
	if !f(variables.TimeHour, v.timeHour) {
		return
	}
	if !f(variables.TimeMin, v.timeMin) {
		return
	}
	if !f(variables.TimeMon, v.timeMon) {
		return
	}
	if !f(variables.TimeSec, v.timeSec) {
		return
	}
	if !f(variables.TimeWday, v.timeWday) {
		return
	}
	if !f(variables.TimeYear, v.timeYear) {
		return
	}
}

type formattable interface {
	Format(res *strings.Builder)
}

func (v *TransactionVariables) format(res *strings.Builder) {
	v.All(func(_ variables.RuleVariable, col collection.Collection) bool {
		if f, ok := col.(formattable); ok {
			f.Format(res)
		} else {
			fmt.Fprintln(res, col)
		}
		return true
	})
}

type resettable interface {
	Reset()
}

func (v *TransactionVariables) reset() {
	v.All(func(_ variables.RuleVariable, col collection.Collection) bool {
		if r, ok := col.(resettable); ok {
			r.Reset()
		}
		return true
	})
}
