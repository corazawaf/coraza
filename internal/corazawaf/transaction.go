// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/bodyprocessors"
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	corazatypes "github.com/corazawaf/coraza/v3/internal/corazatypes"
	stringsutil "github.com/corazawaf/coraza/v3/internal/strings"
	urlutil "github.com/corazawaf/coraza/v3/internal/url"
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/rules"
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

	// Contains the list of matched rules and associated match information
	matchedRules []types.MatchedRule

	// True if the transaction has been disrupted by any rule
	interruption *types.Interruption

	// This is used to store log messages
	Logdata string

	// Rules will be skipped after a rule with this SecMarker is found
	SkipAfter string

	// AllowType is used by the allow disruptive action to skip evaluating rules after being allowed
	AllowType corazatypes.AllowType

	// Copies from the WAF instance that may be overwritten by the ctl action
	AuditEngine              types.AuditEngineStatus
	AuditLogParts            types.AuditLogParts
	ForceRequestBodyVariable bool
	RequestBodyAccess        bool
	RequestBodyLimit         int64
	ResponseBodyAccess       bool
	ResponseBodyLimit        int64
	RuleEngine               types.RuleEngineStatus
	HashEngine               bool
	HashEnforcement          bool

	// Stores the last phase that was evaluated
	// Used by allow to skip phases
	LastPhase types.RulePhase

	// Handles request body buffers
	requestBodyBuffer *BodyBuffer

	// Handles response body buffers
	responseBodyBuffer *BodyBuffer

	// Body processor used to parse JSON, XML, etc
	bodyProcessor bodyprocessors.BodyProcessor

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

func (tx *Transaction) Variables() rules.TransactionVariables {
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
	case variables.AuthType:
		return collections.Noop
	case variables.FilesCombinedSize:
		return tx.variables.filesCombinedSize
	case variables.FullRequest:
		return collections.Noop
	case variables.FullRequestLength:
		return tx.variables.fullRequestLength
	case variables.InboundDataError:
		return tx.variables.inboundDataError
	case variables.MatchedVar:
		return tx.variables.matchedVar
	case variables.MatchedVarName:
		return tx.variables.matchedVarName
	case variables.MultipartBoundaryQuoted:
		return collections.Noop
	case variables.MultipartBoundaryWhitespace:
		return collections.Noop
	case variables.MultipartCrlfLfLines:
		return collections.Noop
	case variables.MultipartDataAfter:
		return tx.variables.multipartDataAfter
	case variables.MultipartDataBefore:
		return collections.Noop
	case variables.MultipartFileLimitExceeded:
		return collections.Noop
	case variables.MultipartHeaderFolding:
		return collections.Noop
	case variables.MultipartInvalidHeaderFolding:
		return collections.Noop
	case variables.MultipartInvalidPart:
		return collections.Noop
	case variables.MultipartInvalidQuoting:
		return collections.Noop
	case variables.MultipartLfLine:
		return collections.Noop
	case variables.MultipartMissingSemicolon:
		return collections.Noop
	case variables.MultipartStrictError:
		return collections.Noop
	case variables.MultipartUnmatchedBoundary:
		return collections.Noop
	case variables.OutboundDataError:
		return tx.variables.outboundDataError
	case variables.PathInfo:
		return collections.Noop
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
	case variables.Sessionid:
		return collections.Noop
	case variables.HighestSeverity:
		return tx.variables.highestSeverity
	case variables.StatusLine:
		return tx.variables.statusLine
	case variables.InboundErrorData:
		return tx.variables.inboundErrorData
	case variables.Duration:
		return tx.variables.duration
	case variables.ResponseHeadersNames:
		return tx.variables.responseHeadersNames
	case variables.RequestHeadersNames:
		return tx.variables.requestHeadersNames
	case variables.Userid:
		return collections.Noop
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
	case variables.TX:
		return tx.variables.tx
	case variables.Rule:
		return tx.variables.rule
	case variables.JSON:
		// TODO(anuraaga): This collection seems to be missing.
		return nil
	case variables.Env:
		return tx.variables.env
	case variables.IP:
		return collections.Noop
	case variables.UrlencodedError:
		return tx.variables.urlencodedError
	case variables.ResponseArgs:
		// TODO(anuraaga): This collection seems to be missing.
		return nil
	case variables.ResponseXML:
		return tx.variables.responseXML
	case variables.RequestXML:
		return tx.variables.requestXML
	case variables.XML:
		return tx.variables.xml
	case variables.MultipartPartHeaders:
		return tx.variables.multipartPartHeaders
	}

	return nil
}

func (tx *Transaction) Interrupt(interruption *types.Interruption) {
	if tx.RuleEngine == types.RuleEngineOn {
		tx.interruption = interruption
	}
}

func (tx *Transaction) DebugLogger() loggers.DebugLogger {
	return tx.WAF.Logger
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
		// Cookies use the same syntax as GET params but with semicolon (;) separator
		values := urlutil.ParseQuery(value, ';')
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
		tx.WAF.Logger.Debug("[%s] Capturing field %d with value %q", tx.id, index, value)
		i := strconv.Itoa(index)
		tx.variables.tx.SetIndex(i, 0, value)
	}
}

// this function is used to control which variables are reset after a new rule is evaluated
func (tx *Transaction) resetCaptures() {
	tx.WAF.Logger.Debug("[%s] Reseting captured variables", tx.id)
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

// matchVariable Creates the MATCHED_ variables required by chains and macro expansion
// MATCHED_VARS, MATCHED_VAR, MATCHED_VAR_NAME, MATCHED_VARS_NAMES
func (tx *Transaction) matchVariable(match *corazarules.MatchData) {
	var varName string
	if match.Key_ != "" {
		varName = match.VariableName_ + ":" + match.Key_
	} else {
		varName = match.VariableName_
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
	tx.WAF.Logger.Debug("[%s] rule %d matched", tx.id, r.ID_)
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
		MatchedDatas_:    mds,
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
// In future releases we may remove de exceptions slice and
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
			panic("attempted to use regex with non-selectable collection: " + rv.Variable.Name())
		}
	case rv.KeyStr != "":
		if m, ok := col.(collection.Keyed); ok {
			matches = m.FindString(rv.KeyStr)
		} else {
			panic("attempted to use string with non-selectable collection: " + rv.Variable.Name())
		}
	default:
		matches = col.FindAll()
	}

	var rmi []int
	for i, c := range matches {
		for _, ex := range rv.Exceptions {
			lkey := strings.ToLower(c.Key())
			// in case it matches the regex or the keyStr
			// Since keys are case sensitive we need to check with lower case
			if (ex.KeyRx != nil && ex.KeyRx.MatchString(lkey)) || strings.ToLower(ex.KeyStr) == lkey {
				// we remove the exception from the list of values
				// we tried with standard append, but it fails... let's do some hacking
				// m2 := append(matches[:i], matches[i+1:]...)
				rmi = append(rmi, i)
			}
		}
	}
	// we read the list of indexes backwards
	// then we remove each one of them because of the exceptions
	for i := len(rmi) - 1; i >= 0; i-- {
		if len(matches) < rmi[i]+1 {
			matches = matches[:rmi[i]-1]
		} else {
			matches = append(matches[:rmi[i]], matches[rmi[i]+1:]...)
		}
	}
	if rv.Count {
		count := len(matches)
		matches = []types.MatchData{
			&corazarules.MatchData{
				VariableName_: rv.Variable.Name(),
				Variable_:     rv.Variable,
				Key_:          rv.KeyStr,
				Value_:        strconv.Itoa(count),
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

// ExtractArguments transforms an url encoded string to a map and creates
// ARGS_POST|GET
func (tx *Transaction) ExtractArguments(orig types.ArgumentType, uri string) {
	data := urlutil.ParseQuery(uri, '&')
	for k, vs := range data {
		for _, v := range vs {
			tx.AddArgument(orig, k, v)
		}
	}
}

// AddArgument Add arguments GET or POST
// This will set ARGS_(GET|POST), ARGS, ARGS_NAMES, ARGS_COMBINED_SIZE and
// ARGS_(GET|POST)_NAMES
func (tx *Transaction) AddArgument(argType types.ArgumentType, key string, value string) {
	// TODO implement ARGS value limit using ArgumentsLimit
	var vals collection.Map
	switch argType {
	case types.ArgumentGET:
		vals = tx.variables.argsGet
	case types.ArgumentPOST:
		vals = tx.variables.argsPost
	case types.ArgumentPATH:
		vals = tx.variables.argsPath
	default:
		return
	}

	vals.Add(key, value)
}

// ProcessURI Performs the analysis on the URI and all the query string variables.
// This method should be called at very beginning of a request process, it is
// expected to be executed prior to the virtual host resolution, when the
// connection arrives on the server.
// note: There is no direct connection between this function and any phase of
//
//	the SecLanguages phases. It is something that may occur between the
//	SecLanguage phase 1 and 2.
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
	parsedURL, err := url.Parse(uri)
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
		tx.ExtractArguments(types.ArgumentGET, parsedURL.RawQuery)
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
	if tx.LastPhase >= types.PhaseRequestHeaders {
		tx.WAF.Logger.Warn("SetServerName has been called after ProcessRequestHeaders")
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
	if tx.LastPhase >= types.PhaseRequestHeaders {
		// Phase already evaluated
		tx.WAF.Logger.Error("ProcessRequestHeaders has already been called")
		return tx.interruption
	}

	if tx.interruption != nil {
		tx.WAF.Logger.Error("Calling ProcessRequestHeaders but there is a preexisting interruption")
		return tx.interruption
	}

	tx.WAF.Rules.Eval(types.PhaseRequestHeaders, tx)
	return tx.interruption
}

func setAndReturnBodyLimitInterruption(tx *Transaction) (*types.Interruption, int, error) {
	tx.DebugLogger().Warn("Disrupting transaction with body size above the configured limit (Action Reject)")
	tx.interruption = &types.Interruption{
		Status: 413,
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
		return nil, 0, errors.New("Overflow reached while writing request body")
	}

	if tx.requestBodyBuffer.length+writingBytes >= tx.RequestBodyLimit {
		tx.variables.inboundErrorData.Set("1")
		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionReject {
			// We interrupt this transaction in case RequestBodyLimitAction is Reject
			return setAndReturnBodyLimitInterruption(tx)
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
		tx.DebugLogger().Warn("Processing request body whose size reached the configured limit (Action ProcessPartial)")
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
			return nil, 0, errors.New("Overflow reached while writing request body")
		}
		if tx.requestBodyBuffer.length+writingBytes >= tx.RequestBodyLimit {
			tx.variables.inboundErrorData.Set("1")
			if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionReject {
				return setAndReturnBodyLimitInterruption(tx)
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
		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionReject {
			return setAndReturnBodyLimitInterruption(tx)
		}

		if tx.WAF.RequestBodyLimitAction == types.BodyLimitActionProcessPartial {
			runProcessRequestBody = true
		}
	}

	err = nil
	if runProcessRequestBody {
		tx.DebugLogger().Warn("Processing request body whose size reached the configured limit (Action ProcessPartial)")
		_, err = tx.ProcessRequestBody()
	}
	return tx.interruption, int(w), err
}

// ProcessRequestBody Performs the analysis of the request body (if any)
//
// This method perform the analysis on the request body. It is optional to
// call that function. If this API consumer already knows that there isn't a
// body for inspect it is recommended to skip this step.
//
// Remember to check for a possible intervention.
func (tx *Transaction) ProcessRequestBody() (*types.Interruption, error) {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil, nil
	}

	if tx.LastPhase >= types.PhaseRequestBody {
		// Phase already evaluated
		tx.WAF.Logger.Warn("ProcessRequestBody has already been called")
		return tx.interruption, nil
	}

	if tx.interruption != nil {
		tx.WAF.Logger.Error("Calling ProcessRequestBody but there is a preexisting interruption")
		return tx.interruption, nil
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
		rbp = "URLENCODED"
		tx.variables.reqbodyProcessor.Set(rbp)
	}
	tx.WAF.Logger.Debug("[%s] Attempting to process request body using %q", tx.id, rbp)
	rbp = strings.ToLower(rbp)
	if rbp == "" {
		// so there is no bodyprocessor, we don't want to generate an error
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.interruption, nil
	}
	bodyprocessor, err := bodyprocessors.Get(rbp)
	if err != nil {
		tx.generateReqbodyError(errors.New("invalid body processor"))
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.interruption, nil
	}
	if err := bodyprocessor.ProcessRequest(reader, tx.Variables(), bodyprocessors.Options{
		Mime:        mime,
		StoragePath: tx.WAF.UploadDir,
	}); err != nil {
		tx.generateReqbodyError(err)
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.interruption, nil
	}

	tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
	return tx.interruption, nil
}

// ProcessResponseHeaders Perform the analysis on the response readers.
//
// This method perform the analysis on the response headers, notice however
// that the headers should be added prior to the execution of this function.
//
// note: Remember to check for a possible intervention.
func (tx *Transaction) ProcessResponseHeaders(code int, proto string) *types.Interruption {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil
	}

	if tx.LastPhase >= types.PhaseResponseHeaders {
		// Phase already evaluated
		tx.WAF.Logger.Error("ProcessResponseHeaders has already been called")
		return tx.interruption
	}

	if tx.interruption != nil {
		tx.WAF.Logger.Error("Calling ProcessResponseHeaders but there is a preexisting interruption")
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
		// TODO: figure out ErrorData vs DataError: https://github.com/corazawaf/coraza/issues/564
		tx.variables.outboundDataError.Set("1")
		if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionReject {
			// We interrupt this transaction in case ResponseBodyLimitAction is Reject
			return setAndReturnBodyLimitInterruption(tx)
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
			// TODO: figure out ErrorData vs DataError: https://github.com/corazawaf/coraza/issues/564
			tx.variables.outboundDataError.Set("1")
			if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionReject {
				return setAndReturnBodyLimitInterruption(tx)
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
		if tx.WAF.ResponseBodyLimitAction == types.BodyLimitActionReject {
			return setAndReturnBodyLimitInterruption(tx)
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
// This method perform the analysis on the response body. It is optional to
// call that method. If this API consumer already knows that there isn't a
// body for inspect it is recommended to skip this step.
//
// note Remember to check for a possible intervention.
func (tx *Transaction) ProcessResponseBody() (*types.Interruption, error) {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil, nil
	}

	if tx.LastPhase >= types.PhaseResponseBody {
		// Phase already evaluated
		tx.WAF.Logger.Warn("ProcessResponseBody has already been called")
		return tx.interruption, nil
	}

	if tx.interruption != nil {
		tx.WAF.Logger.Error("Calling ProcessResponseBody but there is a preexisting interruption")
		return tx.interruption, nil
	}

	if !tx.ResponseBodyAccess || !tx.IsResponseBodyProcessable() {
		tx.WAF.Logger.Debug("[%s] Skipping response body processing (Access: %t)", tx.id, tx.ResponseBodyAccess)
		tx.WAF.Rules.Eval(types.PhaseResponseBody, tx)
		return tx.interruption, nil
	}
	tx.WAF.Logger.Debug("[%s] Attempting to process response body", tx.id)
	reader, err := tx.responseBodyBuffer.Reader()
	if err != nil {
		return tx.interruption, err
	}

	buf := new(strings.Builder)
	length, err := io.Copy(buf, reader)
	if err != nil {
		return tx.interruption, err
	}

	tx.variables.responseContentLength.Set(strconv.FormatInt(length, 10))
	tx.variables.responseBody.Set(buf.String())
	tx.WAF.Rules.Eval(types.PhaseResponseBody, tx)
	return tx.interruption, nil
}

// ProcessLogging Logging all information relative to this transaction.
// An error log
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
		tx.WAF.Logger.Debug("[%s] Transaction not marked for audit logging, AuditEngine is disabled", tx.id)
		return
	}

	if tx.AuditEngine == types.AuditEngineRelevantOnly && !tx.audit {
		// Transaction marked not for audit logging
		tx.WAF.Logger.Debug("[%s] Transaction not marked for audit logging, AuditEngine is RelevantOnly and we got noauditlog", tx.id)
		return
	}

	if tx.AuditEngine == types.AuditEngineRelevantOnly && tx.audit {
		re := tx.WAF.AuditLogRelevantStatus
		status := tx.variables.responseStatus.Get()
		if re != nil && !re.Match([]byte(status)) {
			// Not relevant status
			tx.WAF.Logger.Debug("[%s] Transaction status not marked for audit logging", tx.id)
			return
		}
	}

	tx.WAF.Logger.Debug("[%s] Transaction marked for audit logging", tx.id)
	if writer := tx.WAF.AuditLogWriter; writer != nil {
		// We don't log if there is an empty audit logger
		if err := writer.Write(tx.AuditLog()); err != nil {
			tx.WAF.Logger.Error(err.Error())
		}
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

// AuditLog returns an AuditLog struct, used to write audit logs
func (tx *Transaction) AuditLog() *loggers.AuditLog {
	al := &loggers.AuditLog{}
	al.Messages = nil
	// YYYY/MM/DD HH:mm:ss
	ts := time.Unix(0, tx.Timestamp).Format("2006/01/02 15:04:05")
	al.Parts = tx.AuditLogParts
	clientPort, _ := strconv.Atoi(tx.variables.remotePort.Get())
	hostPort, _ := strconv.Atoi(tx.variables.serverPort.Get())
	status, _ := strconv.Atoi(tx.variables.responseStatus.Get())
	al.Transaction = loggers.AuditTransaction{
		Timestamp:     ts,
		UnixTimestamp: tx.Timestamp,
		ID:            tx.id,
		ClientIP:      tx.variables.remoteAddr.Get(),
		ClientPort:    clientPort,
		HostIP:        tx.variables.serverAddr.Get(),
		HostPort:      hostPort,
		ServerID:      tx.variables.serverName.Get(), // TODO check
		Request: loggers.AuditTransactionRequest{
			Method:      tx.variables.requestMethod.Get(),
			Protocol:    tx.variables.requestProtocol.Get(),
			URI:         tx.variables.requestURI.Get(),
			HTTPVersion: tx.variables.requestProtocol.Get(),
			// Body and headers are audit variables.RequestUriRaws
		},
		Response: loggers.AuditTransactionResponse{
			Status: status,
			// body and headers are audit parts
		},
	}
	rengine := tx.RuleEngine.String()

	al.Transaction.Request.Headers = tx.variables.requestHeaders.Data()
	al.Transaction.Request.Body = tx.variables.requestBody.Get()
	// TODO maybe change to:
	// al.Transaction.Request.Body = tx.RequestBodyBuffer.String()
	al.Transaction.Response.Headers = tx.variables.responseHeaders.Data()
	al.Transaction.Response.Body = tx.variables.responseBody.Get()
	al.Transaction.Producer = loggers.AuditTransactionProducer{
		Connector:  tx.WAF.ProducerConnector,
		Version:    tx.WAF.ProducerConnectorVersion,
		Server:     "",
		RuleEngine: rengine,
		Stopwatch:  tx.GetStopWatch(),
		Rulesets:   tx.WAF.ComponentNames,
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
	var files []loggers.AuditTransactionRequestFiles
	al.Transaction.Request.Files = nil
	for _, file := range tx.variables.files.Get("") {
		var size int64
		if fs := tx.variables.filesSizes.Get(file); len(fs) > 0 {
			size, _ = strconv.ParseInt(fs[0], 10, 64)
			// we ignore the error as it defaults to 0
		}
		ext := filepath.Ext(file)
		at := loggers.AuditTransactionRequestFiles{
			Size: size,
			Name: file,
			Mime: mime.TypeByExtension(ext),
		}
		files = append(files, at)
	}
	al.Transaction.Request.Files = files
	var mrs []loggers.AuditMessage
	for _, mr := range tx.matchedRules {
		r := mr.Rule()
		for _, matchData := range mr.MatchedDatas() {
			mrs = append(mrs, loggers.AuditMessage{
				Actionset: strings.Join(tx.WAF.ComponentNames, " "),
				Message:   matchData.Message(),
				Data: loggers.AuditMessageData{
					File:     mr.Rule().File(),
					Line:     mr.Rule().Line(),
					ID:       r.ID(),
					Rev:      r.Revision(),
					Msg:      matchData.Message(),
					Data:     matchData.Data(),
					Severity: r.Severity(),
					Ver:      r.Version(),
					Maturity: r.Maturity(),
					Accuracy: r.Accuracy(),
					Tags:     r.Tags(),
					Raw:      r.Raw(),
				},
			})
		}
	}
	al.Messages = mrs
	return al
}

// Close closes the transaction after phase 5
// This method helps the GC to clean up the transaction faster and release resources
// It also allows caches the transaction back into the sync.Pool
func (tx *Transaction) Close() error {
	defer tx.WAF.txPool.Put(tx)
	tx.variables.reset()
	var errs []error
	if err := tx.requestBodyBuffer.Reset(); err != nil {
		errs = append(errs, err)
	}
	if err := tx.responseBodyBuffer.Reset(); err != nil {
		errs = append(errs, err)
	}

	tx.WAF.Logger.Debug("[%s] Transaction finished, disrupted: %t", tx.id, tx.IsInterrupted())

	switch {
	case len(errs) == 0:
		return nil
	case len(errs) == 1:
		return fmt.Errorf("transaction close failed: %s", errs[0].Error())
	default:
		return fmt.Errorf("transaction close failed:\n- %s\n- %s", errs[0].Error(), errs[1].Error())
	}
}

// String will return a string with the transaction debug information
func (tx *Transaction) String() string {
	res := strings.Builder{}
	res.WriteString("\n\n----------------------- ERRORLOG ----------------------\n")
	for _, mr := range tx.matchedRules {
		status, _ := strconv.Atoi(tx.variables.responseStatus.Get())
		res.WriteString(mr.ErrorLog(status))
		res.WriteString("\n\n----------------------- MATCHDATA ---------------------\n")
		for _, md := range mr.MatchedDatas() {
			fmt.Fprintf(&res, "%+v\n", md)
		}
		res.WriteByte('\n')
	}

	res.WriteString("\n------------------------ DEBUG ------------------------\n")
	for v := byte(1); v < types.VariablesCount; v++ {
		vr := variables.RuleVariable(v)
		col := tx.Collection(vr)
		fmt.Fprint(&res, col)
	}
	return res.String()
}

// generateReqbodyError generates all the error variables for the request body parser
func (tx *Transaction) generateReqbodyError(err error) {
	tx.variables.reqbodyError.Set("1")
	tx.variables.reqbodyErrorMsg.Set(fmt.Sprintf("%s: %s", tx.variables.reqbodyProcessor.Get(), err.Error()))
	tx.variables.reqbodyProcessorError.Set("1")
	tx.variables.reqbodyProcessorErrorMsg.Set(string(err.Error()))
}

// TransactionVariables has pointers to all the variables of the transaction
type TransactionVariables struct {
	// Single Variables
	urlencodedError          *collections.Single
	responseContentType      *collections.Single
	uniqueID                 *collections.Single
	argsCombinedSize         *collections.SizeCollection
	filesCombinedSize        *collections.Single
	fullRequestLength        *collections.Single
	inboundDataError         *collections.Single
	matchedVar               *collections.Single
	matchedVarName           *collections.Single
	multipartDataAfter       *collections.Single
	outboundDataError        *collections.Single
	queryString              *collections.Single
	remoteAddr               *collections.Single
	remoteHost               *collections.Single
	remotePort               *collections.Single
	reqbodyError             *collections.Single
	reqbodyErrorMsg          *collections.Single
	reqbodyProcessorError    *collections.Single
	reqbodyProcessorErrorMsg *collections.Single
	reqbodyProcessor         *collections.Single
	requestBasename          *collections.Single
	requestBody              *collections.Single
	requestBodyLength        *collections.Single
	requestFilename          *collections.Single
	requestLine              *collections.Single
	requestMethod            *collections.Single
	requestProtocol          *collections.Single
	requestURI               *collections.Single
	requestURIRaw            *collections.Single
	responseBody             *collections.Single
	responseContentLength    *collections.Single
	responseProtocol         *collections.Single
	responseStatus           *collections.Single
	serverAddr               *collections.Single
	serverName               *collections.Single
	serverPort               *collections.Single
	highestSeverity          *collections.Single
	statusLine               *collections.Single
	inboundErrorData         *collections.Single
	// Custom
	env                  *collections.Map
	tx                   *collections.Map
	rule                 *collections.Map
	duration             *collections.Single
	args                 *collections.ConcatKeyed
	argsGet              *collections.NamedCollection
	argsGetNames         collection.Collection
	argsPost             *collections.NamedCollection
	argsPostNames        collection.Collection
	argsPath             *collections.NamedCollection
	argsNames            *collections.ConcatCollection
	filesTmpNames        *collections.Map
	geo                  *collections.Map
	files                *collections.Map
	requestCookies       *collections.NamedCollection
	requestCookiesNames  collection.Collection
	requestHeaders       *collections.NamedCollection
	responseHeadersNames collection.Collection
	responseHeaders      *collections.NamedCollection
	requestHeadersNames  collection.Collection
	multipartName        *collections.Map
	multipartFilename    *collections.Map
	matchedVars          *collections.NamedCollection
	matchedVarsNames     collection.Collection
	filesSizes           *collections.Map
	filesNames           *collections.Map
	filesTmpContent      *collections.Map
	xml                  *collections.Map
	requestXML           *collections.Map
	responseXML          *collections.Map
	multipartPartHeaders *collections.Map
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
	v.serverAddr = collections.NewSingle(variables.ServerAddr)
	v.serverName = collections.NewSingle(variables.ServerName)
	v.serverPort = collections.NewSingle(variables.ServerPort)
	v.highestSeverity = collections.NewSingle(variables.HighestSeverity)
	v.statusLine = collections.NewSingle(variables.StatusLine)
	v.inboundErrorData = collections.NewSingle(variables.InboundErrorData)
	v.duration = collections.NewSingle(variables.Duration)

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

	// XML is a pointer to RequestXML
	v.xml = v.requestXML

	v.argsGet = collections.NewNamedCollection(variables.ArgsGet)
	v.argsGetNames = v.argsGet.Names(variables.ArgsGetNames)
	v.argsPost = collections.NewNamedCollection(variables.ArgsPost)
	v.argsPostNames = v.argsPost.Names(variables.ArgsPostNames)
	v.argsPath = collections.NewNamedCollection(variables.ArgsPath)
	v.argsCombinedSize = collections.NewSizeCollection(variables.ArgsCombinedSize, v.argsGet, v.argsPost)
	v.args = collections.NewConcatKeyed(
		variables.Args,
		v.argsGet,
		v.argsPost,
		v.argsPath,
	)
	v.argsNames = collections.NewConcatCollection(
		variables.ArgsNames,
		v.argsGetNames,
		v.argsPostNames,
		// Only used in a concatenating collection so variable name doesn't matter.
		v.argsPath.Names(variables.Unknown),
	)
	return v
}

func (v *TransactionVariables) UserID() collection.Collection {
	return collections.Noop
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

func (v *TransactionVariables) AuthType() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) FilesCombinedSize() collection.Single {
	return v.filesCombinedSize
}

func (v *TransactionVariables) FullRequest() collection.Collection {
	return collections.Noop
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

func (v *TransactionVariables) MultipartBoundaryQuoted() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartBoundaryWhitespace() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartCrlfLfLines() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartDataAfter() collection.Single {
	return v.multipartDataAfter
}

func (v *TransactionVariables) MultipartDataBefore() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartFileLimitExceeded() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartHeaderFolding() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartInvalidHeaderFolding() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartInvalidPart() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartInvalidQuoting() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartLfLine() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartMissingSemicolon() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartPartHeaders() collection.Map {
	return v.multipartPartHeaders
}

func (v *TransactionVariables) MultipartStrictError() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) MultipartUnmatchedBoundary() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) OutboundDataError() collection.Single {
	return v.outboundDataError
}

func (v *TransactionVariables) PathInfo() collection.Collection {
	return collections.Noop
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

func (v *TransactionVariables) SessionID() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) HighestSeverity() collection.Single {
	return v.highestSeverity
}

func (v *TransactionVariables) StatusLine() collection.Single {
	return v.statusLine
}

func (v *TransactionVariables) InboundErrorData() collection.Single {
	return v.inboundErrorData
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

func (v *TransactionVariables) MatchedVarsNames() collection.Collection {
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

func (v *TransactionVariables) ResponseHeadersNames() collection.Collection {
	return v.responseHeadersNames
}

func (v *TransactionVariables) RequestHeadersNames() collection.Collection {
	return v.requestHeadersNames
}

func (v *TransactionVariables) RequestCookiesNames() collection.Collection {
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

func (v *TransactionVariables) IP() collection.Collection {
	return collections.Noop
}

func (v *TransactionVariables) ArgsNames() collection.Collection {
	return v.argsNames
}

func (v *TransactionVariables) ArgsGetNames() collection.Collection {
	return v.argsGetNames
}

func (v *TransactionVariables) ArgsPostNames() collection.Collection {
	return v.argsPostNames
}

func (v *TransactionVariables) reset() {
	v.urlencodedError.Reset()
	v.responseContentType.Reset()
	v.uniqueID.Reset()
	v.filesCombinedSize.Reset()
	v.fullRequestLength.Reset()
	v.inboundDataError.Reset()
	v.matchedVar.Reset()
	v.matchedVarName.Reset()
	v.multipartDataAfter.Reset()
	v.outboundDataError.Reset()
	v.queryString.Reset()
	v.remoteAddr.Reset()
	v.remoteHost.Reset()
	v.remotePort.Reset()
	v.reqbodyError.Reset()
	v.reqbodyErrorMsg.Reset()
	v.reqbodyProcessorError.Reset()
	v.reqbodyProcessorErrorMsg.Reset()
	v.reqbodyProcessor.Reset()
	v.requestBasename.Reset()
	v.requestBody.Reset()
	v.requestBodyLength.Reset()
	v.requestFilename.Reset()
	v.requestLine.Reset()
	v.requestMethod.Reset()
	v.requestProtocol.Reset()
	v.requestURI.Reset()
	v.requestURIRaw.Reset()
	v.responseBody.Reset()
	v.responseContentLength.Reset()
	v.responseProtocol.Reset()
	v.responseStatus.Reset()
	v.serverAddr.Reset()
	v.serverName.Reset()
	v.serverPort.Reset()
	v.highestSeverity.Reset()
	v.statusLine.Reset()
	v.inboundErrorData.Reset()
	v.env.Reset()
	v.tx.Reset()
	v.rule.Reset()
	v.duration.Reset()
	v.argsGet.Reset()
	v.argsPost.Reset()
	v.argsPath.Reset()
	v.filesTmpNames.Reset()
	v.geo.Reset()
	v.files.Reset()
	v.requestCookies.Reset()
	v.requestHeaders.Reset()
	v.responseHeaders.Reset()
	v.multipartName.Reset()
	v.multipartFilename.Reset()
	v.matchedVars.Reset()
	v.filesSizes.Reset()
	v.filesNames.Reset()
	v.filesTmpContent.Reset()
	v.xml.Reset()
	v.requestXML.Reset()
	v.responseXML.Reset()
	v.multipartPartHeaders.Reset()
}
