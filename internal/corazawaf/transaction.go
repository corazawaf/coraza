// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bufio"
	"fmt"
	"io"
	"mime"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/bodyprocessors"
	"github.com/corazawaf/coraza/v3/collection"
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
	ID string

	// Contains the list of matched rules and associated match information
	MatchedRules []types.MatchedRule

	// True if the transaction has been disrupted by any rule
	Interruption *types.Interruption

	// Contains all Collections, including persistent
	Collections [types.VariablesCount]collection.Collection

	// This is used to store log messages
	Logdata string

	// Rules will be skipped after a rule with this SecMarker is found
	SkipAfter string

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
	RequestBodyBuffer *BodyBuffer

	// Handles response body buffers
	ResponseBodyBuffer *BodyBuffer

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

	Variables TransactionVariables
}

func (tx *Transaction) GetID() string {
	return tx.ID
}

func (tx *Transaction) GetVariables() rules.TransactionVariables {
	return &tx.Variables
}

func (tx *Transaction) Collection(idx variables.RuleVariable) collection.Collection {
	return tx.Collections[idx]
}

func (tx *Transaction) Interrupt(interruption *types.Interruption) {
	if tx.RuleEngine == types.RuleEngineOn {
		tx.Interruption = interruption
	}
}

func (tx *Transaction) ContentInjection() bool {
	return tx.WAF.ContentInjection
}

func (tx *Transaction) DebugLogger() loggers.DebugLogger {
	return tx.WAF.Logger
}

func (tx *Transaction) ResponseBodyReader() (io.Reader, error) {
	return tx.ResponseBodyBuffer.Reader()
}

func (tx *Transaction) RequestBodyReader() (io.Reader, error) {
	return tx.RequestBodyBuffer.Reader()
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
	tx.Variables.RequestHeadersNames.AddUniqueCS(keyl, key, keyl)
	tx.Variables.RequestHeaders.AddCS(keyl, key, value)

	if keyl == "content-type" {
		val := strings.ToLower(value)
		if val == "application/x-www-form-urlencoded" {
			tx.Variables.ReqbodyProcessor.Set("URLENCODED")
		} else if strings.HasPrefix(val, "multipart/form-data") {
			tx.Variables.ReqbodyProcessor.Set("MULTIPART")
		}
	} else if keyl == "cookie" {
		// Cookies use the same syntax as GET params but with semicolon (;) separator
		values := urlutil.ParseQuery(value, ';')
		for k, vr := range values {
			kl := strings.ToLower(k)
			tx.Variables.RequestCookiesNames.AddUniqueCS(kl, k, kl)
			for _, v := range vr {
				tx.Variables.RequestCookies.AddCS(kl, k, v)
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
	tx.Variables.ResponseHeadersNames.AddUniqueCS(keyl, key, keyl)
	tx.Variables.ResponseHeaders.AddCS(keyl, key, value)

	// Most headers can be managed like that
	if keyl == "content-type" {
		spl := strings.SplitN(value, ";", 2)
		tx.Variables.ResponseContentType.Set(spl[0])
	}
}

func (tx *Transaction) Capturing() bool {
	return tx.Capture
}

// CaptureField is used to set the TX:[index] variables by operators
// that supports capture, like @rx
func (tx *Transaction) CaptureField(index int, value string) {
	if tx.Capture {
		tx.WAF.Logger.Debug("[%s] Capturing field %d with value %q", tx.ID, index, value)
		i := strconv.Itoa(index)
		tx.Variables.TX.SetIndex(i, 0, value)
	}
}

// this function is used to control which variables are reset after a new rule is evaluated
func (tx *Transaction) resetCaptures() {
	tx.WAF.Logger.Debug("[%s] Reseting captured variables", tx.ID)
	// We reset capture 0-9
	ctx := tx.Variables.TX
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
		spl := strings.SplitN(l, ":", 2)
		if len(spl) != 2 {
			return nil, fmt.Errorf("invalid request header")
		}
		k := strings.Trim(spl[0], " ")
		v := strings.Trim(spl[1], " ")
		tx.AddRequestHeader(k, v)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}
	ctcol := tx.Variables.RequestHeaders.Get("content-type")
	ct := ""
	if len(ctcol) > 0 {
		ct = strings.Split(ctcol[0], ";")[0]
	}
	for scanner.Scan() {
		if _, err := tx.RequestBodyBuffer.Write(scanner.Bytes()); err != nil {
			return nil, fmt.Errorf("cannot write to request body to buffer")
		}
		// urlencoded cannot end with CRLF
		if ct != "application/x-www-form-urlencoded" {
			if _, err := tx.RequestBodyBuffer.Write([]byte{'\r', '\n'}); err != nil {
				return nil, fmt.Errorf("cannot write to request body to buffer")
			}
		}
	}
	return tx.ProcessRequestBody()
}

// matchVariable Creates the MATCHED_ variables required by chains and macro expansion
// MATCHED_VARS, MATCHED_VAR, MATCHED_VAR_NAME, MATCHED_VARS_NAMES
func (tx *Transaction) matchVariable(match types.MatchData) {
	var varName, varNamel string
	if match.Key != "" {
		varName = match.VariableName + ":" + match.Key
		varNamel = match.VariableName + ":" + strings.ToLower(match.Key)
	} else {
		varName = match.VariableName
		varNamel = match.VariableName
	}
	// Array of values
	matchedVars := tx.Variables.MatchedVars
	// Last key
	matchedVarName := tx.Variables.MatchedVarName
	matchedVarName.Reset()
	// Array of keys
	matchedVarsNames := tx.Variables.MatchedVarsNames

	// We add the key in lowercase for ease of lookup in chains
	// This is similar to args handling
	matchedVars.AddCS(varNamel, varName, match.Value)
	tx.Variables.MatchedVar.Set(match.Value)

	// We add the key in lowercase for ease of lookup in chains
	// This is similar to args handling
	matchedVarsNames.AddCS(varNamel, varName, varName)
	matchedVarName.Set(varName)
}

// MatchRule Matches a rule to be logged
func (tx *Transaction) MatchRule(r *Rule, mds []types.MatchData) {
	tx.WAF.Logger.Debug("[%s] rule %d matched", tx.ID, r.ID)
	// tx.MatchedRules = append(tx.MatchedRules, mr)

	// If the rule is set to audit, we log the transaction to the audit log
	if r.Audit {
		tx.audit = true
	}

	// set highest_severity
	hs := tx.Variables.HighestSeverity
	maxSeverity, _ := types.ParseRuleSeverity(hs.String())
	if r.Severity > maxSeverity {
		hs.Set(strconv.Itoa(r.Severity.Int()))
	}

	mr := types.MatchedRule{
		URI:             tx.Variables.RequestURI.String(),
		ID:              tx.ID,
		ServerIPAddress: tx.Variables.ServerAddr.String(),
		ClientIPAddress: tx.Variables.RemoteAddr.String(),
		Rule:            r.RuleMetadata,
		MatchedDatas:    mds,
	}

	for _, md := range mds {
		// Use 1st set message of rule chain as message
		if md.Message != "" {
			mr.Message = md.Message
			mr.Data = md.Data
			break
		}
	}

	tx.MatchedRules = append(tx.MatchedRules, mr)
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
	collection := rv.Variable
	col := tx.Collections[rv.Variable]
	if col == nil {
		return []types.MatchData{}
	}

	var matches []types.MatchData
	// Now that we have access to the collection, we can apply the exceptions
	if rv.KeyRx == nil {
		if len(rv.KeyStr) == 0 {
			matches = col.FindAll()
		} else {
			matches = col.FindString(rv.KeyStr)
		}
	} else {
		matches = col.FindRegex(rv.KeyRx)
	}

	var rmi []int
	for i, c := range matches {
		for _, ex := range rv.Exceptions {
			lkey := strings.ToLower(c.Key)
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
			{
				VariableName: collection.Name(),
				Variable:     collection,
				Key:          rv.KeyStr,
				Value:        strconv.Itoa(count),
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
// Important: Remember to check for a possible intervention.
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

	tx.Variables.RemoteAddr.Set(client)
	tx.Variables.RemotePort.Set(p)
	tx.Variables.ServerAddr.Set(server)
	tx.Variables.ServerPort.Set(p2)
}

// ExtractArguments transforms an url encoded string to a map and creates
// ARGS_POST|GET
func (tx *Transaction) ExtractArguments(orig string, uri string) {
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
func (tx *Transaction) AddArgument(orig string, key string, value string) {
	// TODO implement ARGS value limit using ArgumentsLimit
	var vals *collection.Map
	if orig == "GET" {
		vals = tx.Variables.ArgsGet
	} else {
		vals = tx.Variables.ArgsPost
	}
	keyl := strings.ToLower(key)

	vals.AddCS(keyl, key, value)
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
	tx.Variables.RequestMethod.Set(method)
	tx.Variables.RequestProtocol.Set(httpVersion)
	tx.Variables.RequestURIRaw.Set(uri)

	// TODO modsecurity uses HTTP/${VERSION} instead of just version, let's check it out
	tx.Variables.RequestLine.Set(fmt.Sprintf("%s %s %s", method, uri, httpVersion))

	var err error

	// we remove anchors
	if in := strings.Index(uri, "#"); in != -1 {
		uri = uri[:in]
	}
	path := ""
	parsedURL, err := url.Parse(uri)
	query := ""
	if err != nil {
		tx.Variables.UrlencodedError.Set(err.Error())
		path = uri
		tx.Variables.RequestURI.Set(uri)
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
		tx.ExtractArguments("GET", parsedURL.RawQuery)
		tx.Variables.RequestURI.Set(parsedURL.String())
		path = parsedURL.Path
		query = parsedURL.RawQuery
	}
	offset := strings.LastIndexAny(path, "/\\")
	if offset != -1 && len(path) > offset+1 {
		tx.Variables.RequestBasename.Set(path[offset+1:])
	} else {
		tx.Variables.RequestBasename.Set(path)
	}
	tx.Variables.RequestFilename.Set(path)

	tx.Variables.QueryString.Set(query)
}

// ProcessRequestHeaders Performs the analysis on the request readers.
//
// This method perform the analysis on the request headers, notice however
// that the headers should be added prior to the execution of this function.
//
// note: Remember to check for a possible intervention.
func (tx *Transaction) ProcessRequestHeaders() *types.Interruption {
	if tx.RuleEngine == types.RuleEngineOff {
		// RUle engine is disabled
		return nil
	}
	tx.WAF.Rules.Eval(types.PhaseRequestHeaders, tx)
	return tx.Interruption
}

func (tx *Transaction) RequestBodyWriter() io.Writer {
	return tx.RequestBodyBuffer
}

// ProcessRequestBody Performs the request body (if any)
//
// This method perform the analysis on the request body. It is optional to
// call that function. If this API consumer already know that there isn't a
// body for inspect it is recommended to skip this step.
//
// Remember to check for a possible intervention.
func (tx *Transaction) ProcessRequestBody() (*types.Interruption, error) {
	if tx.RuleEngine == types.RuleEngineOff {
		return nil, nil
	}
	// we won't process empty request bodies or disabled RequestBodyAccess
	if !tx.RequestBodyAccess || tx.RequestBodyBuffer.Size() == 0 {
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.Interruption, nil
	}
	mime := ""
	if m := tx.Variables.RequestHeaders.Get("content-type"); len(m) > 0 {
		mime = m[0]
	}

	reader, err := tx.RequestBodyBuffer.Reader()
	if err != nil {
		return nil, err
	}

	// Chunked requests will always be written to a temporary file
	if tx.RequestBodyBuffer.Size() >= tx.RequestBodyLimit {
		tx.Variables.InboundErrorData.Set("1")
		if tx.WAF.RequestBodyLimitAction == types.RequestBodyLimitActionReject {
			// We interrupt this transaction in case RequestBodyLimitAction is Reject
			tx.Interruption = &types.Interruption{
				Status: 403,
				Action: "deny",
			}
			return tx.Interruption, nil
		}

		if tx.WAF.RequestBodyLimitAction == types.RequestBodyLimitActionProcessPartial {
			tx.Variables.InboundErrorData.Set("1")
			// we limit our reader to tx.RequestBodyLimit bytes
			reader = io.LimitReader(reader, tx.RequestBodyLimit)
		}
	}

	rbp := tx.Variables.ReqbodyProcessor.String()

	// Default variables.ReqbodyProcessor values
	// XML and JSON must be forced with ctl:requestBodyProcessor=JSON
	if tx.ForceRequestBodyVariable {
		// We force URLENCODED if mime is x-www... or we have an empty RBP and ForceRequestBodyVariable
		rbp = "URLENCODED"
		tx.Variables.ReqbodyProcessor.Set(rbp)
	}
	tx.WAF.Logger.Debug("[%s] Attempting to process request body using %q", tx.ID, rbp)
	rbp = strings.ToLower(rbp)
	if rbp == "" {
		// so there is no bodyprocessor, we don't want to generate an error
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.Interruption, nil
	}
	bodyprocessor, err := bodyprocessors.Get(rbp)
	if err != nil {
		tx.generateReqbodyError(fmt.Errorf("Invalid body processor"))
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.Interruption, nil
	}
	if err := bodyprocessor.ProcessRequest(reader, tx.Collections, bodyprocessors.Options{
		Mime:        mime,
		StoragePath: tx.WAF.UploadDir,
	}); err != nil {
		tx.generateReqbodyError(err)
		tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.Interruption, nil
	}

	tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
	return tx.Interruption, nil
}

// ProcessResponseHeaders Perform the analysis on the response readers.
//
// This method perform the analysis on the response headers, notice however
// that the headers should be added prior to the execution of this function.
//
// note: Remember to check for a possible intervention.
func (tx *Transaction) ProcessResponseHeaders(code int, proto string) *types.Interruption {
	c := strconv.Itoa(code)
	tx.Variables.ResponseStatus.Set(c)
	tx.Variables.ResponseProtocol.Set(proto)

	if tx.RuleEngine == types.RuleEngineOff {
		return nil
	}

	tx.WAF.Rules.Eval(types.PhaseResponseHeaders, tx)
	return tx.Interruption
}

// IsProcessableResponseBody returns true if the response body meets the
// criteria to be processed, response headers must be set before this.
// The content-type response header must be in the SecRequestBodyMime
// This is used by webservers to choose whether tostream response buffers
// directly to the client or write them to Coraza
func (tx *Transaction) IsProcessableResponseBody() bool {
	// TODO add more validations
	ct := tx.Variables.ResponseContentType.String()
	return stringsutil.InSlice(ct, tx.WAF.ResponseBodyMimeTypes)
}

func (tx *Transaction) ResponseBodyWriter() io.Writer {
	return tx.ResponseBodyBuffer
}

// ProcessResponseBody Perform the request body (if any)
//
// This method perform the analysis on the request body. It is optional to
// call that method. If this API consumer already know that there isn't a
// body for inspect it is recommended to skip this step.
//
// note Remember to check for a possible intervention.
func (tx *Transaction) ProcessResponseBody() (*types.Interruption, error) {
	if tx.RuleEngine == types.RuleEngineOff {
		return tx.Interruption, nil
	}
	if !tx.ResponseBodyAccess || !tx.IsProcessableResponseBody() {
		tx.WAF.Logger.Debug("[%s] Skipping response body processing (Access: %t)", tx.ID, tx.ResponseBodyAccess)
		tx.WAF.Rules.Eval(types.PhaseResponseBody, tx)
		return tx.Interruption, nil
	}
	tx.WAF.Logger.Debug("[%s] Attempting to process response body", tx.ID)
	reader, err := tx.ResponseBodyBuffer.Reader()
	if err != nil {
		return tx.Interruption, err
	}
	reader = io.LimitReader(reader, tx.WAF.ResponseBodyLimit)
	buf := new(strings.Builder)
	length, err := io.Copy(buf, reader)
	if err != nil {
		return tx.Interruption, err
	}

	if tx.ResponseBodyBuffer.Size() >= tx.WAF.ResponseBodyLimit {
		tx.Variables.OutboundDataError.Set("1")
	}

	tx.Variables.ResponseContentLength.Set(strconv.FormatInt(length, 10))
	tx.Variables.ResponseBody.Set(buf.String())
	tx.WAF.Rules.Eval(types.PhaseResponseBody, tx)
	return tx.Interruption, nil
}

// ProcessLogging Logging all information relative to this transaction.
// An error log
// At this point there is not need to hold the connection, the response can be
// delivered prior to the execution of this method.
func (tx *Transaction) ProcessLogging() {
	// I'm not sure why but modsecurity won't log if RuleEngine is disabled
	// if tx.RuleEngine == RULE_ENGINE_OFF {
	// 	return
	// }
	tx.WAF.Rules.Eval(types.PhaseLogging, tx)

	if tx.AuditEngine == types.AuditEngineOff {
		// Audit engine disabled
		tx.WAF.Logger.Debug("[%s] Transaction not marked for audit logging, AuditEngine is disabled", tx.ID)
		return
	}

	if tx.AuditEngine == types.AuditEngineRelevantOnly && !tx.audit {
		// Transaction marked not for audit logging
		tx.WAF.Logger.Debug("[%s] Transaction not marked for audit logging, AuditEngine is RelevantOnly and we got noauditlog", tx.ID)
		return
	}

	if tx.AuditEngine == types.AuditEngineRelevantOnly && tx.audit {
		re := tx.WAF.AuditLogRelevantStatus
		status := tx.Variables.ResponseStatus.String()
		if re != nil && !re.Match([]byte(status)) {
			// Not relevant status
			tx.WAF.Logger.Debug("[%s] Transaction status not marked for audit logging", tx.ID)
			return
		}
	}

	tx.WAF.Logger.Debug("[%s] Transaction marked for audit logging", tx.ID)
	if writer := tx.WAF.AuditLogWriter; writer != nil {
		// we don't log if there is an empty audit logger
		if err := writer.Write(tx.AuditLog()); err != nil {
			tx.WAF.Logger.Error(err.Error())
		}
	}
}

// Interrupted will return true if the transaction was interrupted
func (tx *Transaction) Interrupted() bool {
	return tx.Interruption != nil
}

func (tx *Transaction) GetInterruption() *types.Interruption {
	return tx.Interruption
}

func (tx *Transaction) GetMatchedRules() []types.MatchedRule {
	return tx.MatchedRules
}

// AuditLog returns an AuditLog struct, used to write audit logs
func (tx *Transaction) AuditLog() *loggers.AuditLog {
	al := &loggers.AuditLog{}
	al.Messages = nil
	// YYYY/MM/DD HH:mm:ss
	ts := time.Unix(0, tx.Timestamp).Format("2006/01/02 15:04:05")
	al.Parts = tx.AuditLogParts
	al.Transaction = loggers.AuditTransaction{
		Timestamp:     ts,
		UnixTimestamp: tx.Timestamp,
		ID:            tx.ID,
		ClientIP:      tx.Variables.RemoteAddr.String(),
		ClientPort:    tx.Variables.RemotePort.Int(),
		HostIP:        tx.Variables.ServerAddr.String(),
		HostPort:      tx.Variables.ServerPort.Int(),
		ServerID:      tx.Variables.ServerName.String(), // TODO check
		Request: loggers.AuditTransactionRequest{
			Method:      tx.Variables.RequestMethod.String(),
			Protocol:    tx.Variables.RequestProtocol.String(),
			URI:         tx.Variables.RequestURI.String(),
			HTTPVersion: tx.Variables.RequestProtocol.String(),
			// Body and headers are audit variables.RequestUriRaws
		},
		Response: loggers.AuditTransactionResponse{
			Status: tx.Variables.ResponseStatus.Int(),
			// body and headers are audit parts
		},
	}
	rengine := tx.RuleEngine.String()

	al.Transaction.Request.Headers = tx.Variables.RequestHeaders.Data()
	al.Transaction.Request.Body = tx.Variables.RequestBody.String()
	// TODO maybe change to:
	// al.Transaction.Request.Body = tx.RequestBodyBuffer.String()
	al.Transaction.Response.Headers = tx.Variables.ResponseHeaders.Data()
	al.Transaction.Response.Body = tx.Variables.ResponseBody.String()
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
	for _, file := range tx.Variables.Files.Get("") {
		var size int64
		if fs := tx.Variables.FilesSizes.Get(file); len(fs) > 0 {
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
	for _, mr := range tx.MatchedRules {
		r := mr.Rule
		for _, matchData := range mr.MatchedDatas {
			mrs = append(mrs, loggers.AuditMessage{
				Actionset: strings.Join(tx.WAF.ComponentNames, " "),
				Message:   matchData.Message,
				Data: loggers.AuditMessageData{
					File:     mr.Rule.File,
					Line:     mr.Rule.Line,
					ID:       r.ID,
					Rev:      r.Rev,
					Msg:      matchData.Message,
					Data:     matchData.Data,
					Severity: r.Severity,
					Ver:      r.Version,
					Maturity: r.Maturity,
					Accuracy: r.Accuracy,
					Tags:     r.Tags,
					Raw:      r.Raw,
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
	defer transactionPool.Put(tx)
	for _, c := range tx.Collections {
		if c != nil {
			c.Reset()
		}
	}
	var errs []error
	if err := tx.RequestBodyBuffer.Reset(); err != nil {
		errs = append(errs, err)
	}
	if err := tx.ResponseBodyBuffer.Reset(); err != nil {
		errs = append(errs, err)
	}

	tx.WAF.Logger.Debug("[%s] Transaction finished, disrupted: %t", tx.ID, tx.Interrupted())

	switch {
	case len(errs) == 0:
		return nil
	case len(errs) == 1:
		return fmt.Errorf("transaction close failed: %s", errs[0].Error())
	default:
		return fmt.Errorf("transaction close failed:\n- %s\n- %s", errs[0].Error(), errs[1].Error())
	}
}

func (tx *Transaction) String() string {
	return tx.Debug()
}

// Debug will return a string with the transaction debug information
func (tx *Transaction) Debug() string {
	res := "\n\n----------------------- ERRORLOG ----------------------\n"
	for _, mr := range tx.MatchedRules {
		res += mr.ErrorLog(tx.Variables.ResponseStatus.Int())
		res += "\n\n----------------------- MATCHDATA ---------------------\n"
		for _, md := range mr.MatchedDatas {
			res += fmt.Sprintf("%+v", md) + "\n"
		}
		res += "\n"
	}

	res += "\n------------------------ DEBUG ------------------------\n"
	for v := byte(1); v < types.VariablesCount; v++ {
		vr := variables.RuleVariable(v)
		if vr.Name() == "UNKNOWN" {
			continue
		}
		data := map[string][]string{}
		switch col := tx.Collections[vr].(type) {
		case *collection.Simple:
			data[""] = []string{
				col.String(),
			}
		case *collection.Map:
			data = col.Data()
		case *collection.Proxy:
			data = col.Data()
		case *collection.TranslationProxy:
			data[""] = col.Data()
		}

		if len(data) == 1 {
			res += fmt.Sprintf("%s: ", vr.Name())
		} else {
			res += fmt.Sprintf("%s:\n", vr.Name())
		}

		for k, d := range data {
			if k != "" {
				res += fmt.Sprintf("    %s: %s\n", k, strings.Join(d, ","))
			} else {
				res += fmt.Sprintf("%s\n", strings.Join(d, ","))
			}
		}
	}
	return res
}

// generateReqbodyError generates all the error variables for the request body parser
func (tx *Transaction) generateReqbodyError(err error) {
	tx.Variables.ReqbodyError.Set("1")
	tx.Variables.ReqbodyErrorMsg.Set(fmt.Sprintf("%s: %s", tx.Variables.ReqbodyProcessor.String(), err.Error()))
	tx.Variables.ReqbodyProcessorError.Set("1")
	tx.Variables.ReqbodyProcessorErrorMsg.Set(string(err.Error()))
}

// TransactionVariables has pointers to all the variables of the transaction
type TransactionVariables struct {
	// Simple Variables
	Userid                        *collection.Simple
	UrlencodedError               *collection.Simple
	ResponseContentType           *collection.Simple
	UniqueID                      *collection.Simple
	ArgsCombinedSize              *collection.SizeProxy
	AuthType                      *collection.Simple
	FilesCombinedSize             *collection.Simple
	FullRequest                   *collection.Simple
	FullRequestLength             *collection.Simple
	InboundDataError              *collection.Simple
	MatchedVar                    *collection.Simple
	MatchedVarName                *collection.Simple
	MultipartBoundaryQuoted       *collection.Simple
	MultipartBoundaryWhitespace   *collection.Simple
	MultipartCrlfLfLines          *collection.Simple
	MultipartDataAfter            *collection.Simple
	MultipartDataBefore           *collection.Simple
	MultipartFileLimitExceeded    *collection.Simple
	MultipartHeaderFolding        *collection.Simple
	MultipartInvalidHeaderFolding *collection.Simple
	MultipartInvalidPart          *collection.Simple
	MultipartInvalidQuoting       *collection.Simple
	MultipartLfLine               *collection.Simple
	MultipartMissingSemicolon     *collection.Simple
	MultipartStrictError          *collection.Simple
	MultipartUnmatchedBoundary    *collection.Simple
	OutboundDataError             *collection.Simple
	PathInfo                      *collection.Simple
	QueryString                   *collection.Simple
	RemoteAddr                    *collection.Simple
	RemoteHost                    *collection.Simple
	RemotePort                    *collection.Simple
	ReqbodyError                  *collection.Simple
	ReqbodyErrorMsg               *collection.Simple
	ReqbodyProcessorError         *collection.Simple
	ReqbodyProcessorErrorMsg      *collection.Simple
	ReqbodyProcessor              *collection.Simple
	RequestBasename               *collection.Simple
	RequestBody                   *collection.Simple
	RequestBodyLength             *collection.Simple
	RequestFilename               *collection.Simple
	RequestLine                   *collection.Simple
	RequestMethod                 *collection.Simple
	RequestProtocol               *collection.Simple
	RequestURI                    *collection.Simple
	RequestURIRaw                 *collection.Simple
	ResponseBody                  *collection.Simple
	ResponseContentLength         *collection.Simple
	ResponseProtocol              *collection.Simple
	ResponseStatus                *collection.Simple
	ServerAddr                    *collection.Simple
	ServerName                    *collection.Simple
	ServerPort                    *collection.Simple
	Sessionid                     *collection.Simple
	HighestSeverity               *collection.Simple
	StatusLine                    *collection.Simple
	InboundErrorData              *collection.Simple
	// Custom
	Env      *collection.Map
	TX       *collection.Map
	Rule     *collection.Map
	Duration *collection.Simple
	// Proxy Variables
	Args *collection.Proxy
	// Maps Variables
	ArgsGet              *collection.Map
	ArgsPost             *collection.Map
	ArgsPath             *collection.Map
	FilesTmpNames        *collection.Map
	Geo                  *collection.Map
	Files                *collection.Map
	RequestCookies       *collection.Map
	RequestHeaders       *collection.Map
	ResponseHeaders      *collection.Map
	MultipartName        *collection.Map
	MatchedVarsNames     *collection.Map
	MultipartFilename    *collection.Map
	MatchedVars          *collection.Map
	FilesSizes           *collection.Map
	FilesNames           *collection.Map
	FilesTmpContent      *collection.Map
	ResponseHeadersNames *collection.Map
	RequestHeadersNames  *collection.Map
	RequestCookiesNames  *collection.Map
	XML                  *collection.Map
	RequestXML           *collection.Map
	ResponseXML          *collection.Map
	MultipartPartHeaders *collection.Map
	// Persistent variables
	IP *collection.Map
	// Translation Proxy Variables
	ArgsNames     *collection.TranslationProxy
	ArgsGetNames  *collection.TranslationProxy
	ArgsPostNames *collection.TranslationProxy
}

func (v *TransactionVariables) GetUserID() *collection.Simple {
	return v.Userid
}

func (v *TransactionVariables) GetUrlencodedError() *collection.Simple {
	return v.UrlencodedError
}

func (v *TransactionVariables) GetResponseContentType() *collection.Simple {
	return v.ResponseContentType
}

func (v *TransactionVariables) GetUniqueID() *collection.Simple {
	return v.UniqueID
}

func (v *TransactionVariables) GetArgsCombinedSize() *collection.SizeProxy {
	return v.ArgsCombinedSize
}

func (v *TransactionVariables) GetAuthType() *collection.Simple {
	return v.AuthType
}

func (v *TransactionVariables) GetFilesCombinedSize() *collection.Simple {
	return v.FilesCombinedSize
}

func (v *TransactionVariables) GetFullRequest() *collection.Simple {
	return v.FullRequest
}

func (v *TransactionVariables) GetFullRequestLength() *collection.Simple {
	return v.FullRequestLength
}

func (v *TransactionVariables) GetInboundDataError() *collection.Simple {
	return v.InboundDataError
}

func (v *TransactionVariables) GetMatchedVar() *collection.Simple {
	return v.MatchedVar
}

func (v *TransactionVariables) GetMatchedVarName() *collection.Simple {
	return v.MatchedVarName
}

func (v *TransactionVariables) GetMultipartBoundaryQuoted() *collection.Simple {
	return v.MultipartBoundaryQuoted
}

func (v *TransactionVariables) GetMultipartBoundaryWhitespace() *collection.Simple {
	return v.MultipartBoundaryWhitespace
}

func (v *TransactionVariables) GetMultipartCrlfLfLines() *collection.Simple {
	return v.MultipartCrlfLfLines
}

func (v *TransactionVariables) GetMultipartDataAfter() *collection.Simple {
	return v.MultipartDataAfter
}

func (v *TransactionVariables) GetMultipartDataBefore() *collection.Simple {
	return v.MultipartDataBefore
}

func (v *TransactionVariables) GetMultipartFileLimitExceeded() *collection.Simple {
	return v.MultipartFileLimitExceeded
}

func (v *TransactionVariables) GetMultipartHeaderFolding() *collection.Simple {
	return v.MultipartHeaderFolding
}

func (v *TransactionVariables) GetMultipartInvalidHeaderFolding() *collection.Simple {
	return v.MultipartInvalidHeaderFolding
}

func (v *TransactionVariables) GetMultipartInvalidPart() *collection.Simple {
	return v.MultipartInvalidPart
}

func (v *TransactionVariables) GetMultipartInvalidQuoting() *collection.Simple {
	return v.MultipartInvalidQuoting
}

func (v *TransactionVariables) GetMultipartLfLine() *collection.Simple {
	return v.MultipartLfLine
}

func (v *TransactionVariables) GetMultipartMissingSemicolon() *collection.Simple {
	return v.MultipartMissingSemicolon
}

func (v *TransactionVariables) GetMultipartStrictError() *collection.Simple {
	return v.MultipartStrictError
}

func (v *TransactionVariables) GetMultipartUnmatchedBoundary() *collection.Simple {
	return v.MultipartUnmatchedBoundary
}

func (v *TransactionVariables) GetOutboundDataError() *collection.Simple {
	return v.OutboundDataError
}

func (v *TransactionVariables) GetPathInfo() *collection.Simple {
	return v.PathInfo
}

func (v *TransactionVariables) GetQueryString() *collection.Simple {
	return v.QueryString
}

func (v *TransactionVariables) GetRemoteAddr() *collection.Simple {
	return v.RemoteAddr
}

func (v *TransactionVariables) GetRemoteHost() *collection.Simple {
	return v.RemoteHost
}

func (v *TransactionVariables) GetRemotePort() *collection.Simple {
	return v.RemotePort
}

func (v *TransactionVariables) GetReqbodyError() *collection.Simple {
	return v.ReqbodyError
}

func (v *TransactionVariables) GetReqbodyErrorMsg() *collection.Simple {
	return v.ReqbodyErrorMsg
}

func (v *TransactionVariables) GetReqbodyProcessorError() *collection.Simple {
	return v.ReqbodyProcessorError
}

func (v *TransactionVariables) GetReqbodyProcessorErrorMsg() *collection.Simple {
	return v.ReqbodyProcessorErrorMsg
}

func (v *TransactionVariables) GetReqbodyProcessor() *collection.Simple {
	return v.ReqbodyProcessor
}

func (v *TransactionVariables) GetRequestBasename() *collection.Simple {
	return v.RequestBasename
}

func (v *TransactionVariables) GetRequestBody() *collection.Simple {
	return v.RequestBody
}

func (v *TransactionVariables) GetRequestBodyLength() *collection.Simple {
	return v.RequestBodyLength
}

func (v *TransactionVariables) GetRequestFilename() *collection.Simple {
	return v.RequestFilename
}

func (v *TransactionVariables) GetRequestLine() *collection.Simple {
	return v.RequestLine
}

func (v *TransactionVariables) GetRequestMethod() *collection.Simple {
	return v.RequestMethod
}

func (v *TransactionVariables) GetRequestProtocol() *collection.Simple {
	return v.RequestProtocol
}

func (v *TransactionVariables) GetRequestURI() *collection.Simple {
	return v.RequestURI
}

func (v *TransactionVariables) GetRequestURIRaw() *collection.Simple {
	return v.RequestURIRaw
}

func (v *TransactionVariables) GetResponseBody() *collection.Simple {
	return v.ResponseBody
}

func (v *TransactionVariables) GetResponseContentLength() *collection.Simple {
	return v.ResponseContentLength
}

func (v *TransactionVariables) GetResponseProtocol() *collection.Simple {
	return v.ResponseProtocol
}

func (v *TransactionVariables) GetResponseStatus() *collection.Simple {
	return v.ResponseStatus
}

func (v *TransactionVariables) GetServerAddr() *collection.Simple {
	return v.ServerAddr
}

func (v *TransactionVariables) GetServerName() *collection.Simple {
	return v.ServerName
}

func (v *TransactionVariables) GetServerPort() *collection.Simple {
	return v.ServerPort
}

func (v *TransactionVariables) GetSessionid() *collection.Simple {
	return v.Sessionid
}

func (v *TransactionVariables) GetHighestSeverity() *collection.Simple {
	return v.HighestSeverity
}

func (v *TransactionVariables) GetStatusLine() *collection.Simple {
	return v.StatusLine
}

func (v *TransactionVariables) GetInboundErrorData() *collection.Simple {
	return v.InboundErrorData
}

func (v *TransactionVariables) GetEnv() *collection.Map {
	return v.Env
}

func (v *TransactionVariables) GetTX() *collection.Map {
	return v.TX
}

func (v *TransactionVariables) GetRule() *collection.Map {
	return v.Rule
}

func (v *TransactionVariables) GetDuration() *collection.Simple {
	return v.Duration
}

func (v *TransactionVariables) GetArgs() *collection.Proxy {
	return v.Args
}

func (v *TransactionVariables) GetArgsGet() *collection.Map {
	return v.ArgsGet
}

func (v *TransactionVariables) GetArgsPost() *collection.Map {
	return v.ArgsPost
}

func (v *TransactionVariables) GetArgsPath() *collection.Map {
	return v.ArgsPath
}

func (v *TransactionVariables) GetFilesTmpNames() *collection.Map {
	return v.FilesTmpNames
}

func (v *TransactionVariables) GetGeo() *collection.Map {
	return v.Geo
}

func (v *TransactionVariables) GetFiles() *collection.Map {
	return v.Files
}

func (v *TransactionVariables) GetRequestCookies() *collection.Map {
	return v.RequestCookies
}

func (v *TransactionVariables) GetRequestHeaders() *collection.Map {
	return v.RequestHeaders
}

func (v *TransactionVariables) GetResponseHeaders() *collection.Map {
	return v.ResponseHeaders
}

func (v *TransactionVariables) GetMultipartName() *collection.Map {
	return v.MultipartName
}

func (v *TransactionVariables) GetMatchedVarsNames() *collection.Map {
	return v.MatchedVarsNames
}

func (v *TransactionVariables) GetMultipartFilename() *collection.Map {
	return v.MultipartFilename
}

func (v *TransactionVariables) GetMatchedVars() *collection.Map {
	return v.MatchedVars
}

func (v *TransactionVariables) GetFilesSizes() *collection.Map {
	return v.FilesSizes
}

func (v *TransactionVariables) GetFilesNames() *collection.Map {
	return v.FilesNames
}

func (v *TransactionVariables) GetFilesTmpContent() *collection.Map {
	return v.FilesTmpContent
}

func (v *TransactionVariables) GetResponseHeadersNames() *collection.Map {
	return v.ResponseHeadersNames
}

func (v *TransactionVariables) GetRequestHeadersNames() *collection.Map {
	return v.RequestHeadersNames
}

func (v *TransactionVariables) GetRequestCookiesNames() *collection.Map {
	return v.RequestCookiesNames
}

func (v *TransactionVariables) GetXML() *collection.Map {
	return v.XML
}

func (v *TransactionVariables) GetRequestXML() *collection.Map {
	return v.RequestXML
}

func (v *TransactionVariables) GetResponseXML() *collection.Map {
	return v.ResponseXML
}

func (v *TransactionVariables) GetIP() *collection.Map {
	return v.IP
}

func (v *TransactionVariables) GetArgsNames() *collection.TranslationProxy {
	return v.ArgsNames
}

func (v *TransactionVariables) GetArgsGetNames() *collection.TranslationProxy {
	return v.ArgsGetNames
}

func (v *TransactionVariables) GetArgsPostNames() *collection.TranslationProxy {
	return v.ArgsPostNames
}
