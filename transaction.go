// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http:// www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package coraza

import (
	"bufio"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jptosso/coraza-waf/v2/bodyprocessors"
	loggers "github.com/jptosso/coraza-waf/v2/loggers"
	"github.com/jptosso/coraza-waf/v2/types"
	"github.com/jptosso/coraza-waf/v2/types/variables"
	utils "github.com/jptosso/coraza-waf/v2/utils/strings"
	url2 "github.com/jptosso/coraza-waf/v2/utils/url"
	"go.uber.org/zap"
)

// Transaction is created from a WAF instance to handle web requests and responses,
// it contains a copy of most WAF configurations that can be safely changed.
// Transactions are used to store all data like URLs, request and response
// headers. Transactions are used to evaluate rules by phase and generate disruptive
// actions. Disruptive actions can be read from *tx.Interruption.
// It is safe to manage multiple transactions but transactions themself are not
// thread safe
type Transaction struct {
	// If true the transaction is going to be logged, it won't log if IsRelevantStatus() fails
	Log bool

	// Transaction ID
	ID string

	// Contains the list of matched rules and associated match information
	MatchedRules []MatchedRule

	// True if the transaction has been disrupted by any rule
	Interruption *types.Interruption

	// Contains all collections, including persistent
	collections []*Collection

	// Response data to be sent
	Status int

	// This is used to store log messages
	Logdata string

	// Rules will be skipped after a rule with this SecMarker is found
	SkipAfter string

	// Copies from the WafInstance that may be overwritten by the ctl action
	AuditEngine              types.AuditEngineStatus
	AuditLogParts            []rune
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
	StopWatches map[types.RulePhase]int

	// Contains a Waf instance for the current transaction
	Waf Waf

	// Timestamp of the request
	Timestamp int64
}

// Used to test macro expansions
var macroRegexp = regexp.MustCompile(`%\{([\w.-]+?)\}`)

// MacroExpansion expands a string that contains %{somevalue.some-key}
// into it's first value, for example:
// 	v1 := tx.MacroExpansion("%{request_headers.user-agent")
//  v2 := tx.GetCollection(variables.RequestHeaders).GetFirstString("user-agent")
//  v1 == v2 // returns true
// Important: this function is case insensitive
func (tx *Transaction) MacroExpansion(data string) string {
	if data == "" {
		return ""
	}

	// \w includes alphanumeric and _
	r := macroRegexp
	matches := r.FindAllString(data, -1)
	for _, v := range matches {
		match := v[2 : len(v)-1]
		matchspl := strings.SplitN(match, ".", 2)
		col, err := variables.ParseVariable(matchspl[0])
		if err != nil {
			// Invalid collection
			continue
		}
		key := ""
		if len(matchspl) == 2 {
			key = matchspl[1]
		}
		collection := tx.GetCollection(col)
		if collection == nil {
			// Invalid collection again
			continue
		}
		expansion := collection.Get(strings.ToLower(key))
		if len(expansion) == 0 {
			data = strings.ReplaceAll(data, v, "")
		} else {
			data = strings.ReplaceAll(data, v, expansion[0])
		}
	}

	return data
}

// AddRequestHeader Adds a request header
//
// With this method it is possible to feed Coraza with a request header.
// Note: Golang's *http.Request object will not contain a "Host" header
// and you might have to force it
func (tx *Transaction) AddRequestHeader(key string, value string) {
	if key == "" {
		return
	}
	key = strings.ToLower(key)
	tx.GetCollection(variables.RequestHeadersNames).AddUnique("", key)
	tx.GetCollection(variables.RequestHeaders).Add(key, value)

	if key == "content-type" {
		val := strings.ToLower(value)
		if val == "application/x-www-form-urlencoded" {
			tx.GetCollection(variables.ReqbodyProcessor).Set("", []string{"URLENCODED"})
		} else if strings.HasPrefix(val, "multipart/form-data") {
			tx.GetCollection(variables.ReqbodyProcessor).Set("", []string{"MULTIPART"})
		}
	} else if key == "cookie" {
		// Cookies use the same syntax as GET params but with semicolon (;) separator
		values, err := url2.ParseQuery(value, ";")
		if err != nil {
			// if cookie parsing fails we create a urlencoded_error
			// TODO maybe we should have another variable for this
			tx.GetCollection(variables.UrlencodedError).Set("", []string{err.Error()})
			return
		}
		for k, vr := range values {
			tx.GetCollection(variables.RequestCookiesNames).AddUnique("", k)
			for _, v := range vr {
				tx.GetCollection(variables.RequestCookies).Add(k, v)
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
	key = strings.ToLower(key)
	tx.GetCollection(variables.ResponseHeadersNames).AddUnique("", key)
	tx.GetCollection(variables.ResponseHeaders).Add(key, value)

	// Most headers can be managed like that
	if key == "content-type" {
		spl := strings.SplitN(value, ";", 2)
		tx.GetCollection(variables.ResponseContentType).Set("", []string{spl[0]})
	}
}

// CaptureField is used to set the TX:[index] variables by operators
// that supports capture, like @rx
func (tx *Transaction) CaptureField(index int, value string) {
	i := strconv.Itoa(index)
	tx.GetCollection(variables.TX).Set(i, []string{value})
}

// this function is used to control which variables are reset after a new rule is evaluated
func (tx *Transaction) resetAfterRule() {
	// We reset capture 0-9
	ctx := tx.GetCollection(variables.TX)
	for i := 0; i < 10; i++ {
		si := strconv.Itoa(i)
		ctx.Set(si, []string{""})
	}
	tx.GetCollection(variables.MatchedVars).Reset()
	tx.GetCollection(variables.MatchedVarsNames).Reset()
	tx.Capture = false
}

// ParseRequestReader Parses binary request including body,
// it does only supports http/1.1 and http/1.0
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
	ct := tx.GetCollection(variables.RequestHeaders).GetFirstString("content-type")
	ct = strings.Split(ct, ";")[0]
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

// MatchVariable Creates the MATCHED_ variables required by chains and macro expansion
// MATCHED_VARS, MATCHED_VAR, MATCHED_VAR_NAME, MATCHED_VARS_NAMES
func (tx *Transaction) MatchVariable(match MatchData) {
	varname := match.Variable.Name()
	if match.Key != "" {
		varname = fmt.Sprintf("%s:%s", varname, match.Key)
	}
	// Array of values
	matchedVars := tx.GetCollection(variables.MatchedVars)
	// Last value
	matchedVar := tx.GetCollection(variables.MatchedVar)
	matchedVar.Reset()
	// Last key
	matchedVarName := tx.GetCollection(variables.MatchedVarName)
	matchedVarName.Reset()
	// Array of keys
	matchedVarsNames := tx.GetCollection(variables.MatchedVarsNames)

	matchedVars.Add("", match.Value)
	matchedVar.Set("", []string{match.Value})
	// fmt.Printf("%s: %s\n", match.VariableName, match.Value)

	matchedVarsNames.Add("", varname)
	matchedVarName.Set("", []string{varname})
}

// MatchRule Matches a rule to be logged
func (tx *Transaction) MatchRule(mr MatchedRule) {
	tx.Waf.Logger.Debug("rule matched", zap.String("txid", tx.ID), zap.Int("rule", mr.Rule.ID))
	/*
		if mr.Rule.Log && tx.Waf.ErrorLogger != nil {
			// TODO log based on severity
		}*/
	tx.MatchedRules = append(tx.MatchedRules, mr)

	// set highest_severity
	hs := tx.GetCollection(variables.HighestSeverity)
	maxSeverity, _ := types.ParseRuleSeverity(hs.GetFirstString(""))
	if mr.Rule.Severity > maxSeverity {
		hs.Set("", []string{strconv.Itoa(mr.Rule.Severity.Int())})
		tx.Waf.Logger.Debug("Set highest severity", zap.Int("severity", mr.Rule.Severity.Int()))
	}
	// Rules are matched to error log in real time
	if tx.Waf.errorLogCb != nil {
		tx.Waf.errorLogCb(mr)
	}
}

// GetStopWatch is used to debug phase durations
// Normally it should be named StopWatch() but it would be confusing
func (tx *Transaction) GetStopWatch() string {
	ts := tx.Timestamp
	sum := 0
	for _, r := range tx.StopWatches {
		sum += r
	}
	diff := time.Now().UnixNano() - ts
	sw := fmt.Sprintf("%d %d; combined=%d, p1=%d, p2=%d, p3=%d, p4=%d, p5=%d",
		ts, diff, sum, tx.StopWatches[1], tx.StopWatches[2], tx.StopWatches[3], tx.StopWatches[4], tx.StopWatches[5])
	return sw
}

// GetField Retrieve data from collections applying exceptions
// In future releases we may remove de exceptions slice and
// make it easier to use
func (tx *Transaction) GetField(rv ruleVariableParams) []MatchData {
	collection := rv.Variable
	col := tx.GetCollection(collection)
	if col == nil {
		return []MatchData{}
	}

	matches := []MatchData{}
	// In this case we are going to use the bodyprocessor to get the data
	// It requires the VariableHook() function to match the current variable
	if tx.bodyProcessor != nil && tx.bodyProcessor.VariableHook() == collection {
		m, err := tx.bodyProcessor.Find(rv.KeyStr)
		if err != nil {
			tx.Waf.Logger.Error("error getting variable", zap.String("collection", collection.Name()),
				zap.String("key", rv.KeyStr), zap.Error(err))
			return []MatchData{}
		}
		if len(m) == 0 {
			return []MatchData{}
		}
		for key, values := range m {
			for _, value := range values {
				matches = append(matches, MatchData{
					VariableName: collection.Name(),
					Variable:     collection,
					Key:          key,
					Value:        value,
				})
			}
		}
	} else {
		// in case we are not using a variablehook
		// Now that we have access to the collection, we can apply the exceptions
		if rv.KeyRx == nil {
			matches = col.FindString(rv.KeyStr)
		} else {
			matches = col.FindRegex(rv.KeyRx)
		}
	}

	rmi := []int{}
	for i, c := range matches {
		for _, ex := range rv.Exceptions {
			// in case it matches the regex or the keystr
			if (ex.KeyRx != nil && ex.KeyRx.MatchString(c.Key)) || ex.KeyStr == c.Key {
				tx.Waf.Logger.Debug("Variable exception triggered", zap.String("var", rv.Variable.Name()),
					zap.String("key", ex.KeyStr), zap.String("txid", tx.ID), zap.String("match", c.Key),
					zap.Bool("regex", ex.KeyRx != nil))
				// we remove the exception from the list of values
				// we tried with standard append but it fails... let's do some hacking
				// m2 := append(matches[:i], matches[i+1:]...)
				rmi = append(rmi, i)
			}
		}
	}
	// we read the list of indexes backwards
	// then we remove each one of them
	for i := len(rmi) - 1; i >= 0; i-- {
		matches = append(matches[:rmi[i]], matches[rmi[i]+1:]...)
	}
	if rv.Count {
		count := len(matches)
		matches = []MatchData{
			{
				VariableName: collection.Name(),
				Variable:     collection,
				Key:          rv.KeyStr,
				Value:        strconv.Itoa(count),
			},
		}
		tx.Waf.Logger.Debug("Transforming match to count", zap.String("tx", tx.ID),
			zap.String("count", matches[0].Value))
	}
	return matches
}

// GetCollection transforms a VARIABLE_ constant into a
// *Collection used to get VARIABLES data
func (tx *Transaction) GetCollection(variable variables.RuleVariable) *Collection {
	return tx.collections[variable]
}

// savePersistentData save persistent collections to persistence engine
func (tx *Transaction) savePersistentData() {
	// TODO, disabled by now, maybe we should add persistent variables to the
	// collection struct, something like col.Persist("key")
	// pers := []byte{VARIABLE_SESSION, VARIABLE_IP}
	/*
		pers := []byte{}
		for _, v := range pers {
			col := tx.GetCollection(v)
			if col == nil || col.PersistenceKey != "" {
				continue
			}
			data := col.Data()
			// key := col.PersistenceKey
			upc, _ := strconv.Atoi(data["UPDATE_COUNTER"][0])
			upc++
			ct, _ := strconv.ParseInt(data["CREATE_TIME"][0], 10, 64)
			rate := strconv.FormatInt(ct/(int64(ct)*1000), 10)
			ts := time.Now().UnixNano()
			tss := strconv.FormatInt(ts, 10)
			to := ts + int64(tx.Waf.CollectionTimeout)*1000
			timeout := strconv.FormatInt(to, 10)
			data["IS_NEW"] = []string{"0"}
			data["UPDATE_COUNTER"] = []string{strconv.Itoa(upc)}
			data["UPDATE_RATE"] = []string{rate}
			// TODO timeout should only be updated when the collection was modified
			// but the current design isn't compatible
			// New version may have multiple collection types allowing us to identify this cases
			data["TIMEOUT"] = []string{timeout}
			data["LAST_UPDATE_TIME"] = []string{tss}
			// tx.Waf.Persistence.Save(v, key, data)
		}
	*/
}

// RemoveRuleTargetByID Removes the VARIABLE:KEY from the rule ID
// It's mostly used by CTL to dinamically remove targets from rules
func (tx *Transaction) RemoveRuleTargetByID(id int, variable variables.RuleVariable, key string) {
	c := ruleVariableParams{
		Variable: variable,
		KeyStr:   key,
	}
	// Used if it's empty
	if tx.ruleRemoveTargetByID[id] == nil {
		tx.ruleRemoveTargetByID[id] = []ruleVariableParams{
			c,
		}
	} else {
		tx.ruleRemoveTargetByID[id] = append(tx.ruleRemoveTargetByID[id], c)
	}
}

// RemoveRuleByID Removes a rule from the transaction
// It does not affect the WAF rules
func (tx *Transaction) RemoveRuleByID(id int) {
	tx.ruleRemoveByID = append(tx.ruleRemoveByID, id)
}

// ProcessRequest fills all transaction variables from an http.Request object
// Most implementations of Coraza will probably use http.Request objects
// so this will implement all phase 0, 1 and 2 variables
// Note: This function will stop after an interruption
// Note: Do not manually fill any request variables
func (tx *Transaction) ProcessRequest(req *http.Request) (*types.Interruption, error) {
	var client string
	cport := 0
	// IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
	spl := strings.Split(req.RemoteAddr, ":")
	if len(spl) > 1 {
		client = strings.Join(spl[0:len(spl)-1], "")
		cport, _ = strconv.Atoi(spl[len(spl)-1])
	}
	var in *types.Interruption
	// There is no socket access in the request object so we don't know the server client or port
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}
	// Host will always be removed from req.Headers(), so we manually add it
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
	}

	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}
	if req.Body != nil {
		_, err := io.Copy(tx.RequestBodyBuffer, req.Body)
		if err != nil {
			return tx.Interruption, err
		}
		reader := tx.RequestBodyBuffer.Reader()
		req.Body = io.NopCloser(reader)
	}
	return tx.ProcessRequestBody()
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
	// 	tx.GetCollection(VARIABLE_REMOTE_HOST).Set("", []string{addr[0]})
	// }else{
	// 	tx.GetCollection(VARIABLE_REMOTE_HOST).Set("", []string{client})
	// }

	tx.GetCollection(variables.RemoteAddr).Set("", []string{client})
	tx.GetCollection(variables.RemotePort).Set("", []string{p})
	tx.GetCollection(variables.ServerAddr).Set("", []string{server})
	tx.GetCollection(variables.ServerPort).Set("", []string{p2})
}

// ExtractArguments transforms an url encoded string to a map and creates
// ARGS_POST|GET
func (tx *Transaction) ExtractArguments(orig string, uri string) {
	sep := "&"
	if tx.Waf.ArgumentSeparator != "" {
		sep = tx.Waf.ArgumentSeparator
	}
	data, err := url2.ParseQuery(uri, sep)
	// we create a URLENCODED_ERROR if we fail to parse the URL
	if err != nil {
		tx.GetCollection(variables.UrlencodedError).Set("", []string{err.Error()})
	}
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
	var vals, names variables.RuleVariable
	if orig == "GET" {
		vals = variables.ArgsGet
		names = variables.ArgsGetNames
	} else {
		vals = variables.ArgsPost
		names = variables.ArgsPostNames
	}
	tx.GetCollection(variables.Args).Add(key, value)
	tx.GetCollection(variables.ArgsNames).Add("", key)

	tx.GetCollection(vals).Add(key, value)
	tx.GetCollection(names).Add("", key)

	col := tx.GetCollection(variables.ArgsCombinedSize)
	i := col.GetFirstInt64("") + int64(len(key)+len(value))
	istr := strconv.FormatInt(i, 10)
	col.Set("", []string{istr})
}

// ProcessURI Performs the analysis on the URI and all the query string variables.
// This method should be called at very beginning of a request process, it is
// expected to be executed prior to the virtual host resolution, when the
// connection arrives on the server.
// note: There is no direct connection between this function and any phase of
//       the SecLanguages phases. It is something that may occur between the
//       SecLanguage phase 1 and 2.
// note: This function won't add GET arguments, they must be added with AddArgument
func (tx *Transaction) ProcessURI(uri string, method string, httpVersion string) {
	tx.GetCollection(variables.RequestMethod).Set("", []string{method})
	tx.GetCollection(variables.RequestProtocol).Set("", []string{httpVersion})
	tx.GetCollection(variables.RequestURIRaw).Set("", []string{uri})

	// TODO modsecurity uses HTTP/${VERSION} instead of just version, let's check it out
	tx.GetCollection(variables.RequestLine).Set("", []string{fmt.Sprintf("%s %s %s", method, uri, httpVersion)})

	var err error

	// we remove anchors
	if in := strings.Index(uri, "#"); in != -1 {
		uri = uri[:in]
	}
	path := ""
	parsedURL, err := url.Parse(uri)
	query := ""
	if err != nil {
		tx.GetCollection(variables.UrlencodedError).Set("", []string{err.Error()})
		path = uri
		tx.GetCollection(variables.RequestURI).Set("", []string{uri})
		/*
			tx.GetCollection(VARIABLE_URI_PARSE_ERROR).Set("", []string{"1"})
			posRawQuery := strings.Index(uri, "?")
			if posRawQuery != -1 {
				tx.ExtractArguments("GET", uri[posRawQuery+1:])
				path = uri[:posRawQuery]
				query = uri[posRawQuery+1:]
			} else {
				path = uri
			}
			tx.GetCollection(variables.RequestUri).Set("", []string{uri})
		*/
	} else {
		tx.ExtractArguments("GET", parsedURL.RawQuery)
		tx.GetCollection(variables.RequestURI).Set("", []string{parsedURL.String()})
		path = parsedURL.Path
		query = parsedURL.RawQuery
	}
	offset := strings.LastIndexAny(path, "/\\")
	if offset != -1 && len(path) > offset+1 {
		tx.GetCollection(variables.RequestBasename).Set("", []string{path[offset+1:]})
	} else {
		tx.GetCollection(variables.RequestBasename).Set("", []string{path})
	}
	tx.GetCollection(variables.RequestFilename).Set("", []string{path})

	tx.GetCollection(variables.QueryString).Set("", []string{query})
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
	tx.Waf.Rules.Eval(types.PhaseRequestHeaders, tx)
	return tx.Interruption
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
	if !tx.RequestBodyAccess {
		tx.Waf.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.Interruption, nil
	}
	mime := ""
	if m := tx.GetCollection(variables.RequestHeaders).Get("content-type"); len(m) > 0 {
		mime = m[0]
	}

	reader := tx.RequestBodyBuffer.Reader()

	// Chunked requests will always be written to a temporary file
	if tx.RequestBodyBuffer.Size() >= tx.RequestBodyLimit {
		if tx.Waf.RequestBodyLimitAction == types.RequestBodyLimitActionReject {
			// We interrupt this transaction in case RequestBodyLimitAction is Reject
			tx.Interruption = &types.Interruption{
				Status: 403,
				Action: "deny",
			}
			return tx.Interruption, nil
		} else if tx.Waf.RequestBodyLimitAction == types.RequestBodyLimitActionProcessPartial {
			tx.GetCollection(variables.InboundErrorData).Set("", []string{"1"})
			// we limit our reader to tx.RequestBodyLimit bytes
			reader = io.LimitReader(reader, tx.RequestBodyLimit)
		}
	}
	rbp := tx.GetCollection(variables.ReqbodyProcessor).GetFirstString("")

	// Default variables.ReqbodyProcessor values
	// XML and JSON must be forced with ctl:requestBodyProcessor=JSON
	if rbp == "" && tx.ForceRequestBodyVariable {
		// We force URLENCODED if mime is x-www... or we have an empty RBP and ForceRequestBodyVariable
		rbp = "URLENCODED"
		tx.GetCollection(variables.ReqbodyProcessor).Set("", []string{rbp})
	}
	tx.Waf.Logger.Debug("Attempting to process request body", zap.String("txid", tx.ID),
		zap.String("bodyprocessor", rbp))
	rbp = strings.ToLower(rbp)
	if rbp == "" {
		// so there is no bodyprocessor, we don't want to generate an error
		tx.Waf.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.Interruption, nil
	}
	bodyprocessor, err := bodyprocessors.GetBodyProcessor(rbp)
	if err != nil {
		tx.generateReqbodyError(err)
		tx.Waf.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.Interruption, nil
	}
	if err := bodyprocessor.Read(reader, mime, tx.Waf.UploadDir); err != nil {
		tx.generateReqbodyError(err)
		tx.Waf.Rules.Eval(types.PhaseRequestBody, tx)
		return tx.Interruption, nil
	}
	tx.bodyProcessor = bodyprocessor
	// we insert the collections from the bodyprocessor into the collections map
	for k, m := range tx.bodyProcessor.Collections() {
		if k == variables.Args {
			// for ARGS we make a different process, as ARGS are POST + GET and it requires ARGS_COMBINED_SIZE
			size := 0
			for _, vv := range m {
				for _, v := range vv {
					size += len(v)
				}
			}
			tx.GetCollection(variables.ArgsCombinedSize).Set("", []string{strconv.Itoa(size)})
			// in case we receive Args, we must add manually the args and argsnames, otherwise it will be overwritten
			for kk, vv := range m {
				tx.GetCollection(variables.Args).Set(kk, vv)
				tx.GetCollection(variables.ArgsNames).AddUnique("", kk)
			}
		} else {
			for mk, mv := range m {
				tx.GetCollection(k).Set(mk, mv)
			}
		}
	}

	tx.Waf.Rules.Eval(types.PhaseRequestBody, tx)
	return tx.Interruption, nil
}

// ProcessResponseHeaders Perform the analysis on the response readers.
//
// This method perform the analysis on the response headers, notice however
// that the headers should be added prior to the execution of this function.
//
// note: Remember to check for a possible intervention.
//
func (tx *Transaction) ProcessResponseHeaders(code int, proto string) *types.Interruption {
	c := strconv.Itoa(code)
	tx.GetCollection(variables.ResponseStatus).Set("", []string{c})
	tx.GetCollection(variables.ResponseProtocol).Set("", []string{proto})

	if tx.RuleEngine == types.RuleEngineOff {
		return nil
	}

	tx.Waf.Rules.Eval(types.PhaseResponseHeaders, tx)
	return tx.Interruption
}

// IsProcessableResponseBody returns true if the response body meets the
// criteria to be processed, response headers must be set before this.
// The content-type response header must be in the SecRequestBodyMime
// This is used by webservers to choose whether tostream response buffers
// directly to the client or write them to Coraza
func (tx *Transaction) IsProcessableResponseBody() bool {
	// TODO add more validations
	ct := tx.GetCollection(variables.ResponseContentType).GetFirstString("")
	return utils.InSlice(ct, tx.Waf.ResponseBodyMimeTypes)
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
		tx.Waf.Rules.Eval(types.PhaseResponseBody, tx)
		return tx.Interruption, nil
	}
	reader := tx.ResponseBodyBuffer.Reader()
	reader = io.LimitReader(reader, tx.Waf.ResponseBodyLimit)
	buf := new(strings.Builder)
	length, _ := io.Copy(buf, reader)

	tx.GetCollection(variables.ResponseContentLength).Set("", []string{strconv.FormatInt(length, 10)})
	tx.GetCollection(variables.ResponseBody).Set("", []string{buf.String()})
	tx.Waf.Rules.Eval(types.PhaseResponseBody, tx)
	return tx.Interruption, nil
}

// ProcessLogging Logging all information relative to this transaction.
//
// At this point there is not need to hold the connection, the response can be
// delivered prior to the execution of this method.
func (tx *Transaction) ProcessLogging() {
	// I'm not sure why but modsecurity won't log if RuleEngine is disabled
	// if tx.RuleEngine == RULE_ENGINE_OFF {
	// 	return
	// }
	defer func() {
		tx.savePersistentData()
		tx.RequestBodyBuffer.Close()
		tx.ResponseBodyBuffer.Close()
		tx.Waf.Logger.Debug("Transaction finished", zap.String("event", "FINISH_TRANSACTION"), zap.String("txid", tx.ID), zap.Bool("interrupted", tx.Interrupted()))
	}()

	tx.Waf.Rules.Eval(types.PhaseLogging, tx)

	if tx.AuditEngine == types.AuditEngineOff {
		// Audit engine disabled
		tx.Waf.Logger.Debug("Transaction not marked for audit logging, AuditEngine is disabled",
			zap.String("tx", tx.ID),
		)
		return
	}

	if tx.AuditEngine == types.AuditEngineRelevantOnly && !tx.Log {
		re := tx.Waf.AuditLogRelevantStatus
		status := tx.GetCollection(variables.ResponseStatus).GetFirstString("")
		if re != nil && !re.Match([]byte(status)) {
			// Not relevant status
			tx.Waf.Logger.Debug("Transaction status not marked for audit logging",
				zap.String("tx", tx.ID),
			)
			return
		}
	}

	tx.Waf.Logger.Debug("Transaction marked for audit logging",
		zap.String("tx", tx.ID),
	)
	if tx.Waf.AuditLogger() != nil {
		// we don't log if there is an empty auditlogger
		if err := tx.Waf.AuditLogger().Write(tx.AuditLog()); err != nil {
			tx.Waf.Logger.Error(err.Error())
		}
	}
}

// Interrupted will return true if the transaction was interrupted
func (tx *Transaction) Interrupted() bool {
	return tx.Interruption != nil
}

// AuditLog returns an AuditLog struct, used to write audit logs
func (tx *Transaction) AuditLog() loggers.AuditLog {
	al := loggers.AuditLog{}
	parts := tx.AuditLogParts
	al.Messages = []loggers.AuditMessage{}
	// YYYY/MM/DD HH:mm:ss
	ts := time.Unix(0, tx.Timestamp).Format("2006/01/02 15:04:05")
	al.Transaction = loggers.AuditTransaction{
		Timestamp:     ts,
		UnixTimestamp: tx.Timestamp,
		ID:            tx.ID,
		ClientIP:      tx.GetCollection(variables.RemoteAddr).GetFirstString(""),
		ClientPort:    tx.GetCollection(variables.RemotePort).GetFirstInt(""),
		HostIP:        tx.GetCollection(variables.ServerAddr).GetFirstString(""),
		HostPort:      tx.GetCollection(variables.ServerPort).GetFirstInt(""),
		ServerID:      tx.GetCollection(variables.ServerName).GetFirstString(""), // TODO check
		Request: loggers.AuditTransactionRequest{
			Method:      tx.GetCollection(variables.RequestMethod).GetFirstString(""),
			Protocol:    tx.GetCollection(variables.RequestProtocol).GetFirstString(""),
			URI:         tx.GetCollection(variables.RequestURI).GetFirstString(""),
			HTTPVersion: tx.GetCollection(variables.RequestProtocol).GetFirstString(""),
			// Body and headers are audit variables.RequestUriRaws
		},
		Response: loggers.AuditTransactionResponse{
			Status: tx.GetCollection(variables.ResponseStatus).GetFirstInt(""),
			// body and headers are audit parts
		},
	}
	rengine := tx.RuleEngine.String()

	for _, p := range parts {
		switch p {
		case 'B':
			al.Transaction.Request.Headers = tx.GetCollection(variables.RequestHeaders).Data()
		case 'C':
			al.Transaction.Request.Body = tx.GetCollection(variables.RequestBody).GetFirstString("")
			// TODO maybe change to:
			// al.Transaction.Request.Body = tx.RequestBodyBuffer.String()
		case 'F':
			al.Transaction.Response.Headers = tx.GetCollection(variables.ResponseHeaders).Data()
		case 'G':
			al.Transaction.Response.Body = tx.GetCollection(variables.ResponseBody).GetFirstString("")
		case 'H':
			al.Transaction.Producer = loggers.AuditTransactionProducer{
				Connector:  "unknown", // TODO maybe add connector variable to Waf
				Version:    "unknown",
				Server:     "",
				RuleEngine: rengine,
				Stopwatch:  tx.GetStopWatch(),
				Rulesets:   tx.Waf.ComponentNames,
			}
		case 'I':
			/*
			* TODO:
			* This part is a replacement for part C. It will log the same data as C in
			* all cases except when multipart/form-data encoding in used. In this case,
			* it will log a fake application/x-www-form-urlencoded body that contains
			* the information about parameters but not about the files. This is handy
			* if you don’t want to have (often large) files stored in your audit logs.
			 */
		case 'J':
			// upload data
			files := []loggers.AuditTransactionRequestFiles{}
			al.Transaction.Request.Files = []loggers.AuditTransactionRequestFiles{}
			for i, name := range tx.GetCollection(variables.Files).Get("") {
				// TODO we kind of assume there is a file_size for each file with the same index
				size, _ := strconv.ParseInt(tx.GetCollection(variables.FilesSizes).Get("")[i], 10, 64)
				ext := filepath.Ext(name)
				at := loggers.AuditTransactionRequestFiles{
					Size: size,
					Name: name,
					Mime: mime.TypeByExtension(ext),
				}
				files = append(files, at)
			}
			al.Transaction.Request.Files = files
		case 'K':
			mrs := []loggers.AuditMessage{}
			for _, mr := range tx.MatchedRules {
				r := mr.Rule
				mrs = append(mrs, loggers.AuditMessage{
					Actionset: strings.Join(tx.Waf.ComponentNames, " "),
					Message:   tx.Logdata,
					Data: loggers.AuditMessageData{
						File:     mr.Rule.File,
						Line:     mr.Rule.Line,
						ID:       r.ID,
						Rev:      r.Rev,
						Msg:      mr.Message,
						Data:     mr.Data,
						Severity: r.Severity,
						Ver:      r.Version,
						Maturity: r.Maturity,
						Accuracy: r.Accuracy,
						Tags:     r.Tags,
						Raw:      r.Raw,
					},
				})
			}
			al.Messages = mrs
		}
	}
	return al
}

// generateReqbodyError generates all of the error variables for the request body parser
func (tx *Transaction) generateReqbodyError(err error) {
	tx.GetCollection(variables.ReqbodyError).Set("", []string{"1"})
	tx.GetCollection(variables.ReqbodyErrorMsg).Set("", []string{string(err.Error())})
	tx.GetCollection(variables.ReqbodyProcessorError).Set("", []string{"1"})
	tx.GetCollection(variables.ReqbodyProcessorErrorMsg).Set("", []string{string(err.Error())})
}
