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

package coraza

import (
	"bufio"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/antchfx/jsonquery"
	"github.com/antchfx/xmlquery"
	"github.com/jptosso/coraza-waf/loggers"
	"github.com/jptosso/coraza-waf/utils"
	"go.uber.org/zap"
)

type Interruption struct {
	// Rule that caused the interruption
	RuleId int

	// drop, deny, redirect
	Action string

	// Force this status code
	Status int

	// Parameters used by proxy and redirect
	Data string
}

// MatchedRule contains a list of macro expanded messages,
// matched variables and a pointer to the rule
type MatchedRule struct {
	// A single rule may contain multiple messages from chains
	Messages []string
	// A slice of matched variables
	MatchedData []MatchData
	// A pointer to the triggered rule
	Rule Rule
}

// MatchData works like VariableKey but is used for logging
// so it contains the collection as a string and it's value
type MatchData struct {
	// Variable name as a string
	Collection string
	// Key of the variable, blank if no key is required
	Key string
	// Value of the current VARIABLE:KEY
	Value string
}

// VariableKey is used to store Variables with it's key, for example:
// ARGS:id would be the same as {VARIABLE_ARGS, "id"}
type VariableKey struct {
	// Contains the variable
	Collection byte
	// Contains the key of the variable
	Key string
}

type Transaction struct {
	// If true the transaction is going to be logged, it won't log if IsRelevantStatus() fails
	Log bool

	//Transaction Id
	Id string

	// Contains the list of matched rules and associated match information
	MatchedRules []MatchedRule

	//True if the transaction has been disrupted by any rule
	Interruption *Interruption

	// Contains all collections, including persistent
	collections []*Collection

	//Response data to be sent
	Status int

	// This is used to store log messages
	Logdata string

	// Rules will be skipped after a rule with this SecMarker is found
	SkipAfter string

	// Copies from the WafInstance that may be overwritten by the ctl action
	AuditEngine              int
	AuditLogParts            []rune
	ForceRequestBodyVariable bool
	RequestBodyAccess        bool
	RequestBodyLimit         int64
	RequestBodyProcessor     int
	ResponseBodyAccess       bool
	ResponseBodyLimit        int64
	RuleEngine               int
	HashEngine               bool
	HashEnforcement          bool

	// Stores the last phase that was evaluated
	// Used by allow to skip phases
	LastPhase Phase

	// Handles request body buffers
	RequestBodyBuffer *BodyBuffer

	// Handles response body buffers
	ResponseBodyBuffer *BodyBuffer

	// Rules with this id are going to be skipped while processing a phase
	RuleRemoveById []int

	// Used by ctl to remove rule targets by id during the transaction
	// All other "target removers" like "ByTag" are an abstraction of "ById"
	// For example, if you want to remove REQUEST_HEADERS:User-Agent from rule 85:
	// {85: {VARIABLE_REQUEST_HEADERS, "user-agent"}}
	RuleRemoveTargetById map[int][]VariableKey

	// Will skip this number of rules, this value will be decreased on each skip
	Skip int

	// Actions with capture features will read the capture state from this field
	// We have currently removed this feature as Capture will always run
	// We must reuse it in the future
	Capture bool

	// Contains duration in useconds per phase
	StopWatches map[Phase]int

	// Contains de *engine.Waf instance for the current transaction
	Waf *Waf

	// In case of an XML request body we will cache the XML object here
	xmlDoc  *xmlquery.Node
	jsonDoc *jsonquery.Node

	// Timestamp of the request
	Timestamp int64

	// Used internaly to build the HIGHEST_SEVERITY variable
	highestSeverity int
}

// Used to test macro expansions
var macroRegexp = regexp.MustCompile(`%\{([\w.-]+?)\}`)

// MacroExpansion expands a string that contains %{somevalue.some-key}
// into it's first value, for example:
// 	v1 := tx.MacroExpansion("%{request_headers.user-agent")
//  v2 := tx.GetCollection(VARIABLE_REQUEST_HEADERS).GetFirstString("user-agent")
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
		col, err := NameToVariable(strings.ToLower(matchspl[0]))
		if err != nil {
			//Invalid collection
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
	tx.GetCollection(VARIABLE_REQUEST_HEADERS_NAMES).AddUnique("", key)
	tx.GetCollection(VARIABLE_REQUEST_HEADERS).Add(key, value)

	if key == "content-type" {
		val := strings.ToLower(value)
		if val == "application/x-www-form-urlencoded" {
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR).Set("", []string{"URLENCODED"})
		} else if strings.HasPrefix(val, "multipart/form-data") {
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR).Set("", []string{"MULTIPART"})
		}
	} else if key == "host" {
		tx.GetCollection(VARIABLE_SERVER_NAME).Set("", []string{value})
	} else if key == "cookie" {
		// Cookies use the same syntax as GET params but with semicolon (;) separator
		values := utils.ParseQuery(value, ";")
		for k, vr := range values {
			tx.GetCollection(VARIABLE_REQUEST_COOKIES_NAMES).AddUnique("", k)
			for _, v := range vr {
				tx.GetCollection(VARIABLE_REQUEST_COOKIES).Add(k, v)
			}
		}
	}
}

// SetFullRequest Creates the FULL_REQUEST variable based on every input
// It's a heavy operation and it's not used by OWASP CRS so it's optional
func (tx *Transaction) SetFullRequest() {
	headers := ""
	for k, v := range tx.GetCollection(VARIABLE_REQUEST_HEADERS).Data() {
		if k == "" {
			continue
		}
		for _, v2 := range v {
			headers += fmt.Sprintf("%s: %s\n", k, v2)
		}
	}
	full_request := fmt.Sprintf("%s\n%s\n\n%s\n",
		tx.GetCollection(VARIABLE_REQUEST_LINE).GetFirstString(""),
		headers,
		tx.GetCollection(VARIABLE_REQUEST_BODY).GetFirstString(""))
	tx.GetCollection(VARIABLE_FULL_REQUEST).Set("", []string{full_request})
}

// AddResponseHeader Adds a response header variable
//
// With this method it is possible to feed Coraza with a response header.
func (tx *Transaction) AddResponseHeader(key string, value string) {
	if key == "" {
		return
	}
	key = strings.ToLower(key)
	tx.GetCollection(VARIABLE_RESPONSE_HEADERS_NAMES).AddUnique("", key)
	tx.GetCollection(VARIABLE_RESPONSE_HEADERS).Add(key, value)

	//Most headers can be managed like that
	if key == "content-type" {
		spl := strings.SplitN(value, ";", 2)
		tx.GetCollection(VARIABLE_RESPONSE_CONTENT_TYPE).Set("", []string{spl[0]})
	}
}

// CaptureField is used to set the TX:[index] variables by operators
// that supports capture, like @rx
func (tx *Transaction) CaptureField(index int, value string) {
	i := strconv.Itoa(index)
	tx.GetCollection(VARIABLE_TX).Set(i, []string{value})
}

// ResetCapture Resets the captured variables for further uses
// Captures variables must be always reset before capturing again
func (tx *Transaction) ResetCapture() {
	//We reset capture 0-9
	ctx := tx.GetCollection(VARIABLE_TX)
	for i := 0; i < 10; i++ {
		si := strconv.Itoa(i)
		ctx.Set(si, []string{""})
	}
}

// ParseRequestReader Parses binary request including body,
// it does only supports http/1.1 and http/1.0
// This function does not run ProcessConnection
// This function will store in memory the whole reader,
// DON't USE IT FOR PRODUCTION yet
func (tx *Transaction) ParseRequestReader(data io.Reader) (*Interruption, error) {
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
	tx.ProcessUri(spl[1], spl[0], spl[2])
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
	ct := tx.GetCollection(VARIABLE_REQUEST_HEADERS).GetFirstString("content-type")
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

// MatchVars Creates the MATCHED_ variables required by chains and macro expansion
// MATCHED_VARS, MATCHED_VAR, MATCHED_VAR_NAME, MATCHED_VARS_NAMES
func (tx *Transaction) MatchVars(match []MatchData) {
	// Array of values
	mvs := tx.GetCollection(VARIABLE_MATCHED_VARS)
	mvs.Reset()
	// Last value
	mv := tx.GetCollection(VARIABLE_MATCHED_VAR)
	mv.Reset()
	// Last key
	mvn := tx.GetCollection(VARIABLE_MATCHED_VAR_NAME)
	mvn.Reset()
	// Array of keys
	mvns := tx.GetCollection(VARIABLE_MATCHED_VARS_NAMES)
	mvns.Reset()

	mvs.Set("", []string{})
	for _, mm := range match {
		colname := strings.ToUpper(mm.Collection)
		if mm.Key != "" {
			colname = fmt.Sprintf("%s:%s", colname, mm.Key)
		}
		mvs.Add("", mm.Value)
		mv.Set("", []string{mm.Value})

		mvns.Add("", colname)
		mvn.Set("", []string{colname})
	}
}

// MatchRule Matches a rule to be logged
func (tx *Transaction) MatchRule(rule Rule, msgs []string, match []MatchData) {
	if rule.Log && tx.Waf.ErrorLogger != nil {
		str := strings.Builder{}
		str.WriteString("Warning. ")
		variable := match[0].Collection
		if match[0].Key != "" {
			variable += fmt.Sprintf(":%s", match[0].Key)
		}
		if rule.Operator != nil {
			str.WriteString(fmt.Sprintf("Match of \"- %s\" against %q required. ", rule.Operator.Data, variable))
		} else {
			//TODO check msg
			str.WriteString("Unconditional match. ")
		}
		str.WriteString(fmt.Sprintf("[file %q] ", rule.File))
		str.WriteString(fmt.Sprintf("[line \"%d\"] ", rule.Line))
		str.WriteString(fmt.Sprintf("[id \"%d\"] ", rule.Id))
		str.WriteString(fmt.Sprintf("[msg %q] ", msgs[0]))
		str.WriteString(fmt.Sprintf("[data %q]", tx.MacroExpansion(rule.LogData)))
		if rule.Severity != -1 {
			severity := "someseverity"
			str.WriteString(fmt.Sprintf(" [severity %q]", severity))
		}
		switch EventSeverity(rule.Severity) {
		case EventEmergency:
			tx.Waf.ErrorLogger.Emergency(str.String())
		case EventAlert:
			tx.Waf.ErrorLogger.Alert(str.String())
		case EventCritical:
			tx.Waf.ErrorLogger.Critical(str.String())
		case EventError:
			tx.Waf.ErrorLogger.Error(str.String())
		case EventWarning:
			tx.Waf.ErrorLogger.Warning(str.String())
		case EventNotice:
			tx.Waf.ErrorLogger.Notice(str.String())
		case EventInfo:
			tx.Waf.ErrorLogger.Info(str.String())
		case EventDebug:
			tx.Waf.ErrorLogger.Debug(str.String())
		default:
			//TODO
		}
	}
	tx.Waf.Logger.Debug("rule matched", zap.String("txid", tx.Id), zap.Int("rule", rule.Id), zap.Int("count", len(match)))
	mr := MatchedRule{
		Messages:    msgs,
		MatchedData: match,
		Rule:        rule,
	}
	tx.MatchedRules = append(tx.MatchedRules, mr)

	// set highest_severity
	hs := tx.GetCollection(VARIABLE_HIGHEST_SEVERITY)
	maxSeverity := hs.GetFirstInt("")
	if rule.Severity > maxSeverity {
		hs.Set("", []string{strconv.Itoa(rule.Severity)})
		tx.Waf.Logger.Debug("Set highest severity", zap.Int("severity", rule.Severity))
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
// This function will apply xpath if the variable is XML
// In future releases we may remove de exceptions slice and
// make it easier to use
func (tx *Transaction) GetField(rv RuleVariable, exceptions []string) []MatchData {
	collection := rv.Collection
	key := rv.Key
	re := rv.Regex
	if collection == VARIABLE_XML {
		if tx.xmlDoc == nil {
			return []MatchData{}
		}
		data, err := xmlquery.QueryAll(tx.xmlDoc, key)
		if err != nil {
			return []MatchData{}
		}
		res := []MatchData{}
		for _, d := range data {
			//TODO im not sure if its ok but nvm:
			// According to Modsecurity handbook modsecurity builds a collection
			// that contains all iterations of the matched elements
			// doesn't seem too efficient, we are going to modify that
			// also I don't like xmlquery
			output := html.UnescapeString(d.OutputXML(true))
			res = append(res, MatchData{
				Collection: "xml",
				Key:        key,
				Value:      output,
			})
		}
		return res
	} else if collection == VARIABLE_JSON {
		if tx.jsonDoc == nil {
			return []MatchData{}
		}
		data, err := jsonquery.QueryAll(tx.jsonDoc, key)
		if err != nil {
			return []MatchData{}
		}
		res := []MatchData{}
		for _, d := range data {
			//TODO im not sure if its ok but nvm:
			// According to Modsecurity handbook modsecurity builds a collection
			// that contains all iterations of the matched elements
			// doesn't seem too efficient, we are going to modify that
			// also I don't like xmlquery
			output := html.UnescapeString(d.InnerText())
			res = append(res, MatchData{
				Collection: "json",
				Key:        key,
				Value:      output,
			})
		}
		return res
	} else {
		col := tx.GetCollection(collection)
		key = tx.MacroExpansion(key)
		if col == nil {
			return []MatchData{}
		}
		return col.Find(key, re, exceptions)
	}

}

// GetCollection transforms a VARIABLE_ constant into a
// *Collection used to get VARIABLES data
func (tx *Transaction) GetCollection(variable byte) *Collection {
	return tx.collections[variable]
}

// GetCollections is used to debug collections, it maps
// the Collection slice into a map of variable names and collections
func (tx *Transaction) GetCollections() map[string]*Collection {
	cols := map[string]*Collection{}
	for i, col := range tx.collections {
		v := VariableToName(byte(i))
		cols[v] = col
	}
	return cols
}

// savePersistentData save persistent collections to persistence engine
func (tx *Transaction) savePersistentData() {
	//TODO, disabled by now, maybe we should add persistent variables to the
	// collection struct, something like col.Persist("key")
	//pers := []byte{VARIABLE_SESSION, VARIABLE_IP}
	/*
		pers := []byte{}
		for _, v := range pers {
			col := tx.GetCollection(v)
			if col == nil || col.PersistenceKey != "" {
				continue
			}
			data := col.Data()
			//key := col.PersistenceKey
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
			//tx.Waf.Persistence.Save(v, key, data)
		}
	*/
}

// RemoveRuleTargetById Removes the VARIABLE:KEY from the rule ID
// It's mostly used by CTL to dinamically remove targets from rules
func (tx *Transaction) RemoveRuleTargetById(id int, col byte, key string) {
	c := VariableKey{col, key}
	if tx.RuleRemoveTargetById[id] == nil {
		tx.RuleRemoveTargetById[id] = []VariableKey{
			c,
		}
	} else {
		tx.RuleRemoveTargetById[id] = append(tx.RuleRemoveTargetById[id], c)
	}
}

// ProcessRequest
// Fill all transaction variables from an http.Request object
// Most implementations of Coraza will probably use http.Request objects
// so this will implement all phase 0, 1 and 2 variables
// Note: This function will stop after an interruption
// Note: Do not manually fill any request variables
func (tx *Transaction) ProcessRequest(req *http.Request) (*Interruption, error) {
	var client string
	cport := 0
	//IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
	spl := strings.Split(req.RemoteAddr, ":")
	if len(spl) > 1 {
		client = strings.Join(spl[0:len(spl)-1], "")
		cport, _ = strconv.Atoi(spl[len(spl)-1])
	}
	var in *Interruption
	// There is no socket access in the request object so we don't know the server client or port
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessUri(req.URL.String(), req.Method, req.Proto)
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

	tx.GetCollection(VARIABLE_REMOTE_ADDR).Set("", []string{client})
	tx.GetCollection(VARIABLE_REMOTE_PORT).Set("", []string{p})
	tx.GetCollection(VARIABLE_SERVER_ADDR).Set("", []string{server})
	tx.GetCollection(VARIABLE_SERVER_PORT).Set("", []string{p2})
}

// ExtractArguments transforms an url encoded string to a map and creates
// ARGS_POST|GET
func (tx *Transaction) ExtractArguments(orig string, uri string) {
	sep := "&"
	if tx.Waf.ArgumentSeparator != "" {
		sep = tx.Waf.ArgumentSeparator
	}
	data := utils.ParseQuery(uri, sep)
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
	var vals, names byte
	if orig == "GET" {
		vals = VARIABLE_ARGS_GET
		names = VARIABLE_ARGS_GET_NAMES
	} else {
		vals = VARIABLE_ARGS_POST
		names = VARIABLE_ARGS_POST_NAMES
	}
	tx.GetCollection(VARIABLE_ARGS).Add(key, value)
	tx.GetCollection(VARIABLE_ARGS_NAMES).Add("", key)

	tx.GetCollection(vals).Add(key, value)
	tx.GetCollection(names).Add("", key)

	col := tx.GetCollection(VARIABLE_ARGS_COMBINED_SIZE)
	i := col.GetFirstInt64("") + int64(len(key)+len(value))
	istr := strconv.FormatInt(i, 10)
	col.Set("", []string{istr})
}

// ProcessUri Performs the analysis on the URI and all the query string variables.
// This method should be called at very beginning of a request process, it is
// expected to be executed prior to the virtual host resolution, when the
// connection arrives on the server.
// note: There is no direct connection between this function and any phase of
//       the SecLanguages phases. It is something that may occur between the
//       SecLanguage phase 1 and 2.
// note: This function won't add GET arguments, they must be added with AddArgument
func (tx *Transaction) ProcessUri(uri string, method string, httpVersion string) {
	tx.GetCollection(VARIABLE_REQUEST_METHOD).Set("", []string{method})
	tx.GetCollection(VARIABLE_REQUEST_PROTOCOL).Set("", []string{httpVersion})
	tx.GetCollection(VARIABLE_REQUEST_URI_RAW).Set("", []string{uri})

	//TODO modsecurity uses HTTP/${VERSION} instead of just version, let's check it out
	tx.GetCollection(VARIABLE_REQUEST_LINE).Set("", []string{fmt.Sprintf("%s %s %s", method, uri, httpVersion)})

	var err error

	//we remove anchors
	if in := strings.Index(uri, "#"); in != -1 {
		uri = uri[:in]
	}
	path := ""
	parsedUrl, err := url.Parse(uri)
	query := ""
	if err != nil {
		tx.GetCollection(VARIABLE_URLENCODED_ERROR).Set("", []string{err.Error()})
		path = uri
		tx.GetCollection(VARIABLE_REQUEST_URI).Set("", []string{uri})
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
			tx.GetCollection(VARIABLE_REQUEST_URI).Set("", []string{uri})
		*/
	} else {
		tx.ExtractArguments("GET", parsedUrl.RawQuery)
		tx.GetCollection(VARIABLE_REQUEST_URI).Set("", []string{parsedUrl.String()})
		path = parsedUrl.Path
		query = parsedUrl.RawQuery
	}
	offset := strings.LastIndexAny(path, "/\\")
	if offset != -1 && len(path) > offset+1 {
		tx.GetCollection(VARIABLE_REQUEST_BASENAME).Set("", []string{path[offset+1:]})
	} else {
		tx.GetCollection(VARIABLE_REQUEST_BASENAME).Set("", []string{path})
	}
	tx.GetCollection(VARIABLE_REQUEST_FILENAME).Set("", []string{path})

	tx.GetCollection(VARIABLE_QUERY_STRING).Set("", []string{query})
}

// ProcessRequestHeaders Performs the analysis on the request readers.
//
// This method perform the analysis on the request headers, notice however
// that the headers should be added prior to the execution of this function.
//
// note: Remember to check for a possible intervention.
func (tx *Transaction) ProcessRequestHeaders() *Interruption {
	if tx.RuleEngine == RULE_ENGINE_OFF {
		// RUle engine is disabled
		return nil
	}
	tx.Waf.Rules.Eval(PHASE_REQUEST_HEADERS, tx)
	return tx.Interruption
}

// ProcessRequestBody Performs the request body (if any)
//
// This method perform the analysis on the request body. It is optional to
// call that function. If this API consumer already know that there isn't a
// body for inspect it is recommended to skip this step.
//
// Remember to check for a possible intervention.
func (tx *Transaction) ProcessRequestBody() (*Interruption, error) {
	if tx.RuleEngine == RULE_ENGINE_OFF {
		return tx.Interruption, nil
	}
	if !tx.RequestBodyAccess {
		tx.Waf.Rules.Eval(PHASE_REQUEST_BODY, tx)
		return tx.Interruption, nil
	}
	mime := ""

	reader := tx.RequestBodyBuffer.Reader()

	if m := tx.GetCollection(VARIABLE_REQUEST_HEADERS).Get("content-type"); len(m) > 0 {
		//spl := strings.SplitN(m[0], ";", 2) //We must skip charset or others
		mime = m[0]
	}

	// Chunked requests will always be written to a temporary file
	if tx.RequestBodyBuffer.Size() >= tx.RequestBodyLimit {
		if tx.Waf.RequestBodyLimitAction == REQUEST_BODY_LIMIT_ACTION_REJECT {
			// We interrupt this transaction in case RequestBodyLimitAction is Reject
			tx.Interruption = &Interruption{
				Status: 403,
				Action: "deny",
			}
			return tx.Interruption, nil
		} else if tx.Waf.RequestBodyLimitAction == REQUEST_BODY_LIMIT_ACTION_PROCESS_PARTIAL {
			tx.GetCollection(VARIABLE_INBOUND_ERROR_DATA).Set("", []string{"1"})
			// we limit our reader to tx.RequestBodyLimit bytes
			reader = io.LimitReader(reader, tx.RequestBodyLimit)
		}
	}
	rbp := tx.GetCollection(VARIABLE_REQBODY_PROCESSOR).GetFirstString("")

	// Default VARIABLE_REQBODY_PROCESSOR values
	// XML and JSON must be forced with ctl:requestBodyProcessor=JSON
	if rbp == "" && tx.ForceRequestBodyVariable {
		// We force URLENCODED if mime is x-www... or we have an empty RBP and ForceRequestBodyVariable
		rbp = "URLENCODED"
		tx.RequestBodyProcessor = REQUEST_BODY_PROCESSOR_URLENCODED
	}

	switch rbp {
	case "URLENCODED":
		buf := new(strings.Builder)
		if _, err := io.Copy(buf, reader); err != nil {
			tx.Waf.Logger.Debug("Cannot copy reader buffer")
		}

		b := buf.String()
		tx.GetCollection(VARIABLE_REQUEST_BODY).Set("", []string{b})
		//TODO add url encode validation
		//tx.GetCollection(VARIABLE_URLENCODED_ERROR).Set("", []string{err.Error()})
		values := utils.ParseQuery(b, "&")
		for k, vs := range values {
			for _, v := range vs {
				tx.AddArgument("POST", k, v)
			}
		}
	case "XML":
		var err error
		options := xmlquery.ParserOptions{
			Decoder: &xmlquery.DecoderOptions{
				Strict:    false,
				AutoClose: []string{},
				Entity:    map[string]string{},
			},
		}
		tx.xmlDoc, err = xmlquery.ParseWithOptions(reader, options)
		if err != nil {
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR).Set("", []string{"1"})
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR_MSG).Set("", []string{string(err.Error())})
			return tx.Interruption, err
		}
	case "MULTIPART":
		req, _ := http.NewRequest("GET", "/", reader)
		req.Header.Set("Content-Type", mime)
		err := req.ParseMultipartForm(1000000000)
		defer req.Body.Close()
		if err != nil {
			tx.GetCollection(VARIABLE_REQBODY_ERROR).Set("", []string{"1"})
			tx.GetCollection(VARIABLE_REQBODY_ERROR_MSG).Set("", []string{string(err.Error())})
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR).Set("", []string{"1"})
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR_MSG).Set("", []string{string(err.Error())})
			// we should not report this error
			return nil, nil
		}

		fn := tx.GetCollection(VARIABLE_FILES_NAMES)
		fl := tx.GetCollection(VARIABLE_FILES)
		fs := tx.GetCollection(VARIABLE_FILES_SIZES)
		totalSize := int64(0)
		for field, fheaders := range req.MultipartForm.File {
			// TODO add them to temporal storage
			// or maybe not, according to http.MultipartForm, it does exactly that
			// the main issue is how do I get this path?
			fn.Add("", field)
			for _, header := range fheaders {
				fl.Add("", header.Filename)
				totalSize += header.Size
				fs.Add("", fmt.Sprintf("%d", header.Size))
			}
		}
		tx.GetCollection(VARIABLE_FILES_COMBINED_SIZE).Set("", []string{fmt.Sprintf("%d", totalSize)})
		for k, vs := range req.MultipartForm.Value {
			for _, v := range vs {
				tx.AddArgument("POST", k, v)
			}
		}
	case "JSON":
		var err error
		//reader to string
		buf := new(strings.Builder)
		if _, err := io.Copy(buf, reader); err != nil {
			tx.Waf.Logger.Debug("Cannot copy reader buffer")
		}
		//string to reader
		reader = strings.NewReader(buf.String())
		tx.jsonDoc, err = jsonquery.Parse(reader)
		if err != nil {
			tx.generateReqbodyError(err)
			// we should not report this error
			//return nil, nil
		}
		jsmap, err := utils.JSONToMap(buf.String())
		if err != nil {
			tx.generateReqbodyError(err)
			//return nil, nil
		}
		for k, v := range jsmap {
			//TODO is it ok to use AddArgument? it will also sum to args_combined_size
			tx.AddArgument("POST", k, v)
			//fmt.Printf("%q=%q\n", k, v)
		}
	}
	tx.Waf.Rules.Eval(PHASE_REQUEST_BODY, tx)
	return tx.Interruption, nil
}

// ProcessResponseHeaders Perform the analysis on the response readers.
//
// This method perform the analysis on the response headers, notice however
// that the headers should be added prior to the execution of this function.
//
// note: Remember to check for a possible intervention.
//
func (tx *Transaction) ProcessResponseHeaders(code int, proto string) *Interruption {
	c := strconv.Itoa(code)
	tx.GetCollection(VARIABLE_RESPONSE_STATUS).Set("", []string{c})
	tx.GetCollection(VARIABLE_RESPONSE_PROTOCOL).Set("", []string{proto})

	if tx.RuleEngine == RULE_ENGINE_OFF {
		return nil
	}

	tx.Waf.Rules.Eval(PHASE_RESPONSE_HEADERS, tx)
	return tx.Interruption
}

// IsProcessableRequestBody returns true if the response body meets the
// criteria to be processed, response headers must be set before this.
// The content-type response header must be in the SecRequestBodyMime
// This is used by webservers to choose whether tostream response buffers
// directly to the client or write them to Coraza
func (tx *Transaction) IsProcessableResponseBody() bool {
	//TODO add more validations
	ct := tx.GetCollection(VARIABLE_RESPONSE_CONTENT_TYPE).GetFirstString("")
	return utils.StringInSlice(ct, tx.Waf.ResponseBodyMimeTypes)
}

// ProcessResponseBody Perform the request body (if any)
//
// This method perform the analysis on the request body. It is optional to
// call that method. If this API consumer already know that there isn't a
// body for inspect it is recommended to skip this step.
//
// note Remember to check for a possible intervention.
func (tx *Transaction) ProcessResponseBody() (*Interruption, error) {
	if tx.RuleEngine == RULE_ENGINE_OFF {
		return tx.Interruption, nil
	}
	if !tx.ResponseBodyAccess || !tx.IsProcessableResponseBody() {
		tx.Waf.Rules.Eval(PHASE_RESPONSE_BODY, tx)
		return tx.Interruption, nil
	}
	reader := tx.ResponseBodyBuffer.Reader()
	reader = io.LimitReader(reader, tx.Waf.ResponseBodyLimit)
	buf := new(strings.Builder)
	length, _ := io.Copy(buf, reader)

	tx.GetCollection(VARIABLE_RESPONSE_CONTENT_LENGTH).Set("", []string{strconv.FormatInt(length, 10)})
	tx.GetCollection(VARIABLE_RESPONSE_BODY).Set("", []string{buf.String()})
	tx.Waf.Rules.Eval(PHASE_RESPONSE_BODY, tx)
	return tx.Interruption, nil
}

// ProcessLogging Logging all information relative to this transaction.
//
// At this point there is not need to hold the connection, the response can be
// delivered prior to the execution of this method.
func (tx *Transaction) ProcessLogging() {
	// I'm not sure why but modsecurity won't log if RuleEngine is disabled
	//if tx.RuleEngine == RULE_ENGINE_OFF {
	//	return
	//}
	defer func() {
		tx.savePersistentData()
		tx.RequestBodyBuffer.Close()
		tx.ResponseBodyBuffer.Close()
		tx.Waf.Logger.Debug("Transaction finished", zap.String("event", "FINISH_TRANSACTION"), zap.String("txid", tx.Id), zap.Bool("interrupted", tx.Interrupted()))
	}()

	tx.Waf.Rules.Eval(PHASE_LOGGING, tx)

	if tx.AuditEngine == AUDIT_LOG_DISABLED {
		// Audit engine disabled
		tx.Waf.Logger.Debug("Transaction not marked for audit logging, AuditEngine is disabled",
			zap.String("tx", tx.Id),
		)
		return
	}

	if tx.AuditEngine == AUDIT_LOG_RELEVANT && !tx.Log {
		re := tx.Waf.AuditLogRelevantStatus
		status := tx.GetCollection(VARIABLE_RESPONSE_STATUS).GetFirstString("")
		m := re.NewMatcher()
		if !m.MatchString(status, 0) {
			//Not relevant status
			tx.Waf.Logger.Debug("Transaction status not marked for audit logging",
				zap.String("tx", tx.Id),
			)
			return
		}
	}

	tx.Waf.Logger.Debug("Transaction marked for audit logging",
		zap.String("tx", tx.Id),
	)
	for _, l := range tx.Waf.AuditLoggers() {
		if err := l.Write(tx.AuditLog()); err != nil {
			tx.Waf.Logger.Error(err.Error())
		}
	}
}

// Interrupted will return true if the transaction was interrupted
func (tx *Transaction) Interrupted() bool {
	return tx.Interruption != nil
}

// AuditLog returns an AuditLog struct, used to write audit logs
func (tx *Transaction) AuditLog() *loggers.AuditLog {
	al := &loggers.AuditLog{}
	parts := tx.AuditLogParts
	al.Messages = []*loggers.AuditMessage{}
	//YYYY/MM/DD HH:mm:ss
	ts := time.Unix(0, tx.Timestamp).Format("2006/01/02 15:04:05")
	al.Transaction = &loggers.AuditTransaction{
		Timestamp:     ts,
		UnixTimestamp: tx.Timestamp,
		Id:            tx.Id,
		ClientIp:      tx.GetCollection(VARIABLE_REMOTE_ADDR).GetFirstString(""),
		ClientPort:    tx.GetCollection(VARIABLE_REMOTE_PORT).GetFirstInt(""),
		HostIp:        tx.GetCollection(VARIABLE_SERVER_ADDR).GetFirstString(""),
		HostPort:      tx.GetCollection(VARIABLE_SERVER_PORT).GetFirstInt(""),
		ServerId:      tx.GetCollection(VARIABLE_SERVER_NAME).GetFirstString(""), //TODO check
		Request: &loggers.AuditTransactionRequest{
			Method:      tx.GetCollection(VARIABLE_REQUEST_METHOD).GetFirstString(""),
			Protocol:    tx.GetCollection(VARIABLE_REQUEST_PROTOCOL).GetFirstString(""),
			Uri:         tx.GetCollection(VARIABLE_REQUEST_URI).GetFirstString(""),
			HttpVersion: tx.GetCollection(VARIABLE_REQUEST_PROTOCOL).GetFirstString(""),
			//Body and headers are audit parts
		},
		Response: &loggers.AuditTransactionResponse{
			Status: tx.GetCollection(VARIABLE_RESPONSE_STATUS).GetFirstInt(""),
			//body and headers are audit parts
		},
	}
	rengine := ""
	switch tx.RuleEngine {
	case RULE_ENGINE_OFF:
		rengine = "Off"
	case RULE_ENGINE_DETECTONLY:
		rengine = "DetectOnly"
	case RULE_ENGINE_ON:
		rengine = "On"
	}

	for _, p := range parts {
		switch p {
		case 'B':
			al.Transaction.Request.Headers = tx.GetCollection(VARIABLE_REQUEST_HEADERS).Data()
		case 'C':
			al.Transaction.Request.Body = tx.GetCollection(VARIABLE_REQUEST_BODY).GetFirstString("")
			//TODO maybe change to:
			//al.Transaction.Request.Body = tx.RequestBodyBuffer.String()
		case 'F':
			al.Transaction.Response.Headers = tx.GetCollection(VARIABLE_RESPONSE_HEADERS).Data()
		case 'G':
			al.Transaction.Response.Body = tx.GetCollection(VARIABLE_RESPONSE_BODY).GetFirstString("")
		case 'H':
			servera := tx.GetCollection(VARIABLE_RESPONSE_HEADERS).Get("server")
			server := ""
			if len(server) > 0 {
				server = servera[0]
			}
			al.Transaction.Producer = &loggers.AuditTransactionProducer{
				Connector:  "unknown", //TODO maybe add connector variable to Waf
				Version:    "unknown",
				Server:     server,
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
			//upload data
			al.Transaction.Request.Files = []*loggers.AuditTransactionRequestFiles{}
			for i, name := range tx.GetCollection(VARIABLE_FILES).Get("") {
				//TODO we kind of assume there is a file_size for each file with the same index
				size, _ := strconv.ParseInt(tx.GetCollection(VARIABLE_FILES_SIZES).Get("")[i], 10, 64)
				ext := filepath.Ext(name)
				at := &loggers.AuditTransactionRequestFiles{
					Size: size,
					Name: name,
					Mime: mime.TypeByExtension(ext),
				}
				al.Transaction.Request.Files = append(al.Transaction.Request.Files, at)
			}
		case 'K':
			mrs := []*loggers.AuditMessage{}
			for _, mr := range tx.MatchedRules {
				r := mr.Rule
				mrs = append(mrs, &loggers.AuditMessage{
					Actionset: strings.Join(tx.Waf.ComponentNames, " "),
					Message:   tx.Logdata,
					Data: &loggers.AuditMessageData{
						File:     mr.Rule.File,
						Line:     mr.Rule.Line,
						Id:       r.Id,
						Rev:      r.Rev,
						Msg:      tx.MacroExpansion(strings.Join(mr.Messages, " ")), //TODO check
						Data:     tx.MacroExpansion(r.LogData),                      //TODO LogData MUST be in the matched rule
						Severity: r.Severity,
						Ver:      r.Version,
						Maturity: r.Maturity,
						Accuracy: r.Accuracy,
						Tags:     r.Tags,
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
	tx.GetCollection(VARIABLE_REQBODY_ERROR).Set("", []string{"1"})
	tx.GetCollection(VARIABLE_REQBODY_ERROR_MSG).Set("", []string{string(err.Error())})
	tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR).Set("", []string{"1"})
	tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR_MSG).Set("", []string{string(err.Error())})
}
