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

package engine

import (
	"bufio"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/antchfx/xmlquery"
	"github.com/jptosso/coraza-waf/loggers"
	"github.com/jptosso/coraza-waf/utils"
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

type MatchedRule struct {
	Messages    []string
	MatchedData []*MatchData
	Rule        *Rule
}

type MatchData struct {
	Collection string
	Key        string
	Value      string
}

type KeyValue struct {
	Name       string
	Collection byte
	Key        string
}

type Transaction struct {
	// If true the transaction is going to be logged, it won't log if IsRelevantStatus() fails
	Log bool

	//Transaction Id
	Id string

	// Contains the list of matched rules and associated match information
	MatchedRules []*MatchedRule

	//True if the transaction has been disrupted by any rule
	Interruption *Interruption

	// Contains all collections, including persistent
	collections []*Collection

	//Response data to be sent
	Status int `json:"status"`

	Logdata []string `json:"logdata"`

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

	LastPhase int

	RequestBodyBuffer  *BodyBuffer
	ResponseBodyBuffer *BodyBuffer

	// Rules with this id are going to be skipped
	RuleRemoveById []int

	// Used by ctl to remove rule targets by id during the transaction
	RuleRemoveTargetById map[int][]*KeyValue

	// Will skip this number of rules, this value will be decreased on each skip
	Skip int

	// Actions with capture features will read the capture state from this field
	Capture bool

	// Contains duration in useconds per phase
	StopWatches map[int]int

	// Contains de *engine.Waf instance for the current transaction
	Waf *Waf

	XmlDoc *xmlquery.Node

	Timestamp int64
}

var macroRegexp = regexp.MustCompile(`%\{([\w.-]+?)\}`)

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

// Adds a request header
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
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR).Add("", "URLENCODED")
		} else if strings.HasPrefix(val, "multipart/form-data") {
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR).Add("", "MULTIPART")
		}
	} else if key == "host" {
		tx.GetCollection(VARIABLE_SERVER_NAME).Add("", value)
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

// Creates the FULL_REQUEST variable based on every input
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
	tx.GetCollection(VARIABLE_FULL_REQUEST).Add("", full_request)
}

// Adds a response header
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
		tx.GetCollection(VARIABLE_RESPONSE_CONTENT_TYPE).Add("", spl[0])
	}
}

// Used to set the TX:[index] collection by operators
func (tx *Transaction) CaptureField(index int, value string) {
	i := strconv.Itoa(index)
	tx.GetCollection(VARIABLE_TX).Set(i, []string{value})
}

//Reset the capture collection for further uses
func (tx *Transaction) ResetCapture() {
	//We reset capture 0-9
	ctx := tx.GetCollection(VARIABLE_TX)
	for i := 0; i < 10; i++ {
		si := strconv.Itoa(i)
		ctx.Set(si, []string{""})
	}
}

// Parse binary request including body, does only supports http/1.1 and http/1.0
// This function is only intended for testing and debugging
func (tx *Transaction) ParseRequestString(data string) (*Interruption, error) {
	bts := strings.NewReader(data)
	// For dumb reasons we must read the headers and look for the Host header,
	// this function is intended for proxies and the RFC says that a Host must not be parsed...
	// Maybe some time I will create a prettier fix
	scanner := bufio.NewScanner(bts)
	for scanner.Scan() {
		l := scanner.Text()
		if l == "" {
			// It should mean we are now in the request body...
			break
		}
		r := regexp.MustCompile(`^[h|H]ost:\s+(.*?)$`)
		rs := r.FindStringSubmatch(l)
		if len(rs) > 1 {
			tx.AddRequestHeader("Host", rs[1])
		}
	}
	bts.Reset(data)
	//End of this dumb fix...

	buf := bufio.NewReader(bts)
	req, err := http.ReadRequest(buf)
	if err != nil {
		return nil, err
	}

	return tx.ProcessRequest(req)
}

// Creates the MATCHED_VAR* variables required by chains and macro expansion
func (tx *Transaction) MatchVars(match []*MatchData) {
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

// Matches a rule to be logged
func (tx *Transaction) MatchRule(rule *Rule, msgs []string, match []*MatchData) {
	mr := &MatchedRule{
		Messages:    msgs,
		MatchedData: match,
		Rule:        rule,
	}
	tx.MatchedRules = append(tx.MatchedRules, mr)
}

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

// Retrieve data from collections applying exceptions
// This function will apply xpath if the variable is XML
func (tx *Transaction) GetField(rv RuleVariable, exceptions []string) []*MatchData {
	collection := rv.Collection
	key := rv.Key
	re := rv.Regex
	if collection == VARIABLE_XML {
		if tx.XmlDoc == nil {
			return []*MatchData{}
		}
		data, err := xmlquery.QueryAll(tx.XmlDoc, key)
		if err != nil {
			return []*MatchData{}
		}
		res := []*MatchData{}
		for _, d := range data {
			//TODO im not sure if its ok but nvm:
			output := html.UnescapeString(d.OutputXML(true))
			res = append(res, &MatchData{
				Collection: "xml",
				Key:        key,
				Value:      output,
			})
		}
		return res
	} else {
		col := tx.GetCollection(collection)
		key = tx.MacroExpansion(key)
		if col == nil {
			return []*MatchData{}
		}
		return col.Find(key, re, exceptions)
	}
	// TODO some day we should add VARIABLE_JSON

}

func (tx *Transaction) GetCollection(variable byte) *Collection {
	return tx.collections[variable]
}

// This is for debug only
func (tx *Transaction) GetCollections() map[string]*Collection {
	cols := map[string]*Collection{}
	for i, col := range tx.collections {
		v := VariableToName(byte(i))
		cols[v] = col
	}
	return cols
}

func (tx *Transaction) GetRemovedTargets(id int) []*KeyValue {
	return tx.RuleRemoveTargetById[id]
}

func (tx *Transaction) ToAuditJson() []byte {
	al := tx.AuditLog()
	data, _ := al.JSON()
	return data
}

func (tx *Transaction) saveLog() error {
	for _, l := range tx.Waf.AuditLoggers() {
		if err := l.Write(tx.AuditLog()); err != nil {
			tx.Waf.Logger.Error(err.Error())
		}
	}

	return nil
}

// SavePersistentData save persistent collections to persistence engine
func (tx *Transaction) savePersistentData() {
	//TODO, disabled by now, maybe we should add persistent variables to the
	// collection struct, something like col.Persist("key")
	//pers := []byte{VARIABLE_SESSION, VARIABLE_IP}
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
}

// Removes the VARIABLE/TARGET from the rule ID
func (tx *Transaction) RemoveRuleTargetById(id int, col byte, key string) {
	c := &KeyValue{"", col, key}
	if tx.RuleRemoveTargetById[id] == nil {
		tx.RuleRemoveTargetById[id] = []*KeyValue{
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
	tx.ExtractArguments("GET", req.URL.RawQuery)
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
	_, err := io.Copy(tx.RequestBodyBuffer, req.Body)
	if err != nil {
		return tx.Interruption, err
	}
	req.Body = io.NopCloser(tx.RequestBodyBuffer.Reader())
	return tx.ProcessRequestBody()
}

// This method should be called at very beginning of a request process, it is
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

	tx.GetCollection(VARIABLE_REMOTE_ADDR).Add("", client)
	tx.GetCollection(VARIABLE_REMOTE_PORT).Add("", p)
	tx.GetCollection(VARIABLE_SERVER_ADDR).Add("", server)
	tx.GetCollection(VARIABLE_SERVER_PORT).Add("", p2)
	tx.GetCollection(VARIABLE_UNIQUE_ID).Add("", tx.Id)

	//TODO maybe evaluate phase 0?
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

// Add arguments GET or POST
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

// Perform the analysis on the URI and all the query string variables.
// This method should be called at very beginning of a request process, it is
// expected to be executed prior to the virtual host resolution, when the
// connection arrives on the server.
// note: There is no direct connection between this function and any phase of
//       the SecLanguage's phases. It is something that may occur between the
//       SecLanguage phase 1 and 2.
// note: This function won't add GET arguments, they must be added with AddArgument
func (tx *Transaction) ProcessUri(uri string, method string, httpVersion string) {
	// TODO manual url decode
	huri, _ := url.Parse(uri)
	RequestBasename := huri.EscapedPath()
	a := regexp.MustCompile(`\/|\\`) // \ o /
	spl := a.Split(RequestBasename, -1)
	if len(spl) > 0 {
		RequestBasename = spl[len(spl)-1]
	}
	tx.GetCollection(VARIABLE_REQUEST_URI).Add("", huri.String())
	tx.GetCollection(VARIABLE_REQUEST_FILENAME).Add("", huri.Path)
	tx.GetCollection(VARIABLE_REQUEST_BASENAME).Add("", RequestBasename)
	tx.GetCollection(VARIABLE_QUERY_STRING).Add("", huri.RawQuery)
	tx.GetCollection(VARIABLE_REQUEST_URI_RAW).Add("", huri.String())

	tx.GetCollection(VARIABLE_REQUEST_METHOD).Add("", method)
	tx.GetCollection(VARIABLE_REQUEST_PROTOCOL).Add("", httpVersion)
	tx.GetCollection(VARIABLE_REQUEST_LINE).Add("", fmt.Sprintf("%s %s %s", method, huri.String(), httpVersion))
}

// Perform the analysis on the request readers.
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
	tx.Waf.Rules.Evaluate(1, tx)
	return tx.Interruption
}

// Perform the request body (if any)
//
// This method perform the analysis on the request body. It is optional to
// call that function. If this API consumer already know that there isn't a
// body for inspect it is recommended to skip this step.
//
// Remember to check for a possible intervention.
func (tx *Transaction) ProcessRequestBody() (*Interruption, error) {
	if !tx.RequestBodyAccess || tx.RuleEngine == RULE_ENGINE_OFF {
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
	}

	switch rbp {
	case "URLENCODED":
		buf := new(strings.Builder)
		io.Copy(buf, reader)
		b := buf.String()
		tx.GetCollection(VARIABLE_REQUEST_BODY).Set("", []string{b})
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
		tx.XmlDoc, err = xmlquery.ParseWithOptions(reader, options)
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
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR).Set("", []string{"1"})
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR_MSG).Set("", []string{string(err.Error())})
			return tx.Interruption, err
		}

		fn := tx.GetCollection(VARIABLE_FILES_NAMES)
		fl := tx.GetCollection(VARIABLE_FILES)
		fs := tx.GetCollection(VARIABLE_FILES_SIZES)
		totalSize := int64(0)
		for field, fheaders := range req.MultipartForm.File {
			// TODO add them to temporal storage
			fn.Add("", field)
			for _, header := range fheaders {
				fl.Add("", header.Filename)
				totalSize += header.Size
				fs.Add("", fmt.Sprintf("%d", header.Size))
			}
		}
		tx.GetCollection(VARIABLE_FILES_COMBINED_SIZE).Add("", fmt.Sprintf("%d", totalSize))
		for k, vs := range req.MultipartForm.Value {
			for _, v := range vs {
				tx.AddArgument("POST", k, v)
			}
		}
	case "JSON":
		buf := new(strings.Builder)
		io.Copy(buf, reader)
		b := buf.String()
		tx.GetCollection(VARIABLE_REQUEST_BODY).Set("", []string{b})
	}
	tx.Waf.Rules.Evaluate(2, tx)
	return tx.Interruption, nil
}

// Perform the analysis on the response readers.
//
// This method perform the analysis on the response headers, notice however
// that the headers should be added prior to the execution of this function.
//
// note: Remember to check for a possible intervention.
//
func (tx *Transaction) ProcessResponseHeaders(code int, proto string) *Interruption {
	c := strconv.Itoa(code)
	tx.GetCollection(VARIABLE_RESPONSE_STATUS).Add("", c)
	tx.GetCollection(VARIABLE_RESPONSE_PROTOCOL).Add("", proto)

	if tx.RuleEngine == RULE_ENGINE_OFF {
		return nil
	}

	tx.Waf.Rules.Evaluate(3, tx)
	return tx.Interruption
}

// IsProcessableRequestBody returns true if the response body meets the
// criteria to be processed, response headers must be set before.
// The content-type response header must be in the SecRequestBodyMime
// This is used by webservers to stream response buffers directly to the client
func (tx *Transaction) IsProcessableResponseBody() bool {
	ct := tx.GetCollection(VARIABLE_RESPONSE_CONTENT_TYPE).GetFirstString("")
	return utils.StringInSlice(ct, tx.Waf.ResponseBodyMimeTypes)
}

// Perform the request body (if any)
//
// This method perform the analysis on the request body. It is optional to
// call that method. If this API consumer already know that there isn't a
// body for inspect it is recommended to skip this step.
//
// note Remember to check for a possible intervention.
func (tx *Transaction) ProcessResponseBody() (*Interruption, error) {
	if tx.RuleEngine == RULE_ENGINE_OFF || !tx.ResponseBodyAccess || !tx.IsProcessableResponseBody() {
		return tx.Interruption, nil
	}
	length := strconv.FormatInt(tx.ResponseBodyBuffer.Size(), 10)
	reader := tx.ResponseBodyBuffer.Reader()
	reader = io.LimitReader(reader, tx.Waf.ResponseBodyLimit)
	buf := new(strings.Builder)
	io.Copy(buf, reader)

	tx.GetCollection(VARIABLE_RESPONSE_CONTENT_LENGTH).Set("", []string{length})
	tx.GetCollection(VARIABLE_RESPONSE_BODY).Set("", []string{buf.String()})
	tx.Waf.Rules.Evaluate(4, tx)
	return tx.Interruption, nil
}

// Logging all information relative to this transaction.
//
// At this point there is not need to hold the connection, the response can be
// delivered prior to the execution of this method.
func (tx *Transaction) ProcessLogging() {
	// I'm not sure why but modsecurity won't log if RuleEngine is disabled
	if tx.RuleEngine == RULE_ENGINE_OFF {
		return
	}
	defer tx.savePersistentData()

	tx.Waf.Rules.Evaluate(5, tx)

	if tx.AuditEngine == AUDIT_LOG_DISABLED {
		// Audit engine disabled
		return
	}
	if tx.Waf.AuditEngine == AUDIT_LOG_RELEVANT {
		re := tx.Waf.AuditLogRelevantStatus
		status := tx.GetCollection(VARIABLE_RESPONSE_STATUS).GetFirstString("")
		m := re.NewMatcher()
		if !m.MatchString(status, 0) {
			//Not relevant status
			return
		}
	}

	tx.saveLog()
}

// Interrupted will return true if the transaction was interrupted
func (tx *Transaction) Interrupted() bool {
	return tx.Interruption != nil
}

// AuditLog returns an AuditLog struct
func (tx *Transaction) AuditLog() *loggers.AuditLog {
	al := &loggers.AuditLog{}
	parts := tx.AuditLogParts
	al.Messages = []*loggers.AuditMessage{}
	//YYYY/MM/DD HH:mm:ss
	ts := time.Unix(0, tx.Timestamp).Format("2006/01/02 15:04:05")
	al.Transaction = &loggers.AuditTransaction{
		Timestamp:  ts,
		Id:         tx.Id,
		ClientIp:   tx.GetCollection(VARIABLE_REMOTE_ADDR).GetFirstString(""),
		ClientPort: tx.GetCollection(VARIABLE_REMOTE_PORT).GetFirstInt(""),
		HostIp:     "",
		HostPort:   0,
		ServerId:   "",
		Request: &loggers.AuditTransactionRequest{
			Protocol:    tx.GetCollection(VARIABLE_REQUEST_METHOD).GetFirstString(""),
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
				Connector:  "unknown",
				Version:    "unknown",
				Server:     server,
				RuleEngine: rengine,
				Stopwatch:  tx.GetStopWatch(),
			}
		case 'I':
			// not implemented
			// TODO
		case 'J':
			//upload data
			// TODO
		case 'K':
			for _, mr := range tx.MatchedRules {
				r := mr.Rule
				al.Messages = append(al.Messages, &loggers.AuditMessage{
					Actionset: "",
					Message:   "",
					Data: &loggers.AuditMessageData{
						File:     "",
						Line:     0,
						Id:       r.Id,
						Rev:      r.Rev,
						Msg:      tx.MacroExpansion(r.Msg),
						Data:     "",
						Severity: r.Severity,
						Ver:      r.Version,
						Maturity: r.Maturity,
						Accuracy: r.Accuracy,
						Tags:     r.Tags,
					},
				})
			}
		}
	}
	return al
}
