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
	"github.com/antchfx/xmlquery"
	"github.com/jptosso/coraza-waf/pkg/utils"
	log "github.com/sirupsen/logrus"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	Collections []*Collection
	//This map is used to store persistent collections saves, useful to save them after transaction is finished
	PersistentCollections map[string]*PersistentCollection

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
	ResponseBodyMimeType     []string
	RuleEngine               bool
	HashEngine               bool
	HashEnforcement          bool
	AuditLogType             int
	LastPhase                int

	RequestBodyReader  *BodyReader
	ResponseBodyReader *BodyReader

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

	// Used to delete temp files after transaction is finished
	temporaryFiles []string

	Timestamp int64
}

func (tx *Transaction) Init(waf *Waf) error {
	tx.Waf = waf
	tx.Collections = make([]*Collection, VARIABLES_COUNT)
	txid := utils.RandomString(19)
	tx.Id = txid
	for i := range tx.Collections {
		tx.Collections[i] = &Collection{}
		tx.Collections[i].Init(VariableToName(byte(i)))
	}

	for i := 0; i <= 10; i++ {
		is := strconv.Itoa(i)
		tx.GetCollection(VARIABLE_TX).Set(is, []string{})
	}
	tx.Timestamp = time.Now().UnixNano()
	tx.AuditEngine = tx.Waf.AuditEngine
	tx.AuditLogParts = tx.Waf.AuditLogParts
	tx.RequestBodyAccess = true
	tx.RequestBodyLimit = 134217728
	tx.ResponseBodyAccess = true
	tx.ResponseBodyLimit = 524288
	tx.ResponseBodyMimeType = []string{"text/html", "text/plain"}
	tx.RuleEngine = tx.Waf.RuleEngine
	tx.AuditLogType = tx.Waf.AuditLogType
	tx.Skip = 0
	tx.PersistentCollections = map[string]*PersistentCollection{}
	tx.RuleRemoveTargetById = map[int][]*KeyValue{}
	tx.RuleRemoveById = []int{}
	tx.StopWatches = map[int]int{}
	tx.RequestBodyReader = NewBodyReader(tx.Waf.TmpDir, tx.Waf.RequestBodyInMemoryLimit)
	// TODO add response values
	tx.ResponseBodyReader = NewBodyReader(tx.Waf.TmpDir, tx.Waf.RequestBodyInMemoryLimit)

	return nil
}

func (tx *Transaction) MacroExpansion(data string) string {
	if data == "" {
		return ""
	}

	// \w includes alphanumeric and _
	r := regexp.MustCompile(`%\{([\w.-]+?)\}`)
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
			log.Debug("Failed to expand " + match)
		} else {
			data = strings.ReplaceAll(data, v, expansion[0])
			log.Debug(fmt.Sprintf("Expanding %%{%s} to %s", match, expansion[0]))
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
		mp := "multipart/form-data"
		if val == "application/x-www-form-urlencoded" {
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR).Add("", "URLENCODED")
		} else if len(val) > len(mp) && val[0:len(mp)-1] == mp {
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
	for k, v := range tx.GetCollection(VARIABLE_REQUEST_HEADERS).GetData() {
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
func (tx *Transaction) GetField(collection byte, key string, exceptions []string) []*MatchData {
	if collection == VARIABLE_XML {
		if tx.XmlDoc == nil {
			return []*MatchData{}
		}
		data, err := xmlquery.QueryAll(tx.XmlDoc, key)
		if err != nil {
			log.Error("Invalid xpath expression " + key)
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
		return col.GetWithExceptions(key, exceptions)
	}
	// TODO some day we should add VARIABLE_JSON

}

func (tx *Transaction) GetCollection(variable byte) *Collection {
	return tx.Collections[variable]
}

// This is for debug only
func (tx *Transaction) GetCollections() map[string]*Collection {
	cols := map[string]*Collection{}
	for i, col := range tx.Collections {
		v := VariableToName(byte(i))
		cols[v] = col
	}
	return cols
}

func (tx *Transaction) GetRemovedTargets(id int) []*KeyValue {
	return tx.RuleRemoveTargetById[id]
}

func (tx *Transaction) ToAuditJson() []byte {
	al := tx.ToAuditLog()
	return al.ToJson()
}

func (tx *Transaction) ToAuditLog() *AuditLog {
	al := &AuditLog{}
	al.Init(tx)
	return al
}

func (tx *Transaction) saveLog() error {
	return tx.Waf.Logger.WriteAudit(tx)
}

// Save persistent collections to persistence engine
func (tx *Transaction) savePersistentData() {
	/*
		TODO: There is a weird deadlock... gonna fix it
		for col, pc := range tx.PersistentCollections {
			pc.SetData(tx.GetCollection(col).GetData())
			pc.Save()
		}*/
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

// Used by initcol to load a persistent collection and save it after the transaction
// is finished
func (tx *Transaction) RegisterPersistentCollection(collection string, pc *PersistentCollection) {
	tx.PersistentCollections[collection] = pc
}

func (tx *Transaction) addTemporaryFile(path string) {
	tx.temporaryFiles = append(tx.temporaryFiles, path)
}

func (tx *Transaction) removeTemporaryFiles() {
	for _, f := range tx.temporaryFiles {
		os.Remove(f)
	}
	tx.temporaryFiles = []string{}
}

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
	tx.ProcessUri(req.URL, req.Method, req.Proto)
	for k, vr := range req.URL.Query() {
		for _, v := range vr {
			tx.AddArgument("GET", k, v)
		}
	}
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}
	tx.AddRequestHeader("Host", req.Host)
	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}
	_, err := io.Copy(tx.RequestBodyReader, req.Body)
	if err != nil {
		return tx.Interruption, err
	}
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
func (tx *Transaction) ProcessUri(uri *url.URL, method string, httpVersion string) {
	RequestBasename := uri.EscapedPath()
	a := regexp.MustCompile(`\/|\\`) // \ o /
	spl := a.Split(RequestBasename, -1)
	if len(spl) > 0 {
		RequestBasename = spl[len(spl)-1]
	}
	tx.GetCollection(VARIABLE_REQUEST_URI).Add("", uri.String())
	tx.GetCollection(VARIABLE_REQUEST_FILENAME).Add("", uri.Path)
	tx.GetCollection(VARIABLE_REQUEST_BASENAME).Add("", RequestBasename)
	tx.GetCollection(VARIABLE_QUERY_STRING).Add("", uri.RawQuery)
	tx.GetCollection(VARIABLE_REQUEST_URI_RAW).Add("", uri.String())

	tx.GetCollection(VARIABLE_REQUEST_METHOD).Add("", method)
	tx.GetCollection(VARIABLE_REQUEST_PROTOCOL).Add("", httpVersion)
	tx.GetCollection(VARIABLE_REQUEST_LINE).Add("", fmt.Sprintf("%s %s %s", method, uri.String(), httpVersion))
}

// Perform the analysis on the request readers.
//
// This method perform the analysis on the request headers, notice however
// that the headers should be added prior to the execution of this function.
//
// note: Remember to check for a possible intervention.
func (tx *Transaction) ProcessRequestHeaders() *Interruption {
	if !tx.RuleEngine {
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
	if !tx.RequestBodyAccess || !tx.RuleEngine {
		return tx.Interruption, nil
	}
	mime := "application/x-www-form-urlencoded"

	reader := tx.RequestBodyReader.Reader()
	if m := tx.GetCollection(VARIABLE_REQUEST_HEADERS).Get("content-type"); len(m) > 0 {
		//spl := strings.SplitN(m[0], ";", 2) //We must skip charset or others
		mime = m[0]
	}

	// Chunked requests will always be written to a temporary file
	if tx.RequestBodyReader.Size() >= tx.RequestBodyLimit {
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

	//TODO check this out
	if tx.RequestBodyProcessor == 0 && tx.ForceRequestBodyVariable {
		tx.RequestBodyProcessor = REQUEST_BODY_PROCESSOR_URLENCODED
	} else if tx.RequestBodyProcessor == 0 {
		// We force the body processor if none was provided
		//if mime == "application/xml" || mime == "text/xml" {
		// It looks like xml body processor is called by default
		//	tx.RequestBodyProcessor = REQUEST_BODY_PROCESSOR_XML
		if mime == "application/x-www-form-urlencoded" {
			tx.RequestBodyProcessor = REQUEST_BODY_PROCESSOR_URLENCODED
		} else if strings.HasPrefix(mime, "multipart/form-data") {
			tx.RequestBodyProcessor = REQUEST_BODY_PROCESSOR_MULTIPART
		} else if mime == "application/json" {
			tx.RequestBodyProcessor = REQUEST_BODY_PROCESSOR_JSON
		} else {
			tx.RequestBodyProcessor = REQUEST_BODY_PROCESSOR_URLENCODED
		}
	}

	switch tx.RequestBodyProcessor {
	case REQUEST_BODY_PROCESSOR_URLENCODED:
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
	case REQUEST_BODY_PROCESSOR_XML:
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
	case REQUEST_BODY_PROCESSOR_MULTIPART:
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
	case REQUEST_BODY_PROCESSOR_JSON:
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

	if !tx.RuleEngine {
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
	return utils.ArrayContains(tx.ResponseBodyMimeType, ct)
}

// Perform the request body (if any)
//
// This method perform the analysis on the request body. It is optional to
// call that method. If this API consumer already know that there isn't a
// body for inspect it is recommended to skip this step.
//
// note Remember to check for a possible intervention.
func (tx *Transaction) ProcessResponseBody() (*Interruption, error) {
	if !tx.RuleEngine || !tx.ResponseBodyAccess || !tx.IsProcessableResponseBody() {
		return tx.Interruption, nil
	}
	length := strconv.FormatInt(tx.ResponseBodyReader.Size(), 10)
	reader := tx.ResponseBodyReader.Reader()
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
	if !tx.RuleEngine {
		return
	}
	tx.savePersistentData()
	tx.removeTemporaryFiles()

	tx.Waf.Rules.Evaluate(5, tx)

	if tx.AuditEngine == AUDIT_LOG_DISABLED {
		// Audit engine disabled
		return
	}
	re := tx.Waf.AuditLogRelevantStatus
	status := tx.GetCollection(VARIABLE_RESPONSE_STATUS).GetFirstString("")
	m := re.NewMatcher()
	if !m.MatchString(status, 0) {
		//Not relevant status
		return
	}
	tx.saveLog()
}
