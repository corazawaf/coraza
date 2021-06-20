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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/antchfx/xmlquery"
	"github.com/jptosso/coraza-waf/pkg/utils"
	log "github.com/sirupsen/logrus"
	"html"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
	Log bool `json:"log"`

	//Transaction Id
	Id string

	// Contains the list of matched rules and associated match information
	MatchedRules []*MatchedRule `json:"matched_rules"`

	//True if the transaction has been disrupted by any rule
	Disrupted bool `json:"disrupted"`

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

	// Rules with this id are going to be skipped
	RuleRemoveById []int

	// Used by ctl to remove rule targets by id during the transaction
	RuleRemoveTargetById map[int][]*KeyValue

	// Will skip this number of rules, this value will be decreased on each skip
	Skip int

	// Actions with capture features will read the capture state from this field
	Capture bool

	// Contains the ID of the rule that disrupted the transaction
	DisruptiveRuleId int `json:"disruptive_rule_id"`

	// Contains duration in useconds per phase
	StopWatches map[int]int

	// Used for paralelism
	Mux *sync.RWMutex

	// Contains de *engine.Waf instance for the current transaction
	Waf *Waf

	XmlDoc *xmlquery.Node

	// Used to delete temp files after transaction is finished
	temporaryFiles []string

	Timestamp int64
}

func (tx *Transaction) Init(waf *Waf) error {
	tx.Mux = &sync.RWMutex{}
	tx.Waf = waf
	tx.Collections = make([]*Collection, VARIABLES_COUNT)
	txid := utils.RandomString(19)
	tx.Id = txid
	for i, _ := range tx.Collections {
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

//Sets request_headers and request_headers_names
func (tx *Transaction) SetRequestHeaders(headers map[string][]string) {
	for h, vs := range headers {
		for _, value := range vs {
			tx.AddRequestHeader(h, value)
		}
	}
}

//Adds a request header
func (tx *Transaction) AddRequestHeader(key string, value string) {
	if key == "" {
		return
	}
	key = strings.ToLower(key)
	tx.GetCollection(VARIABLE_REQUEST_HEADERS_NAMES).AddUnique("", key)
	tx.GetCollection(VARIABLE_REQUEST_HEADERS).Add(key, value)

	//Most headers can be managed like that except cookies
	rhmap := map[string]byte{}
	for k, v := range rhmap {
		if k == key {
			tx.GetCollection(v).Add("", value)
		}
	}
}

//Sets args_get, args_get_names. Also adds to args_names and args
func (tx *Transaction) SetArgsGet(args map[string][]string) {
	tx.GetCollection(VARIABLE_ARGS_GET).AddMap(args)
	tx.GetCollection(VARIABLE_ARGS).AddMap(args)
	agn := tx.GetCollection(VARIABLE_ARGS_GET_NAMES)
	an := tx.GetCollection(VARIABLE_ARGS_NAMES)
	length := 0
	for k, _ := range args {
		if k == "" {
			continue
		}
		agn.Add("", k)
		an.Add("", k)
		length += len(k)
	}
	tx.addArgsLength(length)
}

//Sets args_post, args_post_names. Also adds to args_names and args
func (tx *Transaction) SetArgsPost(args map[string][]string) {
	tx.GetCollection(VARIABLE_ARGS_POST).AddMap(args)
	tx.GetCollection(VARIABLE_ARGS).AddMap(args)
	apn := tx.GetCollection(VARIABLE_ARGS_POST_NAMES)
	an := tx.GetCollection(VARIABLE_ARGS_NAMES)
	for k, _ := range args {
		if k == "" {
			continue
		}
		apn.Add("", k)
		an.Add("", k)
	}
}

//Sets files, files_combined_size, files_names, files_sizes, files_tmpnames, files_tmp_content
func (tx *Transaction) SetFiles(files map[string][]*multipart.FileHeader) {
	fn := tx.GetCollection(VARIABLE_FILES_NAMES)
	fl := tx.GetCollection(VARIABLE_FILES)
	fs := tx.GetCollection(VARIABLE_FILES_SIZES)
	totalSize := int64(0)
	for field, fheaders := range files {
		// TODO add them to temporal storage
		fn.Add("", field)
		for _, header := range fheaders {
			fl.Add("", header.Filename)
			totalSize += header.Size
			fs.Add("", fmt.Sprintf("%d", header.Size))
		}
	}
	tx.GetCollection(VARIABLE_FILES_COMBINED_SIZE).Add("", fmt.Sprintf("%d", totalSize))
}

//a FULL_REQUEST variable will be set from request_line, request_headers and request_body
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

//Sets remote_address and remote_port
func (tx *Transaction) SetRemoteAddress(address string, port int) {
	p := strconv.Itoa(port)
	tx.GetCollection(VARIABLE_REMOTE_ADDR).Add("", address)
	tx.GetCollection(VARIABLE_REMOTE_PORT).Add("", p)
}

func (tx *Transaction) SetReqBodyProcessor(processor string) {
	tx.GetCollection(VARIABLE_REQBODY_PROCESSOR).Add("", processor)
}

//Sets request_body and request_body_length, it won't work if request_body_inspection is off
func (tx *Transaction) SetRequestBody(body *io.Reader) error {
	if !tx.RequestBodyAccess { // || (tx.RequestBodyLimit > 0 && length > tx.RequestBodyLimit) {
		return nil
	}

	transfer := tx.GetCollection(VARIABLE_REQUEST_HEADERS).GetFirstString("transfer")
	length := tx.GetCollection(VARIABLE_REQUEST_HEADERS).GetFirstInt64("content-length")
	mime := tx.GetCollection(VARIABLE_REQUEST_HEADERS).GetFirstString("content-type")
	mime = strings.ToLower(mime)
	chunked := strings.EqualFold(transfer, "chunked")
	var reader io.Reader

	// Chunked requests will always be written to a temporary file
	if !chunked && length > tx.RequestBodyLimit && tx.Waf.RequestBodyLimitAction == REQUEST_BODY_LIMIT_ACTION_REJECT {
		return errors.New("Rejected request body size")
	} else if !chunked && length > tx.RequestBodyLimit && tx.Waf.RequestBodyLimitAction == REQUEST_BODY_LIMIT_ACTION_PROCESS_PARTIAL {
		tx.GetCollection(VARIABLE_INBOUND_ERROR_DATA).Set("", []string{"1"})
	}

	// In this case we are going to write the buffer to a file
	if chunked || length > tx.Waf.RequestBodyInMemoryLimit {
		tpath := path.Join(tx.Waf.TmpDir, utils.RandomString(16))
		tfile, err := os.Create(tpath)
		defer tfile.Close()
		io.Copy(tfile, *body)
		if err != nil {
			return errors.New("Couldn't create temporary file to store request body buffer")
		}
		// We overwrite the original body with the file
		reader = bufio.NewReader(tfile)
		//then we copy the content to body
		*body = (bufio.NewReader(tfile))
		tx.addTemporaryFile(tpath)
	} else { //we write the buffer to memory
		// In this case we are going to buffer it to memory so be it !
		b, err := ioutil.ReadAll(*body)
		if err != nil {
			return errors.New("Failed to store request body in memory")
		}
		reader = bytes.NewReader(b)
		*body = bytes.NewReader(b)
	}

	//FROM CTL:forcerequestbodyvariable...
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
		uri, err := url.Parse("?" + b)
		tx.GetCollection(VARIABLE_REQUEST_BODY).Set("", []string{b})
		if err != nil {
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR).Set("", []string{"1"})
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR_MSG).Set("", []string{string(err.Error())})
			return err
		}
		tx.AddPostArgsFromUrl(uri)
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
			return err
		}
	case REQUEST_BODY_PROCESSOR_MULTIPART:
		req, _ := http.NewRequest("GET", "/", reader)
		req.Header.Set("Content-Type", mime)
		err := req.ParseMultipartForm(1000000000)
		defer req.Body.Close()
		if err != nil {
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR).Set("", []string{"1"})
			tx.GetCollection(VARIABLE_REQBODY_PROCESSOR_ERROR_MSG).Set("", []string{string(err.Error())})
			return err
		}
		tx.SetFiles(req.MultipartForm.File)
		tx.SetArgsPost(req.MultipartForm.Value)
	case REQUEST_BODY_PROCESSOR_JSON:
		buf := new(strings.Builder)
		io.Copy(buf, reader)
		b := buf.String()
		tx.GetCollection(VARIABLE_REQUEST_BODY).Set("", []string{b})
	}

	return nil
}

//Sets request_cookies and request_cookies_names
func (tx *Transaction) SetRequestCookies(cookies []*http.Cookie) {
	for _, c := range cookies {
		tx.Collections[VARIABLE_REQUEST_COOKIES].Add(c.Name, c.Value)
		tx.Collections[VARIABLE_REQUEST_COOKIES_NAMES].Add("", c.Name)
	}
}

//sets response_body and response_body_length, it won't work if response_body_inpsection is off
func (tx *Transaction) SetResponseBody(body []byte, length int64) {
	// TBI
}

//Sets response_headers, response_headers_names, response_content_length and response_content_type
func (tx *Transaction) SetResponseHeaders(headers map[string][]string) {
	for h, vs := range headers {
		for _, value := range vs {
			tx.AddResponseHeader(h, value)
		}
	}
}

func (tx *Transaction) AddResponseHeader(key string, value string) {
	if key == "" {
		return
	}
	key = strings.ToLower(key)
	tx.GetCollection(VARIABLE_RESPONSE_HEADERS_NAMES).AddUnique("", key)
	tx.GetCollection(VARIABLE_RESPONSE_HEADERS).Add(key, value)

	//Most headers can be managed like that except cookies
	rhmap := map[string]byte{
		"content-type":   VARIABLE_RESPONSE_CONTENT_TYPE,
		"content-length": VARIABLE_RESPONSE_CONTENT_LENGTH,
	}
	for k, v := range rhmap {
		if k == key {
			tx.GetCollection(v).Add("", value)
		}
	}
}

//Sets response_status
func (tx *Transaction) SetResponseStatus(status int) {
	s := strconv.Itoa(status)
	tx.GetCollection(VARIABLE_RESPONSE_STATUS).Set("", []string{s})
}

//Sets request_uri, request_filename, request_basename, query_string and request_uri_raw
func (tx *Transaction) SetUrl(u *url.URL) {
	RequestBasename := u.EscapedPath()
	a := regexp.MustCompile(`\/|\\`) // \ o /
	spl := a.Split(RequestBasename, -1)
	if len(spl) > 0 {
		RequestBasename = spl[len(spl)-1]
	}
	tx.GetCollection(VARIABLE_REQUEST_URI).Add("", u.String())
	tx.GetCollection(VARIABLE_REQUEST_FILENAME).Add("", u.Path)
	tx.GetCollection(VARIABLE_REQUEST_BASENAME).Add("", RequestBasename)
	tx.GetCollection(VARIABLE_QUERY_STRING).Add("", u.RawQuery)
	tx.GetCollection(VARIABLE_REQUEST_URI_RAW).Add("", u.String())
}

//Sets args_get and args_get_names
func (tx *Transaction) AddGetArgsFromUrl(u *url.URL) {
	params := utils.ParseQuery(u.RawQuery, "&")
	argsg := tx.GetCollection(VARIABLE_ARGS_GET)
	args := tx.GetCollection(VARIABLE_ARGS)
	length := 0
	for k, v := range params {
		for _, vv := range v {
			argsg.Add(k, vv)
			args.Add(k, vv)
			length += len(k) + len(vv) + 1
		}
		tx.GetCollection(VARIABLE_ARGS_GET_NAMES).AddUnique("", k)
		tx.GetCollection(VARIABLE_ARGS_NAMES).AddUnique("", k)
	}
	tx.addArgsLength(length)
}

//Sets args_post and args_post_names
func (tx *Transaction) AddPostArgsFromUrl(u *url.URL) {
	params := utils.ParseQuery(u.RawQuery, "&")
	argsp := tx.GetCollection(VARIABLE_ARGS_POST)
	args := tx.GetCollection(VARIABLE_ARGS)
	length := 0
	for k, v := range params {
		for _, vv := range v {
			argsp.Add(k, vv)
			args.Add(k, vv)
			length += len(k) + len(vv) + 1
		}
		tx.GetCollection(VARIABLE_ARGS_POST_NAMES).AddUnique("", k)
		tx.GetCollection(VARIABLE_ARGS_NAMES).AddUnique("", k)
	}
	tx.addArgsLength(length)
}

func (tx *Transaction) addArgsLength(length int) {
	col := tx.GetCollection(VARIABLE_ARGS_COMBINED_SIZE)
	i := col.GetFirstInt64("") + int64(length)
	istr := strconv.FormatInt(i, 10)
	col.Set("", []string{istr})
}

func (tx *Transaction) AddCookies(cookies string) {
	//TODO implement SecCookieFormat and SecCookieV0Separator
	header := http.Header{}
	header.Add("Cookie", cookies)
	request := http.Request{Header: header}
	tx.SetRequestCookies(request.Cookies())
}

//Adds request_line, request_method, request_protocol, request_basename and request_uri
func (tx *Transaction) SetRequestLine(method string, protocol string, requestUri string) {
	tx.GetCollection(VARIABLE_REQUEST_METHOD).Add("", method)
	tx.GetCollection(VARIABLE_REQUEST_URI).Add("", requestUri)
	tx.GetCollection(VARIABLE_REQUEST_PROTOCOL).Add("", protocol)
	tx.GetCollection(VARIABLE_REQUEST_LINE).Add("", fmt.Sprintf("%s %s %s", method, requestUri, protocol))
}

//Resolves remote hostname and sets remote_host variable
func (tx *Transaction) ResolveRemoteHost() {
	addr, err := net.LookupAddr(tx.GetCollection(VARIABLE_REMOTE_ADDR).GetFirstString(""))
	if err != nil {
		return
	}
	tx.GetCollection(VARIABLE_REMOTE_HOST).Set("", []string{addr[0]})
}

//
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
func (tx *Transaction) ParseRequestString(data string) error {
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
		return err
	}

	tx.ParseRequestObjectHeaders(req)

	b := req.Body.(io.Reader)
	err = tx.SetRequestBody(&b)
	if err != nil {
		return err
	}
	return nil
}

// Parse binary response including body, does only supports http/1.1 and http/1.0
// This function is only intended for testing and debugging
func (tx *Transaction) ParseResponseString(req *http.Request, data string) error {
	//TODO not implemented yet
	/*
		buf := bufio.NewReader(strings.NewReader(data))
		res, err := http.ReadResponse(buf, req)
		if err != nil {
			return err
		}

		err = tx.ParseResponseObject(res)
		if err != nil {
			return err
		}*/
	return nil
}

// Parse golang http request object into transaction
// It will handle all transaction variables required for phase 1
func (tx *Transaction) ParseRequestObjectHeaders(req *http.Request) {
	re := regexp.MustCompile(`^\[(.*?)\]:(\d+)$`)
	matches := re.FindAllStringSubmatch(req.RemoteAddr, -1)
	address := ""
	port := 0
	//no more validations as we don't expect weird ip addresses
	if len(matches) > 0 {
		address = string(matches[0][1])
		port, _ = strconv.Atoi(string(matches[0][2]))
	}
	query := utils.ParseQuery(req.URL.RawQuery, "&")
	tx.SetArgsGet(query)
	tx.SetUrl(req.URL)
	tx.SetRemoteAddress(address, port)
	tx.SetRequestLine(req.Method, req.Proto, req.RequestURI)
	tx.SetRequestHeaders(req.Header)
	tx.SetRequestCookies(req.Cookies())
}

// Parse golang http response object into transaction
func (tx *Transaction) ParseResponseObjectHeaders(res *http.Response) error {
	tx.SetResponseHeaders(res.Header)
	//TBI
	return nil
}

// Execute rules for the specified phase, between 1 and 5
// Returns true if transaction is disrupted
func (tx *Transaction) ExecutePhase(phase int) bool {
	if tx.Disrupted && phase != 5 {
		return true
	}
	if tx.LastPhase == 5 {
		return tx.Disrupted
	}
	tx.LastPhase = phase
	log.Debug(fmt.Sprintf("===== Starting Phase %d =====", phase))
	ts := time.Now().UnixNano()
	usedRules := 0
	tx.LastPhase = phase
	for _, r := range tx.Waf.Rules.GetRules() {
		// Rules with phase 0 will always run
		if r.Phase != phase && r.Phase != 0 {
			continue
		}
		rid := strconv.Itoa(r.Id)
		if r.Id == 0 {
			rid = strconv.Itoa(r.ParentId)
		}
		if utils.ArrayContainsInt(tx.RuleRemoveById, r.Id) {
			log.Debug(fmt.Sprintf("Skipping rule %s because of a ctl", rid))
			continue
		}
		log.Debug(fmt.Sprintf("Evaluating rule %s", rid))
		//we always evaluate secmarkers
		if tx.SkipAfter != "" {
			if r.SecMark == tx.SkipAfter {
				tx.SkipAfter = ""
				log.Debug("Matched SecMarker " + r.SecMark)
			} else {
				log.Debug("Skipping rule because of secmarker, expecting " + tx.SkipAfter)
			}
			continue
		}
		if tx.Skip > 0 {
			tx.Skip--
			//Skipping rule
			log.Debug("Skipping rule because of skip")
			continue
		}
		txr := tx.GetCollection(VARIABLE_RULE)
		txr.Set("id", []string{rid})
		txr.Set("rev", []string{r.Rev})
		txr.Set("severity", []string{r.Severity})
		//txr.Set("logdata", []string{r.LogData})
		txr.Set("msg", []string{r.Msg})
		match := r.Evaluate(tx)
		if len(match) > 0 {
			log.Debug(fmt.Sprintf("Rule %s matched", rid))
			for _, m := range match {
				log.Debug(fmt.Sprintf("MATCH %s:%s", m.Key, m.Value))
			}
		}

		tx.Capture = false //we reset the capture flag on every run
		usedRules++
		if tx.Disrupted && phase != 5 {
			log.Debug(fmt.Sprintf("Disrupted by rule %s", rid))
			// TODO Maybe we shouldnt force phase 5?
			tx.ExecutePhase(5)
			break
		}
	}
	log.Debug(fmt.Sprintf("===== Finished Phase %d =====", phase))
	tx.StopWatches[phase] = int(time.Now().UnixNano() - ts)
	if phase == 5 {
		log.Debug("Saving persistent data")
		tx.savePersistentData()
		if tx.AuditEngine == AUDIT_LOG_RELEVANT && tx.isRelevantStatus() {
			tx.saveLog()
		} else if tx.AuditEngine == AUDIT_LOG_ENABLED {
			tx.saveLog()
		}

	}
	return tx.Disrupted
}

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

func (tx *Transaction) MatchRule(rule *Rule, msgs []string, match []*MatchData) {
	mr := &MatchedRule{
		Messages:    msgs,
		MatchedData: match,
		Rule:        rule,
	}
	tx.MatchedRules = append(tx.MatchedRules, mr)
}

func (tx *Transaction) ToJSON() ([]byte, error) {
	return json.Marshal(tx)
}

func (tx *Transaction) GetTimestamp() string {
	t := time.Unix(0, tx.Timestamp)
	ts := t.Format("02/Jan/2006:15:04:20 -0700")
	return ts
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

func (tx *Transaction) GetField(collection byte, key string, exceptions []string) []*MatchData {
	switch collection {
	case VARIABLE_XML:
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
	case VARIABLE_JSON:
		// TODO, for future versions
		return []*MatchData{}
	default:
		col := tx.GetCollection(collection)
		key = tx.MacroExpansion(key)
		if col == nil {
			return []*MatchData{}
		}
		return col.GetWithExceptions(key, exceptions)
	}

}

func (tx *Transaction) GetCollection(variable byte) *Collection {
	return tx.Collections[variable]
}

func (tx *Transaction) GetCollections() []*Collection {
	return tx.Collections
}

func (tx *Transaction) GetRemovedTargets(id int) []*KeyValue {
	return tx.RuleRemoveTargetById[id]
}

func (tx *Transaction) isRelevantStatus() bool {
	if tx.AuditEngine == AUDIT_LOG_DISABLED {
		return false
	}
	re := tx.Waf.AuditLogRelevantStatus
	status := strconv.Itoa(tx.Status)
	m := re.NewMatcher()
	return m.MatchString(status, 0)
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

func (tx *Transaction) RegisterPersistentCollection(collection string, pc *PersistentCollection) {
	tx.PersistentCollections[collection] = pc
}

func (tx *Transaction) addTemporaryFile(path string) {
	tx.temporaryFiles = append(tx.temporaryFiles, path)
}

//gonna remove it
func (tx *Transaction) GetAuditPath() (string, string) {
	return "/tmp/audit", tx.Id
}
