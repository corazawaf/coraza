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
	Name string
	Key string
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
	Collections map[string]*Collection
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
	tx.Collections = map[string]*Collection{}
	txid := utils.RandomString(19)
	tx.Id = txid
	keys := []string{"args", "args_combined_size", "args_get", "args_get_names", "args_names",
		"args_post", "args_post_names", "auth_type", "duration", "env", "files", "files_combined_size",
		"files_names", "full_request", "full_request_length", "files_sizes", "files_tmpnames",
		"files_tmp_content", "geo", "highest_severity", "inbound_data_error", "matched_var", "matched_vars",
		"matched_var_name", "matched_vars_names", "modsec_build", "multipart_crlf_lf_lines",
		"multipart_filename", "multipart_name", "multipart_strict_error", "multipart_unmatched_boundary",
		"outbound_data_error", "path_info", "perf_all", "perf_combined", "perf_gc", "perf_logging",
		"perf_phase1", "perf_phase2", "perf_phase3", "perf_phase4", "perf_phase5", "perf_rules",
		"perf_sread", "perf_swrite", "query_string", "remote_addr", "remote_host", "remote_port",
		"remote_user", "reqbody_error", "reqbody_error_msg", "reqbody_processor", "request_basename",
		"request_body", "request_body_length", "request_cookies", "request_cookies_names", "request_filename",
		"request_headers", "request_headers_names", "request_line", "request_method", "request_protocol",
		"request_uri", "request_uri_raw", "response_body", "response_content_length", "response_content_type",
		"response_headers", "response_headers_names", "response_protocol", "response_status", "rule",
		"script_basename", "script_filename", "script_gid", "script_groupname", "script_mode", "script_uid",
		"script_username", "sdbm_delete_error", "server_addr", "server_name", "server_port", "session",
		"sessionid", "status_line", "stream_input_body", "stream_output_body", "time", "time_day", "time_epoch",
		"time_hour", "time_min", "time_mon", "time_sec", "time_wday", "time_year", "tx", "unique_id",
		"urlencoded_error", "userid", "useragent_ip", "webappid", "webserver_error_log", "xml", "request_content_type",
		"reqbody_processor_error", "reqbody_processor_error_msg"}
	for _, k := range keys {
		tx.Collections[k] = &Collection{}
		tx.Collections[k].Init(k)
	}

	for i := 0; i <= 10; i++ {
		is := strconv.Itoa(i)
		tx.GetCollection("tx").Set(is, []string{})
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
		col := strings.ToLower(matchspl[0])
		key := ""
		if len(matchspl) == 2 {
			key = matchspl[1]
		}
		collection := tx.GetCollection(col)
		if collection == nil {
			return ""
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
	tx.GetCollection("request_headers_names").AddUnique("", key)
	tx.GetCollection("request_headers").Add(key, value)

	//Most headers can be managed like that except cookies
	rhmap := map[string]string{
		"content-type":   "request_content_type",
		"content-length": "request_body_length",
	}
	for k, v := range rhmap {
		if k == key {
			tx.GetCollection(v).Add("", value)
		}
	}
}

//Sets args_get, args_get_names. Also adds to args_names and args
func (tx *Transaction) SetArgsGet(args map[string][]string) {
	tx.GetCollection("args_get").AddMap(args)
	tx.GetCollection("args").AddMap(args)
	agn := tx.GetCollection("args_get_names")
	an := tx.GetCollection("args_names")
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
	tx.GetCollection("args_post").AddMap(args)
	tx.GetCollection("args").AddMap(args)
	apn := tx.GetCollection("args_post_names")
	an := tx.GetCollection("args_names")
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
	fn := tx.GetCollection("files_names")
	fl := tx.GetCollection("files")
	fs := tx.GetCollection("files_sizes")
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
	tx.GetCollection("files_combined_size").Add("", fmt.Sprintf("%d", totalSize))
}

//a FULL_REQUEST variable will be set from request_line, request_headers and request_body
func (tx *Transaction) SetFullRequest() {
	headers := ""
	for k, v := range tx.GetCollection("request_headers").GetData() {
		if k == "" {
			continue
		}
		for _, v2 := range v {
			headers += fmt.Sprintf("%s: %s\n", k, v2)
		}
	}
	full_request := fmt.Sprintf("%s\n%s\n\n%s\n",
		tx.GetCollection("request_line").GetFirstString(""),
		headers,
		tx.GetCollection("request_body").GetFirstString(""))
	tx.GetCollection("full_request").Add("", full_request)
}

//Sets remote_address and remote_port
func (tx *Transaction) SetRemoteAddress(address string, port int) {
	p := strconv.Itoa(port)
	tx.GetCollection("remote_addr").Add("", address)
	tx.GetCollection("remote_port").Add("", p)
}

func (tx *Transaction) SetReqBodyProcessor(processor string) {
	tx.GetCollection("reqbody_processor").Add("", processor)
}

//Sets request_body and request_body_length, it won't work if request_body_inspection is off
func (tx *Transaction) SetRequestBody(body *io.Reader) error {
	if !tx.RequestBodyAccess { // || (tx.RequestBodyLimit > 0 && length > tx.RequestBodyLimit) {
		return nil
	}

	transfer := tx.GetCollection("request_headers").GetFirstString("transfer")
	length := tx.GetCollection("request_headers").GetFirstInt64("content-length")
	mime := tx.GetCollection("request_headers").GetFirstString("content-type")
	mime = strings.ToLower(mime)
	chunked := strings.EqualFold(transfer, "chunked")
	var reader io.Reader

	// Chunked requests will always be written to a temporary file
	if !chunked && length > tx.RequestBodyLimit && tx.Waf.RequestBodyLimitAction == REQUEST_BODY_LIMIT_ACTION_REJECT {
		return errors.New("Rejected request body size")
	} else if !chunked && length > tx.RequestBodyLimit && tx.Waf.RequestBodyLimitAction == REQUEST_BODY_LIMIT_ACTION_PROCESS_PARTIAL {
		tx.GetCollection("inbound_error_data").Set("", []string{"1"})
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
		tx.GetCollection("request_body").Set("", []string{b})
		if err != nil {
			tx.GetCollection("reqbody_processor_error").Set("", []string{"1"})
			tx.GetCollection("reqbody_processor_error_msg").Set("", []string{string(err.Error())})
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
			tx.GetCollection("reqbody_processor_error").Set("", []string{"1"})
			tx.GetCollection("reqbody_processor_error_msg").Set("", []string{string(err.Error())})
			return err
		}
	case REQUEST_BODY_PROCESSOR_MULTIPART:
		req, _ := http.NewRequest("GET", "/", reader)
		req.Header.Set("Content-Type", mime)
		err := req.ParseMultipartForm(1000000000)
		defer req.Body.Close()
		if err != nil {
			tx.GetCollection("reqbody_processor_error").Set("", []string{"1"})
			tx.GetCollection("reqbody_processor_error_msg").Set("", []string{string(err.Error())})
			return err
		}
		tx.SetFiles(req.MultipartForm.File)
		tx.SetArgsPost(req.MultipartForm.Value)
	case REQUEST_BODY_PROCESSOR_JSON:
		buf := new(strings.Builder)
		io.Copy(buf, reader)
		b := buf.String()
		tx.GetCollection("request_body").Set("", []string{b})
	}
	l := strconv.FormatInt(length, 10)
	tx.GetCollection("request_body_length").Add("", l)

	return nil
}

//Sets request_cookies and request_cookies_names
func (tx *Transaction) SetRequestCookies(cookies []*http.Cookie) {
	for _, c := range cookies {
		tx.Collections["request_cookies"].Add(c.Name, c.Value)
		tx.Collections["request_cookies_names"].Add("", c.Name)
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
	tx.GetCollection("response_headers_names").AddUnique("", key)
	tx.GetCollection("response_headers").Add(key, value)

	//Most headers can be managed like that except cookies
	rhmap := map[string]string{
		"content-type":   "response_content_type",
		"content-length": "response_body_length",
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
	tx.GetCollection("response_status").Set("", []string{s})
}

//Sets request_uri, request_filename, request_basename, query_string and request_uri_raw
func (tx *Transaction) SetUrl(u *url.URL) {
	RequestBasename := u.EscapedPath()
	a := regexp.MustCompile(`\/|\\`) // \ o /
	spl := a.Split(RequestBasename, -1)
	if len(spl) > 0 {
		RequestBasename = spl[len(spl)-1]
	}
	tx.GetCollection("request_uri").Add("", u.String())
	tx.GetCollection("request_filename").Add("", u.Path)
	tx.GetCollection("request_basename").Add("", RequestBasename)
	tx.GetCollection("query_string").Add("", u.RawQuery)
	tx.GetCollection("request_uri_raw").Add("", u.String())
}

//Sets args_get and args_get_names
func (tx *Transaction) AddGetArgsFromUrl(u *url.URL) {
	params := utils.ParseQuery(u.RawQuery, "&")
	argsg := tx.GetCollection("args_get")
	args := tx.GetCollection("args")
	length := 0
	for k, v := range params {
		for _, vv := range v {
			argsg.Add(k, vv)
			args.Add(k, vv)
			length += len(k) + len(vv) + 1
		}
		tx.GetCollection("args_get_names").AddUnique("", k)
		tx.GetCollection("args_names").AddUnique("", k)
	}
	tx.addArgsLength(length)
}

//Sets args_post and args_post_names
func (tx *Transaction) AddPostArgsFromUrl(u *url.URL) {
	params := utils.ParseQuery(u.RawQuery, "&")
	argsp := tx.GetCollection("args_post")
	args := tx.GetCollection("args")
	length := 0
	for k, v := range params {
		for _, vv := range v {
			argsp.Add(k, vv)
			args.Add(k, vv)
			length += len(k) + len(vv) + 1
		}
		tx.GetCollection("args_post_names").AddUnique("", k)
		tx.GetCollection("args_names").AddUnique("", k)
	}
	tx.addArgsLength(length)
}

func (tx *Transaction) addArgsLength(length int) {
	col := tx.GetCollection("args_combined_size")
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
	tx.GetCollection("request_method").Add("", method)
	tx.GetCollection("request_uri").Add("", requestUri)
	tx.GetCollection("request_protocol").Add("", protocol)
	tx.GetCollection("request_line").Add("", fmt.Sprintf("%s %s %s", method, requestUri, protocol))
}

//Resolves remote hostname and sets remote_host variable
func (tx *Transaction) ResolveRemoteHost() {
	addr, err := net.LookupAddr(tx.GetCollection("remote_addr").GetFirstString(""))
	if err != nil {
		return
	}
	tx.GetCollection("remote_host").Set("", []string{addr[0]})
}

//
func (tx *Transaction) CaptureField(index int, value string) {
	i := strconv.Itoa(index)
	tx.GetCollection("tx").Set(i, []string{value})
}

//Reset the capture collection for further uses
func (tx *Transaction) ResetCapture() {
	//We reset capture 0-9
	ctx := tx.GetCollection("tx")
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
		txr := tx.GetCollection("rule")
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
	mvs := tx.GetCollection("matched_vars")
	mvs.Reset()
	// Last value
	mv := tx.GetCollection("matched_var")
	mv.Reset()
	// Last key
	mvn := tx.GetCollection("matched_var_name")
	mvn.Reset()
	// Array of keys
	mvns := tx.GetCollection("matched_vars_names")
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

func (tx *Transaction) GetField(collection string, key string, exceptions []string) []*MatchData {
	switch collection {
	case "xml":
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
	case "json":
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

func (tx *Transaction) GetCollection(name string) *Collection {
	return tx.Collections[name]
}

func (tx *Transaction) GetCollections() map[string]*Collection {
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
func (tx *Transaction) RemoveRuleTargetById(id int, col string, key string) {
	c := &KeyValue{col, key}
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