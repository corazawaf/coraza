// Copyright 2020 Juan Pablo Tosso
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
    "fmt"
	"github.com/jptosso/coraza-waf/pkg/utils"	
    "regexp"
    "strings"
    "mime/multipart"
    "strconv"
    "sync"
    "os/exec"
    "os"
    "bytes"
    "net"
    "net/http"
    "net/url"
    "time"
    "io/ioutil"
    "mime"
    "bufio"
    "path"
    "encoding/json"
    "github.com/antchfx/xmlquery"
    log"github.com/sirupsen/logrus"
)

type MatchedRule struct {
	Id int
	DisruptiveAction int
	Messages []string
	MatchedData []*MatchData
    Rule *Rule
}

type MatchData struct {
    Collection string
    Key string
    Value string
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
    Collections map[string]*LocalCollection
    //This map is used to store persistent collections saves, useful to save them after transaction is finished
    PersistentCollections map[string]*PersistentCollection

    //Response data to be sent
    Status int `json:"status"`

    Logdata []string `json:"logdata"`

    // Rules will be skipped after a rule with this SecMarker is found
    SkipAfter string

    // Copies from the WafInstance
    AuditEngine int
    AuditLogParts []rune
    ForceRequestBodyVariable bool
    RequestBodyAccess bool
    RequestBodyLimit int64
    RequestBodyProcessor int
    ResponseBodyAccess bool
    ResponseBodyLimit int64
    RuleEngine bool
    HashEngine bool
    HashEnforcement bool
    AuditLogType int
    LastPhase int

    // Rules with this id are going to be skipped
    RuleRemoveById []int

    // Used by ctl to remove rule targets by id during the transaction
    RuleRemoveTargetById map[int][]*Collection

    // Will skip this number of rules, this value will be decreased on each skip
    Skip int `json:"skip"`

    // Actions with capture features will read the capture state from this field
    Capture bool `json:"capture"`

    // Contains the ID of the rule that disrupted the transaction
    DisruptiveRuleId int `json:"disruptive_rule_id"`

    // Contains duration in useconds per phase
    StopWatches map[int]int

    // Used for paralelism
    Mux *sync.RWMutex

    // Contains de *engine.Waf instance for the current transaction
    WafInstance *Waf

    XmlDoc *xmlquery.Node
}

func (tx *Transaction) Init(waf *Waf) error{
    tx.Mux = &sync.RWMutex{}
    tx.WafInstance = waf
    tx.Collections = map[string]*LocalCollection{}
    txid := utils.RandomString(19)
    tx.Id = txid
    tx.InitTxCollection()

    tx.SetSingleCollection("id", txid)
    tx.SetSingleCollection("timestamp", strconv.FormatInt(time.Now().UnixNano(), 10))
    tx.Disrupted = false
    //TODO copy objects
    tx.AuditEngine = tx.WafInstance.AuditEngine
    tx.AuditLogParts = tx.WafInstance.AuditLogParts
    tx.RequestBodyAccess = tx.WafInstance.RequestBodyAccess
    tx.RequestBodyLimit = tx.WafInstance.RequestBodyLimit
    tx.ResponseBodyAccess = tx.WafInstance.ResponseBodyAccess
    tx.ResponseBodyLimit = tx.WafInstance.ResponseBodyLimit
    tx.RuleEngine = tx.WafInstance.RuleEngine
    tx.AuditLogType = tx.WafInstance.AuditLogType
    tx.Skip = 0
    tx.PersistentCollections = map[string]*PersistentCollection{}
    tx.RuleRemoveTargetById = map[int][]*Collection{}
    tx.RuleRemoveById = []int{}
    tx.StopWatches = map[int]int{}

    return nil
}

func (tx *Transaction) MacroExpansion(data string) string{
    if data == ""{
        return ""
    }
    //fmt.Println("DATA: ", data)
    r := regexp.MustCompile(`%\{(.*?)\}`)
    matches := r.FindAllString(data, -1)
    for _, v := range matches {
        match := v[2:len(v)-1] 
        matchspl := strings.SplitN(match, ".", 2)
        col := strings.ToLower(matchspl[0])
        key := ""
        if len(matchspl) == 2{
            key = matchspl[1]            
        }
        collection := tx.GetCollection(col)
        if collection == nil{
            return ""
        }
        expansion := collection.Get(strings.ToLower(key))
        if len(expansion) == 0{
            data = strings.ReplaceAll(data, v, "")
        }else{
            data = strings.ReplaceAll(data, v, expansion[0])
        }
    }
    //fmt.Println("Macro: " + data)
    return data
}

//Functions required by web server

//Sets request_headers and request_headers_names
func (tx *Transaction) SetRequestHeaders(headers map[string][]string) {
    hl := tx.GetCollection("request_headers")
    rhn := tx.GetCollection("request_headers_names")
    hl.AddMap(headers)
    for k, _ := range headers{
        if k == "" {
            continue
        }
        k = strings.ToLower(k)
        rhn.AddToKey("", k)
    }
    //default cases for compatibility:
    cl := hl.GetSimple("content-length")[0]
    if cl == "" {
        hl.Set("content-length", []string{"0"})
        cl = "0"
    }
    tx.GetCollection("request_body_length").Set("", []string{cl})
}

//Adds a request header
func (tx *Transaction) AddRequestHeader(key string, value string) {
    key = strings.ToLower(key)
    tx.GetCollection("request_headers_names").AddToKey("", key)
    tx.GetCollection("request_headers").AddToKey(key, value)
}

//Sets args_get, args_get_names. Also adds to args_names and args
func (tx *Transaction) SetArgsGet(args map[string][]string) {
    tx.GetCollection("args_get").AddMap(args)
    tx.GetCollection("args").AddMap(args)
    agn := tx.GetCollection("args_get_names")
    an := tx.GetCollection("args_names")
    for k, _ := range args{
        if k == "" {
            continue
        }
        agn.AddToKey("", k)
        an.AddToKey("", k)
    }  
}

//Sets args_post, args_post_names. Also adds to args_names and args
func (tx *Transaction) SetArgsPost(args map[string][]string) {
    tx.GetCollection("args_post").AddMap(args)
    tx.GetCollection("args").AddMap(args)
    apn := tx.GetCollection("args_post_names")
    an := tx.GetCollection("args_names")
    for k, _ := range args{
        if k == "" {
            continue
        }
        apn.AddToKey("", k)
        an.AddToKey("", k)
    } 
}

func (tx *Transaction) SetAuthType(auth string) {
    tx.GetCollection("auth_type").AddToKey("", auth)
}

//Sets files, files_combined_size, files_names, files_sizes, files_tmpnames, files_tmp_content
func (tx *Transaction) SetFiles(files map[string][]*multipart.FileHeader) {
    fn := tx.GetCollection("files_names")
    fl := tx.GetCollection("files")
    fs := tx.GetCollection("files_sizes")
    totalSize := int64(0)
    for field, fheaders := range files{
        // TODO add them to temporal storage
        fn.AddToKey("", field)
        for _, header := range fheaders{
            fl.AddToKey("", header.Filename)
            totalSize += header.Size
            fs.AddToKey("", fmt.Sprintf("%d", header.Size))
        }
    }
    tx.GetCollection("files_combined_size").AddToKey("", fmt.Sprintf("%d", totalSize))
}

//Will be built from request_line, request_headers and request_body
func (tx *Transaction) SetFullRequest() {
    headers := ""
    for k, v := range tx.GetCollection("request_headers").Data{
        if k == "" {
            continue
        }
        for _, v2 := range v{
            headers += fmt.Sprintf("%s: %s\n", k, v2)
        }
    }
    full_request := fmt.Sprintf("%s\n%s\n\n%s\n", 
        tx.GetCollection("request_line").GetFirstString(),
        headers,
        tx.GetCollection("request_body").GetFirstString())
    tx.GetCollection("full_request").AddToKey("", full_request)
}


//Sets remote_address and remote_port
func (tx *Transaction) SetRemoteAddress(address string, port int) {
    p := strconv.Itoa(port)
    tx.GetCollection("remote_addr").AddToKey("", address)
    tx.GetCollection("remote_port").AddToKey("", p)
}

func (tx *Transaction) SetReqBodyProcessor(processor string){
    tx.GetCollection("reqbody_processor").AddToKey("", processor)
}

func (tx *Transaction) SetRemoteUser(user string) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    tx.Collections["remote_user"].AddToKey("", user)
}


//Sets request_body and request_body_length, it won't work if request_body_inspection is off
func (tx *Transaction) SetRequestBody(body string, length int64, mime string) {
    //TODO requires more validations. chunks, etc
    if !tx.RequestBodyAccess || (tx.RequestBodyLimit > 0 && length > tx.RequestBodyLimit){
        return
    }
    l := strconv.FormatInt(length, 10)
    tx.GetCollection("request_body_length").AddToKey("", l)
    if mime == "application/xml"{
        var err error
        tx.XmlDoc, err = xmlquery.Parse(strings.NewReader(body))
        if err != nil {
            log.Error("Cannot parse XML body for request")
        }        
        tx.GetCollection("request_body").Set("", []string{})
    }else if mime == "application/json" {
        // JSON!
        //doc, err := xmlquery.Parse(strings.NewReader(s))
        //tx.Json = doc
    }else {
        tx.GetCollection("request_body").Set("", []string{body})
    }
    /*
    //TODO shall we do this and force the real length?
    l := strconv.Itoa(length)
    if tx.Collections["request_headers"].Data["content-length"] == nil{
        tx.Collections["request_headers"].Data["content-length"] = []string{l}
    }else{
        tx.Collections["request_headers"].Data["content-length"][0] = l
    }*/    
}

//Sets request_cookies and request_cookies_names
func (tx *Transaction) SetRequestCookies(cookies []*http.Cookie) {
    for _, c := range cookies{
        tx.Collections["request_cookies"].AddToKey(c.Name, c.Value)
        tx.Collections["request_cookies_names"].AddToKey("", c.Name)
    }
}

//sets response_body and response_body_length, it won't work if response_body_inpsection is off
func (tx *Transaction) SetResponseBody(body string, length int64) {
    if !tx.ResponseBodyAccess || length > tx.ResponseBodyLimit{
        return
    }
    l := fmt.Sprintf("%d", length)
    tx.Collections["response_body"].AddToKey("", body)
    tx.Collections["response_body_length"].AddToKey("", l)
}

//Sets response_headers, response_headers_names, response_content_length and response_content_type
func (tx *Transaction) SetResponseHeaders(headers map[string][]string) {
    tx.Collections["response_headers"].AddMap(headers)
    for k, _ := range headers{
        if k == "" {
            continue
        }
        tx.Collections["response_headers_names"].AddToKey("", k)
    }
}

//Sets response_status
func (tx *Transaction) SetResponseStatus(status int) {
    s := strconv.Itoa(status)
    tx.Collections["response_status"].AddToKey("", s)

}

//Sets request_uri, request_filename, request_basename, query_string and request_uri_raw
func (tx *Transaction) SetUrl(u *url.URL){
    RequestBasename := u.EscapedPath()
    a := regexp.MustCompile(`\/|\\`) // \ o /
    spl := a.Split(RequestBasename, -1)
    if len(spl) > 0{
        RequestBasename = spl[len(spl)-1]
    }
    tx.GetCollection("request_uri").AddToKey("", u.String())
    tx.GetCollection("request_filename").AddToKey("", u.Path)
    tx.GetCollection("request_basename").AddToKey("", RequestBasename)
    tx.GetCollection("query_string").AddToKey("", u.RawQuery)
    tx.GetCollection("request_uri_raw").AddToKey("", u.String())
}

//Sets args_get and args_get_names
func (tx *Transaction) AddGetArgsFromUrl(u *url.URL){
    params := u.Query()
    argsg := tx.GetCollection("args_get")
    args := tx.GetCollection("args")
    for k, v := range params{
        for _, vv := range v{
            argsg.AddToKey(k, vv)
            args.AddToKey(k, vv)
        }
        tx.GetCollection("args_get_names").AddToKey("", k)
        tx.GetCollection("args_names").AddToKey("", k)
    }
}

//Sets args_post and args_post_names
func (tx *Transaction) AddPostArgsFromUrl(u *url.URL){
    params := u.Query()
    argsp := tx.GetCollection("args_post")
    args := tx.GetCollection("args")
    for k, v := range params{
        for _, vv := range v{
            argsp.AddToKey(k, vv)
            args.AddToKey(k, vv)
        }
        tx.GetCollection("args_post_names").AddToKey("", k)
        tx.GetCollection("args_names").AddToKey("", k)
    }
}

//Adds request_line, request_method, request_protocol, request_basename and request_uri
func (tx *Transaction) SetRequestLine(method string, protocol string, requestUri string) {
    tx.GetCollection("request_method").AddToKey("", method)
    tx.GetCollection("request_uri").AddToKey("", requestUri)
    tx.GetCollection("request_protocol").AddToKey("", protocol)
    tx.GetCollection("request_line").AddToKey("", fmt.Sprintf("%s %s %s", method, requestUri, protocol))

}

//Adds request_line, request_method, request_protocol, request_basename and request_uri
func (tx *Transaction) SetRequestMethod(method string) {
    tx.Collections["request_method"].AddToKey("", method)
}

//Resolves remote hostname and sets remote_host variable
func (tx *Transaction) ResolveRemoteHost() {
    addr, err := net.LookupAddr(tx.Collections["remote_addr"].GetFirstString())
    if err != nil{
        return
    }
    tx.Collections["remote_host"].AddToKey("", addr[0])
}

//
func (tx *Transaction) CaptureField(index int, value string) {
    i := strconv.Itoa(index)
    tx.Collections["tx"].Data[i] = []string{value}
}

func (tx *Transaction) InitTxCollection(){
    keys := []string{ "args", "args_post", "args_get", "args_names", "args_post_names", "args_get_names", "query_string", "remote_addr", "request_basename", "request_uri", "tx", "remote_port",
                      "request_body", "request_content_type", "request_content_length", "request_cookies", "request_cookies_names",  "request_line", "files_sizes",
                      "request_filename", "request_headers", "request_headers_names", "request_method", "request_protocol", "request_filename", "full_request",
                      "request_uri", "request_line", "response_body", "response_content_length", "response_content_type", "request_cookies", "request_uri_raw",
                      "response_headers", "response_headers_names", "response_protocol", "response_status", "appid", "id", "timestamp", "files_names", "files",
                      "files_combined_size", "reqbody_processor", "request_body_length", "xml", "matched_vars", "rule"}
    
    for _, k := range keys{
        tx.Collections[k] = &LocalCollection{}
        tx.Collections[k].Init(k)
    }

    for i := 0; i <= 10; i++ {
        is := strconv.Itoa(i)
        tx.Collections["tx"].Data[is] = []string{}
    }    
}

//Reset the capture collection for further uses
func (tx *Transaction) ResetCapture(){
    //We reset capture 0-9
    ctx := tx.GetCollection("tx")
    for i := 0; i < 10; i++{
        si := strconv.Itoa(i)
        ctx.Set(si, []string{""})
    }
}


// Parse binary request including body, does only supports http/1.1 and http/1.0
func (tx *Transaction) ParseRequestString(data string) error{
    buf := bufio.NewReader(strings.NewReader(data))
    req, err := http.ReadRequest(buf)
    if err != nil {
        return err
    }

    err = tx.ParseRequestObject(req)
    if err != nil {
        return err
    }
    return nil
}

// Parse binary response including body, does only supports http/1.1 and http/1.0
func (tx *Transaction) ParseResponseString(req *http.Request, data string) error{
    buf := bufio.NewReader(strings.NewReader(data))
    res, err := http.ReadResponse(buf, req)
    if err != nil {
        return err
    }

    err = tx.ParseResponseObject(res)
    if err != nil {
        return err
    }
    return nil
}

// Parse golang http request object into transaction
func (tx *Transaction) ParseRequestObject(req *http.Request) error{
    re := regexp.MustCompile(`^\[(.*?)\]:(\d+)$`)
    matches := re.FindAllStringSubmatch(req.RemoteAddr, -1)
    address := ""
    port := 0
    //no more validations as we don't spake weird ip addresses
    if len(matches) > 0 {
        address = string(matches[0][1])
        port, _ = strconv.Atoi(string(matches[0][2]))
    }
    tx.SetRequestHeaders(req.Header)
    tx.SetArgsGet(req.URL.Query())
    tx.SetUrl(req.URL)
    tx.SetRemoteAddress(address, port)
    tx.SetRequestCookies(req.Cookies())
    tx.SetRequestLine(req.Method, req.Proto, req.RequestURI)
    tx.ExecutePhase(1)

    if tx.Disrupted || req.Body == nil{
        return nil
    }

    //phase 2
    cl := tx.GetCollection("request_headers").GetSimple("content-type")
    ctype := "text/plain"
    ct := ""
    if len(cl) > 0{
        spl := strings.SplitN(cl[0], ";", 2)
        ctype = spl[0]
        ct = cl[0]
    }
    //f.tx.SetReqBodyProcessor("URLENCODED")
    switch ctype {
    case "application/x-www-form-urlencoded":
        //url encode
        err := req.ParseForm()
        if err != nil {
            return err
        }
        tx.SetArgsPost(req.PostForm)
        break
    case "multipart/form-data":
        //multipart
        //url encode
        tx.SetReqBodyProcessor("MULTIPART")
        err := req.ParseMultipartForm(tx.RequestBodyLimit)
        if err != nil {
            panic(err)
            return err
        }
        tx.SetFiles(req.MultipartForm.File)
        tx.SetArgsPost(req.MultipartForm.Value)
        break
    }
    body, err := ioutil.ReadAll(req.Body)
    defer req.Body.Close()
    //TODO BUFFERING
    if err != nil{
        return err
    }
    tx.SetRequestBody(string(body), int64(len(body)), ct)    
    tx.ExecutePhase(2)     
    return nil
}

// Parse golang http response object into transaction
func (tx *Transaction) ParseResponseObject(res *http.Response) error{
    tx.SetResponseHeaders(res.Header)
    //res.Header.Set("X-Coraza-Waf", "woo")
    if tx.ExecutePhase(3) {
        return nil
    }
    //TODO response body
    tx.ExecutePhase(4)
    return nil
}

// Parse request body from a string
// Avoid it as it is a heavy load operation
func (tx *Transaction) ParseRequestBodyBinary(mimeval string, body string) error{
    // Maybe it would be easier to create an http instance with fake headers and append the body
    _, params, _ := mime.ParseMediaType(mimeval)
    boundary := params["boundary"]
    mr := multipart.NewReader(strings.NewReader(body), boundary)
    files := map[string][]*multipart.FileHeader{}
    args := map[string][]string{}
    for {
        p, err := mr.NextPart()
        if err != nil {
            break
        }
        data, err := ioutil.ReadAll(p)
        if err != nil {
            return err
        }
        key := p.FormName()
        file := p.FileName()
        mpf := &multipart.FileHeader{
            Filename: file, 
            Header: p.Header, 
            Size: int64(len(data)),
        }
        if files[key] == nil{
            files[key] = []*multipart.FileHeader{mpf}
        }else{
            files[key] = append(files[key], mpf)
        }
        if args[key] == nil{
            args[key] = []string{string(data)}
        }else{
            args[key] = append(args[key], string(data))
        }
    }
    tx.SetFiles(files)
    tx.SetArgsPost(args)
    return nil
}

// Execute rules for the specified phase, between 1 and 5
// Returns true if transaction is disrupted
func (tx *Transaction) ExecutePhase(phase int) bool{
    ts := time.Now().UnixNano()
    usedRules := 0
    tx.LastPhase = phase
    for _, r := range tx.WafInstance.Rules.GetRules() {
        //we always execute secmarkers
        if r.Phase != phase {
            continue
        }

        if tx.SkipAfter != ""{
            if r.SecMark != tx.SkipAfter{
                continue
            }else{
                tx.SkipAfter = ""
            }
        }
        if tx.Skip > 0{
            tx.Skip--
            //Skipping rule
            continue
        }
        txr := tx.GetCollection("rule")
        rid := strconv.Itoa(r.Id)
        txr.Set("id", []string{rid})
        txr.Set("rev", []string{r.Rev})
        txr.Set("severity", []string{r.Severity})
        //txr.Set("logdata", []string{r.LogData})
        txr.Set("msg", []string{r.Msg})
        r.Evaluate(tx)
        tx.Capture = false //we reset the capture flag on every run
        usedRules++
    }
    tx.Mux.Lock()
    tx.StopWatches[phase] = int(time.Now().UnixNano() - ts)
    tx.Mux.Unlock()
    if tx.Disrupted || phase == 5{
        if phase != 5{
            tx.ExecutePhase(5)
        }else if tx.IsRelevantStatus(){
            tx.SaveLog()
            tx.SavePersistentData()
        }
    }
    return tx.Disrupted
}

func (tx *Transaction) MatchRule(rule *Rule, msgs []string, match []*MatchData){
    mr := &MatchedRule{
        Id: rule.Id,
        DisruptiveAction: 0,
        Messages: msgs,
        MatchedData: match,
        Rule: rule,
    }
    m := tx.GetCollection("matched_vars")
    tx.MatchedRules = append(tx.MatchedRules, mr)
    mv := m.GetSimple("")
    for _, m := range match{
        mv = append(mv, m.Value)
    }
    m.Set("", mv)
}

func (tx *Transaction) InitCollection(key string){
    col := &LocalCollection{}
    col.Init(key)
    tx.Mux.Lock()
    defer tx.Mux.Unlock()    
    tx.Collections[key] = col

}

func (tx *Transaction) ToJSON() ([]byte, error){
    return json.Marshal(tx)
}

func (tx *Transaction) SetSingleCollection(key string, value string){ 
    tx.Collections[key] = &LocalCollection{}
    tx.Collections[key].Init(key)
    tx.Collections[key].Add("", []string{value})
}

func (tx *Transaction) GetSingleCollection(key string) string{ 
    key = strings.ToLower(key)
    col := tx.GetCollection(key)
    if col == nil{
        return ""
    }
    return col.GetFirstString()
}

func (tx *Transaction) GetTimestamp() string{
    t := time.Unix(0, tx.GetCollection("timestamp").GetFirstInt64())
    ts := t.Format("02/Jan/2006:15:04:20 -0700")    
    return ts
}

func (tx *Transaction) GetStopWatch() string {  
    ts := tx.GetCollection("timestamp").GetFirstInt64()
    sum := 0
    for _, r := range tx.StopWatches{
        sum += r
    }
    diff := time.Now().UnixNano()-ts
    sw := fmt.Sprintf("%d %d; combined=%d, p1=%d, p2=%d, p3=%d, p4=%d, p5=%d",
        ts, diff, sum, tx.StopWatches[1], tx.StopWatches[2], tx.StopWatches[3], tx.StopWatches[4], tx.StopWatches[5])
    return sw
}

func (tx *Transaction) GetField(collection string, key string, exceptions []string) ([]*MatchData){     
    switch collection{
    case "xml":
        if tx.XmlDoc == nil{
            return []*MatchData{}
        }
        data, err := xmlquery.QueryAll(tx.XmlDoc, key)
        if err != nil{
            log.Error("Invalid xpath expression " + key)
            return []*MatchData{}
        }
        res := []*MatchData{}
        for _, d := range data {
            res = append(res, &MatchData{
                Collection: "XML",
                Value: d.InnerText(),
            })
        }
        return res
    case "json":
        // TODO, for future versions
        return []*MatchData{}
    default:

        col := tx.GetCollection(collection)
        key = tx.MacroExpansion(key)
        if col == nil{
            return []*MatchData{}
        }
        return col.GetWithExceptions(key, exceptions)        
    }

}

func (tx *Transaction) GetCollection(name string) *LocalCollection{     
    tx.Mux.RLock()
    defer tx.Mux.RUnlock()
    return tx.Collections[name] 
}

func (tx *Transaction) GetCollections() map[string]*LocalCollection{     
    tx.Mux.RLock()
    defer tx.Mux.RUnlock()
    return tx.Collections
}

func (tx *Transaction) GetRemovedTargets(id int) []*Collection{     
    tx.Mux.RLock()
    defer tx.Mux.RUnlock()
    return tx.RuleRemoveTargetById[id]
}

//Returns directory and filename
func (tx *Transaction) GetAuditPath() (string, string){
    t := time.Unix(0, tx.GetCollection("timestamp").GetFirstInt64())

    // append the two directories
    p2 := fmt.Sprintf("/%s/%s/", t.Format("20060102"), t.Format("20060102-1504"))
    logdir:= path.Join(tx.WafInstance.AuditLogStorageDir, p2)
    // Append the filename
    filename := fmt.Sprintf("/%s-%s", t.Format("20060102-150405"), tx.Id)
    return logdir, filename
}

func (tx *Transaction) IsRelevantStatus() bool{
    if tx.AuditEngine == AUDIT_LOG_DISABLED{
        return false
    }
    if tx.AuditEngine == AUDIT_LOG_ENABLED {
        return true
    }
    re := tx.WafInstance.AuditLogRelevantStatus
    status := strconv.Itoa(tx.Status)
    m := re.NewMatcher()
    return m.MatchString(status, 0)
}

func (tx *Transaction) ToAuditJson() []byte{
    al := tx.ToAuditLog()
    return al.ToJson()
}

func (tx *Transaction) ToAuditLog() *AuditLog{
    al := &AuditLog{}
    al.Init(tx)
    return al
}

func (tx *Transaction) SaveLog() error{
    return tx.WafInstance.Logger.WriteAudit(tx)
}

// Get html error page as a string
func (tx *Transaction) GetErrorPage() string{
    switch tx.WafInstance.ErrorPageMethod{
    case ERROR_PAGE_DEBUG:
        buff := "<link href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css\" rel=\"stylesheet\">"
        buff += "<h1>Coraza Security Error - Debug Mode</h1>"
        buff += "<h3>Rules Triggered</h3>"
        buff += "<table class='table table-striped'><thead><tr><th>ID</th><th>Action</th><th>Msg</th><th>Match</th><th>Raw Rule</th></tr></thead><tbody>"
        /*
        for _, mr := range tx.MatchedRules{
            match := strings.Join(mr.MatchedData, "<br>")
            rule := mr.Rule.Raw
            for child := mr.Rule.Chain; child != nil; child = child.Chain{
                rule += "<br><strong>CHAIN:</strong> " + child.Raw
            }
            buff += fmt.Sprintf("<tr><td>%d</td><td>%d</td><td></td><td>%s</td><td>%s</td></tr>", mr.Id, mr.DisruptiveAction, match, rule)
        }*/
        buff += "</tbody></table>"

        buff += "<h3>Transaction Collections</h3>"
        buff += "<table class='table table-striped'><thead><tr><th>Collection</th><th>Key</th><th>Values</th></tr></thead><tbody>"
        for key, col := range tx.GetCollections(){
            for k2, data := range col.Data{
                d := strings.Join(data, "<br>")
                buff += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>", key, k2, d)
            }
        }
        buff += "</tbody></table>"
        var prettyJSON bytes.Buffer
        json.Indent(&prettyJSON, tx.ToAuditJson(), "", "\t")        
        buff += fmt.Sprintf("<h3>Audit Log</h3><pre>%s</pre>", prettyJSON.String())
        return buff
    case ERROR_PAGE_SCRIPT:
        cmd := exec.Command(tx.WafInstance.ErrorPageFile)
        path, file := tx.GetAuditPath()
        cmd.Env = append(os.Environ(),
            "TRANSACTION_ID=" + tx.Id, 
            "AUDIT_FILE=" + path + file,
            "DISRUPTIVE_RULE_ID=" + strconv.Itoa(tx.DisruptiveRuleId),
        )
        stdout, err := cmd.Output()
        if err != nil {
            return "Error script failed"
        }
        return string(stdout)
    case ERROR_PAGE_FILE:
        return tx.WafInstance.ErrorPageFile
    case ERROR_PAGE_INLINE:
        return tx.WafInstance.ErrorPageFile        
    }
    return fmt.Sprintf("<h1>Error 403</h1><!-- %s -->", tx.Id)
}

// Save persistent collections to persistence engine
func (tx *Transaction) SavePersistentData() {
    for col, pc := range tx.PersistentCollections{
        pc.SetData(tx.GetCollection(col).Data)
        pc.Save()
    }
}

// Removes the VARIABLE/TARGET from the rule ID
func (tx *Transaction) RemoveRuleTargetById(id int, col string, key string){
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    c := &Collection{col, key}
    if tx.RuleRemoveTargetById[id] == nil{
        tx.RuleRemoveTargetById[id] = []*Collection{
            c,
        }
    }else{
        tx.RuleRemoveTargetById[id] = append(tx.RuleRemoveTargetById[id], c)
    }
}