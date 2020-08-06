package engine

import (
    "fmt"
	"github.com/jptosso/coraza-waf/pkg/utils"	
    "regexp"
    "strings"
    "mime/multipart"
    "strconv"
    "sync"
    "net"
    "net/http"
    "net/url"
    "time"
    "encoding/json"
)

type MatchedRule struct {
	Id int
	Action string
	Messages []string
	MatchedData []string
    Rule *Rule
}

type Transaction struct {
	//Options
	Log bool `json:"log"`
    Id string

    MatchedRules []*MatchedRule `json:"matched_rules"`
    Disrupted bool `json:"disrupted"`
    ActionParams string `json:"action_params"`

    Profiling int64 `json:"profiling"`

    Collections map[string]*utils.LocalCollection

    //Response data to be sent
    Status int `json:"status"`
    Logdata []string `json:"logdata"`
    
    NewPersistentCollections map[string]string

    AuditLog bool
    SkipAfter string

    AuditLogPath1 string
    DefaultAction string
    AuditEngine bool
    AuditLogParts []int
    DebugLogLevel int
    ForceRequestBodyVariable bool
    RequestBodyAccess bool
    RequestBodyLimit int64
    RequestBodyProcessor bool
    ResponseBodyAccess bool
    ResponseBodyLimit int64
    RuleEngine bool
    RuleRemoveById []int
    RuleRemoveByMsg []string
    RuleRemoveByTag []string
    HashEngine bool
    HashEnforcement bool

    Skip int `json:"skip"`
    Capture bool `json:"capture"`

    //Used for the capture action, it will store the last results from RX to add them to TX:0..10
    DisruptiveRuleId int `json:"disruptive_rule_id"`

    RemoveRuleById []int
    RemoveRuleByTag []string
    RemoveTargetFromTag map[string][]*Collection //rt[rule-tag]
    RemoveTargetFromId map[int][]*Collection

    Mux *sync.RWMutex
    WafInstance *Waf
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
        collection := tx.Collections[col]
        if collection == nil{
            return ""
        }
        expansion := collection.Get(key)
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
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    tx.Collections["request_headers"].AddMap(headers)
    for k, _ := range headers{
        if k == "" {
            continue
        }
        tx.Collections["request_headers_names"].AddToKey("", k)
    }
    //default cases for compatibility:
    if tx.Collections["request_headers"].Data["content-length"] == nil {
        tx.Collections["request_headers"].Data["content-length"] = []string{"0"}
    }
    if tx.Collections["request_headers"].Data["content-type"] == nil {
        //is this the default content-type?
        tx.Collections["request_headers"].Data["content-type"] = []string{"text/plain"}
    }
}

//Adds a request header
func (tx *Transaction) AddRequestHeader(key string, value string) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    tx.Collections["request_headers_names"].AddToKey("", key)
    tx.Collections["request_headers"].AddToKey(key, value)
}

//Sets args_get, args_get_names. Also adds to args_names and args
func (tx *Transaction) SetArgsGet(args map[string][]string) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    tx.Collections["args_get"].AddMap(args)
    tx.Collections["args"].AddMap(args)
    for k, _ := range args{
        if k == "" {
            continue
        }
        tx.Collections["args_get_names"].AddToKey("", k)
        tx.Collections["args_names"].AddToKey("", k)
    }  
}

//Sets args_post, args_post_names. Also adds to args_names and args
func (tx *Transaction) SetArgsPost(args map[string][]string) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    tx.Collections["args_post"].AddMap(args)
    tx.Collections["args"].AddMap(args)
    for k, _ := range args{
        if k == "" {
            continue
        }
        tx.Collections["args_post_names"].AddToKey("", k)
        tx.Collections["args_names"].AddToKey("", k)
    }  
}

func (tx *Transaction) SetAuthType(auth string) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    tx.Collections["auth_type"].AddToKey("", auth)
}

//Sets files, files_combined_size, files_names, files_sizes, files_tmpnames, files_tmp_content
func (tx *Transaction) SetFiles(files map[string][]*multipart.FileHeader) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    totalSize := int64(0)
    for field, fheaders := range files{
        tx.Collections["files_names"].AddToKey("", field)
        for _, header := range fheaders{
            tx.Collections["files"].AddToKey("", header.Filename)
            totalSize += header.Size
            tx.Collections["files_sizes"].AddToKey("", fmt.Sprintf("%d", header.Size))
        }
    }
    tx.Collections["files_combined_size"].AddToKey("", fmt.Sprintf("%d", totalSize))
}

//Will be built from request_line, request_headers and request_body
func (tx *Transaction) SetFullRequest() {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    headers := ""
    for k, v := range tx.Collections["request_headers"].Data{
        if k == "" {
            continue
        }
        for _, v2 := range v{
            headers += fmt.Sprintf("%s: %s\n", k, v2)
        }
    }
    full_request := fmt.Sprintf("%s\n%s\n%s", 
        tx.Collections["request_line"].GetFirstString(),
        headers,
        tx.Collections["request_body"].GetFirstString())
    tx.Collections["full_request"].AddToKey("", full_request)
}


//Sets remote_address and remote_port
func (tx *Transaction) SetRemoteAddress(address string, port int) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    p := strconv.Itoa(port)
    tx.Collections["remote_addr"].AddToKey("", address)
    tx.Collections["remote_port"].AddToKey("", p)
}

func (tx *Transaction) SetReqBodyProcessor(processor string){
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    tx.Collections["reqbody_processor"].AddToKey("", processor)
}

func (tx *Transaction) SetRemoteUser(user string) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    tx.Collections["remote_user"].AddToKey("", user)
}


//Sets request_body and request_body_length, it won't work if request_body_inspection is off
func (tx *Transaction) SetRequestBody(body string, length int64) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    if !tx.RequestBodyAccess || length > tx.RequestBodyLimit{
        return
    }
    l := fmt.Sprintf("%d", length)
    tx.Collections["request_body"].AddToKey("", body)
    tx.Collections["request_body_length"].AddToKey("", l)
}

//Sets request_cookies and request_cookies_names
func (tx *Transaction) SetRequestCookies(cookies []*http.Cookie) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    for _, c := range cookies{
        tx.Collections["request_cookies"].AddToKey(c.Name, c.Value)
        tx.Collections["request_cookies_names"].AddToKey("", c.Name)
    }
}

//sets response_body and response_body_length, it won't work if response_body_inpsection is off
func (tx *Transaction) SetResponseBody(body string, length int64) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    if !tx.ResponseBodyAccess || length > tx.ResponseBodyLimit{
        return
    }
    l := fmt.Sprintf("%d", length)
    tx.Collections["response_body"].AddToKey("", body)
    tx.Collections["response_body_length"].AddToKey("", l)
}

//Sets response_headers, response_headers_names, response_content_length and response_content_type
func (tx *Transaction) SetResponseHeaders(headers map[string][]string) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
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
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    s := strconv.Itoa(status)
    tx.Collections["response_status"].AddToKey("", s)

}

//Sets request_uri, request_filename, request_basename, query_string and request_uri_raw
func (tx *Transaction) SetUrl(u *url.URL){
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    RequestBasename := u.EscapedPath()
    a := regexp.MustCompile(`\/|\\`) // \ o /
    spl := a.Split(RequestBasename, -1)
    if len(spl) > 0{
        RequestBasename = spl[len(spl)-1]
    }
    tx.Collections["request_uri"].AddToKey("", u.EscapedPath())
    tx.Collections["request_filename"].AddToKey("", u.Path)
    tx.Collections["request_basename"].AddToKey("", RequestBasename)
    tx.Collections["query_string"].AddToKey("", u.RawQuery)
    tx.Collections["request_uri_raw"].AddToKey("", u.String())
}

//Sets args_get and args_get_names
func (tx *Transaction) AddGetArgsFromUrl(u *url.URL){
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    params := u.Query()
    for k, v := range params{
        for _, vv := range v{
            tx.Collections["args_get"].AddToKey(k, vv)
            tx.Collections["args"].AddToKey(k, vv)
        }
        tx.Collections["args_get_names"].AddToKey("", k)
        tx.Collections["args_names"].AddToKey("", k)
    }
}

//Sets args_post and args_post_names
func (tx *Transaction) AddPostArgsFromUrl(u *url.URL){
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    params := u.Query()
    for k, v := range params{
        for _, vv := range v{
            tx.Collections["args_post"].AddToKey(k, vv)
            tx.Collections["args"].AddToKey(k, vv)
        }
        tx.Collections["args_post_names"].AddToKey("", k)
        tx.Collections["args_names"].AddToKey("", k)
    }
}

//Adds request_line, request_method, request_protocol, request_basename and request_uri
func (tx *Transaction) SetRequestLine(method string, protocol string, requestUri string) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    tx.Collections["request_method"].AddToKey("", method)
    tx.Collections["request_protocol"].AddToKey("", protocol)
    tx.Collections["request_line"].AddToKey("", fmt.Sprintf("%s %s %s", method, requestUri, protocol))

}

//Adds request_line, request_method, request_protocol, request_basename and request_uri
func (tx *Transaction) SetRequestMethod(method string) {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
    tx.Collections["request_method"].AddToKey("", method)
}

//Resolves remote hostname and sets remote_host variable
func (tx *Transaction) ResolveRemoteHost() {
    tx.Mux.Lock()
    defer tx.Mux.Unlock()
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
                      "files_combined_size", "reqbody_processor", "request_body_length"}
    
    for _, k := range keys{
        tx.Collections[k] = &utils.LocalCollection{}
        tx.Collections[k].Init()
    }

    for i := 0; i <= 10; i++ {
        is := strconv.Itoa(i)
        tx.Collections["tx"].Data[is] = []string{}
    }    
}

//Reset the capture collection for further uses
func (tx *Transaction) ResetCapture(){
    //We reset capture 0-9
    for i := 0; i < 10; i++{
        si := strconv.Itoa(i)
        tx.Collections["tx"].Data[si] = []string{""}
    }
}

func (tx *Transaction) initVars() {
    tx.Collections = map[string]*utils.LocalCollection{}
    txid := utils.RandomString(19)
    tx.Id = txid
    tx.InitTxCollection()

    tx.SetSingleCollection("id", txid)
    tx.SetSingleCollection("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
    tx.Disrupted = false
    tx.AuditLogPath1 = tx.WafInstance.AuditLogPath1
    tx.AuditEngine = tx.WafInstance.AuditEngine
    tx.AuditLogParts = tx.WafInstance.AuditLogParts
    tx.DebugLogLevel = tx.WafInstance.DebugLogLevel
    tx.ForceRequestBodyVariable = tx.WafInstance.ForceRequestBodyVariable
    tx.RequestBodyAccess = tx.WafInstance.RequestBodyAccess
    tx.RequestBodyLimit = tx.WafInstance.RequestBodyLimit
    tx.RequestBodyProcessor = tx.WafInstance.RequestBodyProcessor
    tx.ResponseBodyAccess = tx.WafInstance.ResponseBodyAccess
    tx.ResponseBodyLimit = tx.WafInstance.ResponseBodyLimit
    tx.RuleEngine = tx.WafInstance.RuleEngine
    tx.HashEngine = tx.WafInstance.HashEngine
    tx.HashEnforcement = tx.WafInstance.HashEnforcement
    tx.DefaultAction = tx.WafInstance.DefaultAction
    tx.Skip = 0
    
    tx.RemoveRuleById = []int{}
    tx.RemoveRuleByTag = []string{}
    tx.RemoveTargetFromTag = map[string][]*Collection{}
    tx.RemoveTargetFromId = map[int][]*Collection{}

    tx.NewPersistentCollections = map[string]string{}
}

func (tx *Transaction) Init(waf *Waf) error{
    tx.WafInstance = waf
    tx.initVars()
    tx.Mux = &sync.RWMutex{}
    return nil
}

func (tx *Transaction) ExecutePhase(phase int) error{
    if phase < 1 || phase > 5 {
        return fmt.Errorf("Phase must be between 1 and 5, %d used", phase)
    }
    usedRules := 0

    for _, r := range tx.WafInstance.Rules.GetRules() {
        //we always execute secmarkers
        if r.Phase == phase || r.SecMark != ""{
            if tx.SkipAfter != ""{
                if r.SecMark != tx.SkipAfter{
                    //skip this rule
                    //fmt.Println("Skipping rule (skipAfter) " + fmt.Sprintf("%d", r.Id) + " to " + tx.SkipAfter + " currently " + r.SecMark)
                    continue
                }else{
                    //fmt.Println("Ending skip")
                    tx.SkipAfter = ""
                }
            }
            if tx.Skip > 0{
                tx.Skip -= 1
                //fmt.Println("Skipping rule (skip) " + fmt.Sprintf("%d", r.Id))
                //Skipping rule
                continue
            }
            //tx.WafInstance.Logger.Debug(fmt.Sprintf("Evaluating rule %d", r.Id))
            r.Evaluate(tx)
            tx.Capture = false //we reset the capture flag on every run
            usedRules++
        }
        if tx.Disrupted{
            return nil
        }
    }
    if phase == 5{
        if tx.AuditLog{
            if tx.IsRelevantStatus(){
                tx.SaveLog()
            }
        }
    }
    return nil
}

func (tx *Transaction) MatchRule(rule *Rule, msgs []string, matched []string){
    mr := &MatchedRule{
        Id: rule.Id,
        Action: rule.Action,
        Messages: msgs,
        MatchedData: matched,
        Rule: rule,
    }
    tx.MatchedRules = append(tx.MatchedRules, mr)

}

func (tx *Transaction) InitCollection(key string){
    tx.Collections[key] = &utils.LocalCollection{}
}

func (tx *Transaction) ToJSON() ([]byte, error){
    return json.Marshal(tx)
}

func (tx *Transaction) SetSingleCollection(key string, value string){
    tx.Collections[key] = &utils.LocalCollection{}
    tx.Collections[key].Init()
    tx.Collections[key].Add("", []string{value})
}

func (tx *Transaction) GetSingleCollection(key string) string{
    key = strings.ToLower(key)
    col := tx.Collections[key]
    if col == nil{
        return ""
    }
    return col.GetFirstString()
}

func (tx *Transaction) GetField(collection string, key string, exceptions []string) ([]string){
    col := tx.Collections[collection]
    key = tx.MacroExpansion(key)
    if col == nil{
        return []string{}
    }
    return col.GetWithExceptions(key, exceptions)
}

func (tx *Transaction) IsRelevantStatus() bool{
    re := tx.WafInstance.AuditLogRelevantStatus
    status := strconv.Itoa(tx.Status)
    return re.MatchString(status)
}

func (tx *Transaction) ToAuditJson() []byte{
    al := tx.ToAuditLog()
    return al.ToJson()
}

func (tx *Transaction) ToAuditLog() *AuditLog{
    al := &AuditLog{}
    al.Init(tx, tx.AuditLogParts)
    return al
}


func (tx *Transaction) SaveLog() error{
    return tx.WafInstance.Logger.WriteAudit(tx)
}