package models

import (
    "fmt"
	"github.com/jptosso/coraza-waf/pkg/utils"	
    "regexp"
    "strings"
    "mime/multipart"
    "strconv"
    "net"
    "net/http"
    "net/url"
)

type MatchedRule struct {
	Id int
	Action string
	Messages []string
	MatchedData []string
}

type Transaction struct {
	//Options
	Log bool `json:"log"`

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

    DefaultAction string
    AuditEngine bool
    AuditLogParts string
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
    RuleRemoveTargetById map[int]map[string]string // ID[collection][key]
    RuleRemoveTargetByMsg map[int]map[string]string // ID[collection][key]
    RuleRemoveTargetByTag map[int]map[string]string // ID[collection][key]
    HashEngine bool
    HashEnforcement bool

    Skip int `json:"skip"`
    Capture bool `json:"capture"`

    //Used for the capture action, it will store the last results from RX to add them to TX:0..10
    RxMatch []string `json:"rx_match"`
    DisruptiveRuleId int `json:"disruptive_rule_id"`
}

func (tx *Transaction) MacroExpansion(data string) string{
    if data == ""{
        return ""
    }
    //fmt.Println("DATA: ", data)
    r := regexp.MustCompile(`%\{(.*?)\}`)
    matches := r.FindAllString(data, -1)
    for _, v := range matches {
        match := v[2:len(v)-1] //removemos caracteres
        matchspl := strings.SplitN(match, ".", 2)
        col := strings.ToLower(matchspl[0])
        key := strings.ToLower(col)
        if len(matchspl) == 2{
            key = matchspl[1]            
        }
        collection := tx.Collections[col]
        if collection == nil{
            return ""
        }
        expansion := collection.Get(key) //TODO REVISAR
        if len(expansion) == 0{
            continue
        }
        data = strings.ReplaceAll(data, v, expansion[0])
    }
    //fmt.Println("Macro: " + data)
    return data
}

//Functions required by web server

//Sets request_headers and request_headers_names
func (tx *Transaction) SetRequestHeaders(headers map[string][]string) {
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

//Sets args_get, args_get_names. Also adds to args_names and args
func (tx *Transaction) SetArgsGet(args map[string][]string) {
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
    tx.Collections["auth_type"].AddToKey("", auth)
}

//Sets files, files_combined_size, files_names, files_sizes, files_tmpnames, files_tmp_content
func (tx *Transaction) SetFiles(files map[string][]*multipart.FileHeader) {
    total_size := int64(0)
    for field, fheaders := range files{
        tx.Collections["files_names"].AddToKey("", field)
        for _, header := range fheaders{
            tx.Collections["files"].AddToKey("", header.Filename)
            total_size += header.Size
            tx.Collections["files_sizes"].AddToKey("", fmt.Sprintf("%d", header.Size))
        }
    }
    tx.Collections["files_combined_size"].AddToKey("", fmt.Sprintf("%d", total_size))
}

//Will be built from request_line, request_headers and request_body
func (tx *Transaction) SetFullRequest() {
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
    p := strconv.Itoa(port)
    tx.Collections["remote_addr"].AddToKey("", address)
    tx.Collections["remote_port"].AddToKey("", p)
}

func (tx *Transaction) SetRemoteUser(user string) {
    tx.Collections["remote_user"].AddToKey("", user)
}


//Sets request_body and request_body_length, it won't work if request_body_inspection is off
func (tx *Transaction) SetRequestBody(body string, length int64) {
    if !tx.RequestBodyAccess || length > tx.RequestBodyLimit{
        return
    }
    l := fmt.Sprintf("%d", length)
    tx.Collections["request_body"].AddToKey("", body)
    tx.Collections["request_body_length"].AddToKey("", l)
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
    request_basename := u.EscapedPath()
    a := regexp.MustCompile(`\/|\\`) // \ o /
    spl := a.Split(request_basename, -1)
    if len(spl) > 0{
        request_basename = spl[len(spl)-1]
    }
    tx.Collections["request_uri"].AddToKey("", u.EscapedPath())
    tx.Collections["request_filename"].AddToKey("", u.Path)
    tx.Collections["request_basename"].AddToKey("", request_basename)
    tx.Collections["query_string"].AddToKey("", u.RawQuery)
    tx.Collections["request_uri_raw"].AddToKey("", u.String())
    //TODO shall we add user data? *Userinfo 
}

//Adds request_line, request_method, request_protocol, request_basename and request_uri
func (tx *Transaction) SetRequestLine(method string, protocol string, requestUri string) {
    tx.Collections["request_method"].AddToKey("", method)
    tx.Collections["request_protocol"].AddToKey("", protocol)
    tx.Collections["request_line"].AddToKey("", fmt.Sprintf("%s %s %s", method, requestUri, protocol))

}

//Resolves remote hostname and sets remote_host variable
func (tx *Transaction) ResolveRemoteHost() {
    addr, err := net.LookupAddr("198.252.206.16")
    if err != nil{
        return
    }
    //TODO: ADD CACHE
    tx.Collections["remote_host"].AddToKey("", addr[0])
}