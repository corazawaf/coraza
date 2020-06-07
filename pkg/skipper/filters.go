package skipper

import (
    "strings"
    "strconv"
    "sync"
    "io"
    "net/http"
    "encoding/json"
    "fmt"
    "os"
    "os/exec"
    "bytes"
    "github.com/zalando/skipper/filters"
    "github.com/zalando/skipper/filters/serve"
    "github.com/jptosso/coraza-waf/pkg/waf"
    "github.com/jptosso/coraza-waf/pkg/models"
)

type CorazaSpec struct {}

type CorazaFilter struct {
    //constant values
    policypath string
    datapath string
    wafinstance *waf.Waf

    //context values
    tx *waf.Transaction

    mux *sync.RWMutex
}

func (s *CorazaSpec) Name() string { return "corazaWAF" }

func (s *CorazaSpec) CreateFilter(config []interface{}) (filters.Filter, error) {
    if len(config) == 0 {
        return nil, filters.ErrInvalidFilterParameters
    }
    policypath := config[0].(string)
    datapath := config[1].(string)

    if policypath == "" {
        return nil, filters.ErrInvalidFilterParameters
    }
    if datapath == "" {
        return nil, filters.ErrInvalidFilterParameters
    }    

    
    wi := &waf.Waf{}
    wi.Datapath = datapath
    wi.Init()

    wafparser := waf.Parser{}
    wafparser.Init(wi)
    err := wafparser.FromFile(policypath)
    if err != nil {
        return nil, err
    }
    wi.SortRules()    
    return &CorazaFilter{policypath, datapath, wi, nil, &sync.RWMutex{}}, nil
}

func (f *CorazaFilter) Request(ctx filters.FilterContext) {
    f.mux.Lock()
    defer f.mux.Unlock()
    r := ctx.Request()
    f.tx = &waf.Transaction{}
    f.tx.Init(f.wafinstance)

    //TODO watch out for ipv6, idk why it prints [::1:12345] instead of ::1:12345 like vanilla http requests 
    addrspl := strings.SplitN(r.RemoteAddr, ":", 2) 
    port := 0
    if len(addrspl) == 2 {
        port, _ = strconv.Atoi(addrspl[1])
    }
    f.tx.SetRequestHeaders(r.Header)
    f.tx.SetArgsGet(r.URL.Query())
    //tx.SetAuthType("") //Not supported
    f.tx.SetUrl(r.URL)
    f.tx.SetRemoteAddress(addrspl[0], port)
    //tx.SetRemoteUser("") //Not supported
    f.tx.SetRequestCookies(r.Cookies())
    f.tx.SetRequestLine(r.Method, r.Proto, r.RequestURI)
    f.tx.ExecutePhase(1)
    if f.tx.Disrupted {
        f.ErrorPage(ctx)
        return
    }   
    err := f.loadRequestBody(r)
    if err != nil{
        f.ErrorPage(ctx)
        return
    }
    f.tx.ExecutePhase(2)
    if f.tx.Disrupted {
        f.ErrorPage(ctx)
        return
    }   
    f.tx.SetFullRequest()
    f.tx.ExecutePhase(3)
    if f.tx.Disrupted {
        f.ErrorPage(ctx)
        //l.DebugErrorHandler(w, r, nil)
        return
    }    
}

func (f *CorazaFilter) Response(ctx filters.FilterContext) {
    f.mux.Lock()
    defer f.mux.Unlock()    
    if f.tx.Disrupted{
        //Skip response phase
        return
    }
    f.tx.SetResponseHeaders(ctx.Response().Header)
    ctx.Response().Header.Set("X-Coraza-Waf", "woo")
    f.tx.ExecutePhase(4)
    f.tx.ExecutePhase(5)
}

func (f *CorazaFilter) ErrorPage(ctx filters.FilterContext) { 
    f.tx.ExecutePhase(5)
    serve.ServeHTTP(ctx, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request){
        rw.WriteHeader(http.StatusForbidden)
        rw.Header().Set("Content-Type", "text/html")
        io.WriteString(rw, "<link href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css\" rel=\"stylesheet\">")
        io.WriteString(rw, fmt.Sprintf("<h1>Coraza Security Error - Debug Mode</h1>"))
        io.WriteString(rw, "<h3>Rules Triggered</h3>")
        io.WriteString(rw, "<table class='table table-striped'><thead><tr><th>ID</th><th>Action</th><th>Msg</th><th>Match</th><th>Raw Rule</th></tr></thead><tbody>")

        for _, mr := range f.tx.MatchedRules{
            match := strings.Join(mr.MatchedData, "<br>")
            rule := mr.Rule.Raw
            for child := mr.Rule.ChildRule; child != nil; child = child.ChildRule{
                rule += "<br><strong>CHAIN:</strong> " + child.Raw
            }
            io.WriteString(rw, fmt.Sprintf("<tr><td>%d</td><td>%s</td><td></td><td>%s</td><td>%s</td></tr>", mr.Id, mr.Action, match, rule))
        }
        io.WriteString(rw, "</tbody></table>")

        io.WriteString(rw, "<h3>Transaction Collections</h3>")
        io.WriteString(rw, "<table class='table table-striped'><thead><tr><th>Collection</th><th>Key</th><th>Values</th></tr></thead><tbody>")
        for key, col := range f.tx.Collections{
            for k2, data := range col.Data{
                d := strings.Join(data, "<br>")
                io.WriteString(rw, fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>", key, k2, d))
            }
        }
        io.WriteString(rw, "</tbody></table>")
        al := &models.AuditLog{}
        al.Parse(&f.tx.Transaction)
        var prettyJSON bytes.Buffer
        json.Indent(&prettyJSON, al.ToJson(), "", "\t")        
        io.WriteString(rw, fmt.Sprintf("<h3>Audit Log</h3><pre>%s</pre>", prettyJSON.String()))
    }))
}

func (f *CorazaFilter) CustomErrorPage(ctx filters.FilterContext) { 
    serve.ServeHTTP(ctx, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request){        
        rw.WriteHeader(http.StatusForbidden)
        rw.Header().Set("Content-Type", "text/html")
        cmd := exec.Command("custom-script.py")
        cmd.Env = os.Environ()
        cmd.Env = append(cmd.Env, "waf_txid=" + f.tx.Id)
        cmd.Env = append(cmd.Env, "waf_timestamp=" + strconv.FormatInt(f.tx.Collections["timestamp"].GetFirstInt64(), 10))
        stdout, err := cmd.Output()
        if err != nil {
            io.WriteString(rw, "<h1>Security Error</h1>")
            io.WriteString(rw, "<small>There was an error rendering this page, please check the error logs.</small>")
            return
        }
        io.WriteString(rw, string(stdout))
    }))
}

func (f *CorazaFilter) loadRequestBody(r *http.Request) error{
    tx := f.tx
    cl := tx.Collections["request_headers"].Data["content-type"]
    ctype := "text/plain"
    if len(cl) > 0{
        spl := strings.SplitN(cl[0], ";", 2)
        ctype = spl[0]
    }
    f.tx.SetReqBodyProcessor("URLENCODED")
    switch ctype {
    default:
        //url encode
        err := r.ParseForm()
        if err != nil {
            //TODO mostrar el error
            //l.DebugErrorHandler(w, r, nil)
            return nil
        }
        tx.SetArgsPost(r.PostForm)
    case "multipart/form-data":
        //multipart
        //url encode
        f.tx.SetReqBodyProcessor("MULTIPART")
        err := r.ParseMultipartForm(tx.RequestBodyLimit)
        if err != nil {
            //TODO mostrar el error
            //l.DebugErrorHandler(w, r, nil)
            return nil
        }
        tx.SetFiles(r.MultipartForm.File)
        tx.SetArgsPost(r.MultipartForm.Value)
    }
    return nil
}