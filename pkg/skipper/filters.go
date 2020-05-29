package skipper

import (
    "strings"
    "strconv"
    "sync"
    "io"
    "net/http"
    "fmt"
    "github.com/zalando/skipper/filters"
    "github.com/zalando/skipper/filters/serve"
    "github.com/jptosso/coraza-waf/pkg/waf"
    _"github.com/jptosso/coraza-waf/pkg/models"
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
        io.WriteString(rw, fmt.Sprintf("WAF Security Error, triggered rule: %d", f.tx.DisruptiveRuleId))
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