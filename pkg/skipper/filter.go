package skipper
import (
    "strings"
    "strconv"
    "sync"
    "io"
    "net/http"
    "regexp"
    "github.com/zalando/skipper/filters"
    "github.com/zalando/skipper/filters/serve"
    "github.com/jptosso/coraza-waf/pkg/engine"   
    "github.com/jptosso/coraza-waf/pkg/parser"
)

type CorazaSpec struct {}

type CorazaFilter struct {
    //constant values
    policypath string
    wafinstance *engine.Waf

    //context values
    tx *engine.Transaction

    mux *sync.RWMutex
}

func (s *CorazaSpec) Name() string { return "corazaWAF" }

func (s *CorazaSpec) CreateFilter(config []interface{}) (filters.Filter, error) {
    if len(config) == 0 {
        return nil, filters.ErrInvalidFilterParameters
    }
    policypath := config[0].(string)

    if policypath == "" {
        return nil, filters.ErrInvalidFilterParameters
    }

    wi := &engine.Waf{}
    wi.Init()

    wafparser := parser.Parser{}
    wafparser.Init(wi)
    err := wafparser.FromFile(policypath)
    if err != nil {
        return nil, err
    }
    wi.Rules.Sort()
    wi.InitLogger()
    return &CorazaFilter{policypath, wi, nil, &sync.RWMutex{}}, nil
}

func (f *CorazaFilter) Request(ctx filters.FilterContext) {
    //f.mux.Lock()
    //defer f.mux.Unlock()
    r := ctx.Request()
    f.tx = &engine.Transaction{}
    f.tx.Init(f.wafinstance)

    re := regexp.MustCompile(`^\[(.*?)\]:(\d+)$`)
    matches := re.FindAllStringSubmatch(r.RemoteAddr, -1)
    address := ""
    port := 0

    //no more validations as we don't spake weird ip addresses
    if len(matches) > 0 {
        address = string(matches[0][1])
        port, _ = strconv.Atoi(string(matches[0][2]))
    }

    f.tx.SetRequestHeaders(r.Header)
    //For some reason, skipper hides de Host header, so we have to manually add it:
    f.tx.Collections["request_headers"].Data["host"] = []string{ctx.OutgoingHost()}
    f.tx.SetArgsGet(r.URL.Query())
    //tx.SetAuthType("") //Not supported
    f.tx.SetUrl(r.URL)
    f.tx.SetRemoteAddress(address, port)
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
        return
    }   
    f.tx.SetFullRequest()
    f.tx.ExecutePhase(3)
    if f.tx.Disrupted {
        return
    }
}

func (f *CorazaFilter) Response(ctx filters.FilterContext) {
    //f.mux.Lock()
    //defer f.mux.Unlock()    
    if f.tx.Disrupted{
        //Skip response phase
        f.ErrorPage(ctx)
        return
    }
    f.tx.SetResponseHeaders(ctx.Response().Header)
    ctx.Response().Header.Set("X-Coraza-Waf", "woo")
    f.tx.ExecutePhase(4)
    f.tx.ExecutePhase(5)
}

func (f *CorazaFilter) ErrorPage(ctx filters.FilterContext) { 
    serve.ServeHTTP(ctx, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request){
        rw.WriteHeader(http.StatusForbidden)
        rw.Header().Set("Content-Type", "text/html")
        io.WriteString(rw, f.tx.GetErrorPage())    
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
            //TODO ??
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
            //TODO ??
            //l.DebugErrorHandler(w, r, nil)
            return nil
        }
        tx.SetFiles(r.MultipartForm.File)
        tx.SetArgsPost(r.MultipartForm.Value)
    }
    return nil
}