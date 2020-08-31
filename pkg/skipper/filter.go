package skipper
import (
    "io"
    "net/http"
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
    tx := &engine.Transaction{}
    tx.Init(wi)    
    return &CorazaFilter{policypath, wi, tx}, nil
}

func (f *CorazaFilter) Request(ctx filters.FilterContext) {
    req := ctx.Request()

    err := f.tx.ParseRequestObject(req)
    if err != nil || f.tx.Disrupted{
        f.ErrorPage(ctx)
    }    
}

func (f *CorazaFilter) Response(ctx filters.FilterContext) {
    err := f.tx.ParseResponseObject(ctx.Response())
    if err != nil || f.tx.Disrupted {
        f.ErrorPage(ctx)
        return
    }
    f.tx.ExecutePhase(5)
}

func (f *CorazaFilter) ErrorPage(ctx filters.FilterContext) { 
    f.tx.ExecutePhase(5)
    serve.ServeHTTP(ctx, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request){
        rw.WriteHeader(http.StatusForbidden)
        //rw.Header().Set("Content-Type", "text/html")
        io.WriteString(rw, f.tx.GetErrorPage())    
    }))
}