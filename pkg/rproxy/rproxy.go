package rproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jptosso/coraza/pkg/waf"
	"io"
	_ "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Upstream struct {
	Proxy             *httputil.ReverseProxy
	Weight            int
	HealthCheckUrl    string
	HealthCheckStatus int
	ErrorCount        int //TODO thread friendly
}

func (us *Upstream) Init() {

}

type Server struct {
	Hostnames []string
	Address   string
	Port      int
	Locations []*Location
}

func (s *Server) Init() {
	s.Locations = make([]*Location, 0)
}

func (s *Server) AddLocation(location *Location) {
	location.ParentServer = s
	s.Locations = append(s.Locations, location)
}

type Location struct {
	ParentServer  *Server
	Path          string
	Upstreams     []*Upstream
	Listener      *http.ServeMux
	WafInstance   *waf.Waf
	LastUpstreamN int //for round robin
}

func (l *Location) Init(wafinstance *waf.Waf) {
	l.Upstreams = make([]*Upstream, 0)
	l.WafInstance = wafinstance
}

type HttpServer struct {
	Servers   map[int][]*Server //Servers grouped by port and address
	Listeners []*http.ServeMux
}

func (hs *HttpServer) Init() {
	hs.Servers = make(map[int][]*Server)
}

func (hs *HttpServer) Overwrite(newHs *HttpServer) {

}

func (hs *HttpServer) Start() {
	for port, servers := range hs.Servers {
		for _, server := range servers {
			addr := fmt.Sprintf("%s:%d", server.Address, port)
			servermux := http.NewServeMux()
			for _, location := range server.Locations {
				location.Listener = servermux
				location.Listener.HandleFunc(location.Path, location.RequestHandler)
			}
			hs.Listeners = append(hs.Listeners, servermux)
			err := http.ListenAndServe(addr, servermux)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (hs *HttpServer) Shutdown() {
	/*
		for port, serverport := range hs.Servers{
			for address, server := range serverport{
				addr := fmt.Sprintf("%s:%d", address, port)
				servermux := http.NewServeMux()
				for _, location := range server.Locations{
					//location.Listener.Shutdown()
				}
			}
		}*/
}

func (hs *HttpServer) AddServer(server *Server) {
	if hs.Servers[server.Port] == nil {
		hs.Servers[server.Port] = make([]*Server, 0)
	}
	hs.Servers[server.Port] = append(hs.Servers[server.Port], server)
}

func (l *Location) AddUpstream(upstream *ConfigUpstreamServer) error {
	ups := Upstream{}
	ups.Init()
	upurlstr := upstream.Address
	upurl, _ := url.Parse(upurlstr)
	reverseProxy := httputil.NewSingleHostReverseProxy(upurl)
	reverseProxy.ModifyResponse = l.ModifyResponse
	reverseProxy.ErrorHandler = l.ErrorHandler
	reverseProxy.Director = l.Director
	reverseProxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   60 * time.Second,
			KeepAlive: 60 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	reverseProxy.Transport = nil
	ups.Proxy = reverseProxy
	l.Upstreams = append(l.Upstreams, &ups)

	return nil
}

func (l *Location) ModifyResponse(response *http.Response) error {
	ctx := response.Request.Context()
	tx := ctx.Value("tx").(*waf.Transaction)
	//phases 4 and 5
	tx.ExecutePhase(4)
	tx.ExecutePhase(5)
	tx.Save() //here we cannot stop communication anymore
	return nil
}

func (l *Location) Director(req *http.Request) {
	req.Header.Add("X-Forwarded-Host", req.Host)
	//req.URL.Path = "/"
	req.URL.Host = l.ParentServer.Hostnames[0]
	req.URL.Scheme = "https"
}

func (l *Location) ErrorHandler(responsewriter http.ResponseWriter, request *http.Request, err error) {
	ctx := request.Context()
	tx := ctx.Value("tx").(*waf.Transaction)
	tx.ExecutePhase(5)
	responsewriter.WriteHeader(403)
	responsewriter.Header().Set("Content-Type", "text/html")
	envs := map[string]string{
		"tx_id": tx.Collections["id"].GetFirstString(),
	}
	envs = envs
	tx.Save()
	io.WriteString(responsewriter, fmt.Sprintf("Gateway Error<!-- TX: %s -->\n", tx.Collections["id"].GetFirstString()))
}

func (l *Location) DebugErrorHandler(responsewriter http.ResponseWriter, request *http.Request, err error) {
	ctx := request.Context()
	tx := ctx.Value("tx").(*waf.Transaction)
	tx.ExecutePhase(5)
	tx.Profiling = time.Now().UnixNano() - tx.Profiling
	responsewriter.Header().Set("Content-Type", "application/json")
	responsewriter.WriteHeader(403)
	type Debug struct {
		Tx    *waf.Transaction
		Rules []*waf.Rule
	}
	debug := &Debug{tx, tx.WafInstance.Rules}
	res, _ := json.Marshal(debug)
	tx.Save()
	io.WriteString(responsewriter, string(res))
}

func (l *Location) RequestHandler(w http.ResponseWriter, r *http.Request) {
	tx := &waf.Transaction{}

	tx.Init(l.WafInstance)
	tx.Profiling = time.Now().UnixNano()
	ctx := context.WithValue(r.Context(), "tx", tx)
	r = r.WithContext(ctx)
	//phase 1, 2 y 3
	l.LoadRequestHeadersPhase(tx, w, r)
	tx.ExecutePhase(1)
	if tx.Disrupted {
		l.DebugErrorHandler(w, r, nil)
		return
	}	
	err := l.LoadRequestBodyPhase(tx, w, r)
	if err != nil{
		fmt.Println("Error reading body", err)
		return
	}
	tx.ExecutePhase(2)
	if tx.Disrupted {
		l.DebugErrorHandler(w, r, nil)
		return
	}	
	tx.SetFullRequest()
	tx.ExecutePhase(3)
	if tx.Disrupted {
		l.DebugErrorHandler(w, r, nil)
		return
	}

	//TODO revisar si se puede sobreescribir heading parser
	p := l.GetNextUpstream()
	w.Header().Set("X-Coraza-Version", "1.0")
	w.Header().Set("X-Remote-Addr", "...")
	w.Header().Set("X-Transaction-Id", "...")
	//l.DebugErrorHandler(w, r, nil)
	p.ServeHTTP(w, r)
}

func (l *Location) GetNextUpstream() *httputil.ReverseProxy {
	//round robin, weight, etc...
	return l.Upstreams[0].Proxy
}

func (l *Location) LoadRequestHeadersPhase(tx *waf.Transaction, w http.ResponseWriter, r *http.Request) {
	//basenamespl := regexp.MustCompile(`\/|\\`)
	addrspl := strings.SplitN(r.RemoteAddr, ":", 2)
	port := 0
	if len(addrspl) == 2 {
		port, _ = strconv.Atoi(addrspl[1])
	}
	tx.SetRequestHeaders(r.Header)
	tx.SetArgsGet(r.URL.Query())
	//tx.SetAuthType("") //Not supported
	tx.SetUrl(r.URL)
	tx.SetRemoteAddress(addrspl[0], port)
	//tx.SetRemoteUser("") //Not supported
	tx.SetRequestCookies(r.Cookies())
	tx.SetRequestLine(r.Method, r.Proto, r.RequestURI)
}

func (l *Location) LoadRequestBodyPhase(tx *waf.Transaction, w http.ResponseWriter, r *http.Request) error {
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

//son pocas lineas, quizas podríamos tambien probar con https://github.com/zalando/skipper