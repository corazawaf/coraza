package proxy

import (
	"context"
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/engine"
	policy "github.com/jptosso/coraza-waf/pkg/parser"
	"io"
	_ "log"
	_ "net"
	"net/http"
	"net/http/httputil"
	_ "net/url"
	"strconv"
	"strings"
	_ "sync"
)

type ProxyServer struct {
	Config *Config
}

func (ps *ProxyServer) Init(config *Config) error {
	ps.Config = config
	ports := map[string]*http.ServeMux{}
	for _, server := range ps.Config.Servers {
		listeners := []*http.ServeMux{}
		for _, l := range server.Listen {
			//TODO autocomplete with 0.0.0.0 if empty
			if ports[l] == nil {
				ports[l] = http.NewServeMux()
			}
			listeners = append(listeners, ports[l])
		}

		for _, location := range server.Locations {
			waf := engine.NewWaf()
			parser, _ := policy.NewParser(waf)
			err := parser.FromFile(location.Policy)
			if err != nil {
				return err
			}

			location.Waf = waf
			location.Listeners = listeners
			for _, l := range listeners {
				//keep in mind that trailing slashes are required to create index handlers!!!!
				l.HandleFunc(location.Path, location.RequestHandler)
			}
		}
	}
	if len(ports) == 0 {
		fmt.Println("No listeners created...")
	}
	for addr, mux := range ports {
		err := http.ListenAndServe(addr, mux)
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func (l *Location) ModifyResponse(response *http.Response) error {
	ctx := response.Request.Context()
	tx := ctx.Value("tx").(*engine.Transaction)
	//phases 4 and 5
	tx.ExecutePhase(4)
	tx.ExecutePhase(5)
	return nil
}

func (l *Location) Director(req *http.Request) {
	req.Header.Add("X-Forwarded-Host", req.Host)
	//req.URL.Path = "/"
	//req.URL.Host = l.ParentServer.Hostnames[0]
	req.URL.Scheme = "https"
}

func (l *Location) ErrorHandler(responsewriter http.ResponseWriter, request *http.Request, err error) {
	ctx := request.Context()
	tx := ctx.Value("tx").(*engine.Transaction)
	tx.ExecutePhase(5)
	responsewriter.WriteHeader(403)
	responsewriter.Header().Set("Content-Type", "text/html")
	envs := map[string]string{
		"tx_id": tx.Collections["id"].GetFirstString(),
	}
	envs = envs //TODO do something
	io.WriteString(responsewriter, fmt.Sprintf("Gateway Error<!-- TX: %s -->\n", tx.Collections["id"].GetFirstString()))
}


func (l *Location) RequestHandler(w http.ResponseWriter, r *http.Request) {
	l.mux.Lock()
	defer l.mux.Unlock()
	tx := l.Waf.NewTransaction()
	ctx := context.WithValue(r.Context(), "tx", tx)
	// this will assign the new TX to the parent context pointer
	r = r.WithContext(ctx)
	//phase 1, 2 y 3
	l.LoadRequestHeadersPhase(tx, w, r)
	if tx.Disrupted {
		//TODO disrupt
		return
	}

	//TODO revisar si se puede sobreescribir heading parser
	p := l.GetNextUpstream()
	w.Header().Set("X-Coraza-Version", "1.0")
	w.Header().Set("X-Remote-Addr", "...")
	w.Header().Set("X-Transaction-Id", "...")
	p.ServeHTTP(w, r)
}

func (l *Location) GetNextUpstream() *httputil.ReverseProxy {
	//round robin, weight, etc...

	return l.ups.Servers[0].Proxy
}

func (l *Location) LoadRequestHeadersPhase(tx *engine.Transaction, w http.ResponseWriter, r *http.Request) {
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
