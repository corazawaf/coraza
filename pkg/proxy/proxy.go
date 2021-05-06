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

package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/engine"
	policy "github.com/jptosso/coraza-waf/pkg/parser"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProxyCtx struct {
	Tx       *engine.Transaction
	Upstream *UpstreamServer
}

type ProxyServer struct {
	Config *Config
}

func (ps *ProxyServer) Init(config *Config) error {
	ps.Config = config
	ports := map[string]*http.ServeMux{}
	portsTls := map[string]*http.ServeMux{}
	sslconf := NewTlsConfig()
	for i, server := range ps.Config.Servers {
		log.Info(fmt.Sprintf("Creating server %d", i))
		listeners := []*http.ServeMux{}
		if server.Ssl != nil {
			log.Info("Adding keys to TLS")
			err := sslconf.AddCertificate(server.Ssl.Certificate, server.Ssl.PrivateKey)
			if err != nil{
				log.Fatal(err)
				return err
			}
		}
		for y, l := range server.Listen {
			log.Info(fmt.Sprintf("Creating listener for server %d with address %s", i, l))
			spl := strings.SplitN(l, " ", 2)
			server.Listen[y] = spl[0]
			l = spl[0]
			var port *http.ServeMux
			sm := http.NewServeMux()
			if len(spl) == 2 && spl[1] == "ssl" {
				log.Info(fmt.Sprintf("Creating HTTPS listener %s", spl[0]))
				if portsTls[l] == nil {
					portsTls[l] = sm
					port = portsTls[l]
				}
			} else {
				log.Info(fmt.Sprintf("Creating HTTP listener %s", l))
				if ports[l] == nil {
					ports[l] = sm
					port = ports[l]
				}
			}

			listeners = append(listeners, port)
		}

		for _, location := range server.Locations {
			log.Info(fmt.Sprintf("Creating location handler for server %d", i))
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
	if len(ports) == 0 && len(portsTls) == 0 {
		fmt.Println("No listeners created...")
	}
	wg := new(sync.WaitGroup)
	wg.Add(len(ports) + len(portsTls))
	for addr, mux := range ports {
		server := &http.Server{
			Addr:           addr,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
			Handler:        mux,
		}
		log.Info(fmt.Sprintf("Starting HTTP listener %s", addr))
		go func() {
			err := server.ListenAndServe()
			if err != nil {
				log.Fatal(err)
			}
			wg.Done()
		}()
	}
	//TLS listeners with SNI support req.Host will be used to find the certificate
	for addr, mux := range portsTls {
		conf := sslconf.Build()
		server := &http.Server{
			Addr:           addr,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
			TLSConfig:      conf,
			Handler:        mux,
		}
		log.Info(fmt.Sprintf("Starting HTTPS listener %s", addr))
		listener, err := tls.Listen("tcp", addr, conf)
		if err != nil {
			panic(err)
		}
		go func() {
			log.Fatal(server.Serve(listener))
			wg.Done()
		}()
	}
	log.Info("All listeners are ready and waiting for connections")
	wg.Wait()
	return nil
}

func (l *Location) ModifyResponse(response *http.Response) error {
	ctx := response.Request.Context()
	ups := ctx.Value("ups").(*ProxyCtx)
	tx := ups.Tx
	//phases 4 and 5
	tx.ExecutePhase(4)
	tx.ExecutePhase(5)
	return nil
}

func (l *Location) Director(req *http.Request) {
	host := l.server.Hostnames[0]
	req.Header.Add("X-Forwarded-Host", req.Host)
	ctx := req.Context()
	ups := ctx.Value("ups").(*ProxyCtx)

	req.Header.Add("Host", host)
	path := req.URL.Path
	if !l.PathTrail {
		path = path[l.padding:]
	}
	req.URL.Path = ups.Upstream.Path + path
	req.URL.Host = host
	req.Host = host
	req.URL.Scheme = "http"
	if ups.Upstream.Ssl{
		req.URL.Scheme = "https"
	}
}

func (l *Location) ErrorHandler(responsewriter http.ResponseWriter, request *http.Request, err error) {
	ctx := request.Context()
	ups := ctx.Value("ups").(*ProxyCtx)
	tx := ups.Tx
	tx.ExecutePhase(5)
	responsewriter.WriteHeader(500)
	responsewriter.Header().Set("Content-Type", "text/html")
	io.WriteString(responsewriter, fmt.Sprintf("Gateway Error\n<!-- TX: %s -->\n", tx.Collections["id"].GetFirstString()))
	log.Error(err)
}

func (l *Location) RequestHandler(w http.ResponseWriter, r *http.Request) {
	log.Info("Intercepting request")
	//TODO lock?
	//l.mux.Lock()
	//defer l.mux.Unlock()
	//TODO revisar si se puede sobreescribir heading parser
	log.Info("Selecting upstream")
	p := l.GetNextUpstream()
	tx := l.Waf.NewTransaction()
	ctx := context.WithValue(r.Context(), "ups", &ProxyCtx{tx, p})
	// this will assign the new TX to the parent context pointer
	r = r.WithContext(ctx)
	//phase 1, 2 y 3
	l.LoadRequestHeadersPhase(tx, w, r)
	if tx.Disrupted {
		//TODO disrupt
		return
	}

	w.Header().Set("X-Coraza-Version", "1.0")
	w.Header().Set("X-Transaction-Id", "...")
	log.Info("Serving to upstream")
	p.Proxy.ServeHTTP(w, r)
}

func (l *Location) GetNextUpstream() *UpstreamServer {
	//round robin, weight, etc...
	log.Info("Serving upstream")
	return l.ups.Servers[0]
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

func (l *Location) SetUpstream(ups *Upstream) error {
	log.Info(fmt.Sprintf("Adding upstream %s to location with %d servers", ups.Hash, len(ups.Servers)))
	for _, upstream := range ups.Servers {
		scheme := "http"
		if upstream.Ssl {
			scheme = "https"
		}
		upurlstr := fmt.Sprintf("%s://%s:%d", scheme, upstream.Server, upstream.Port)
		log.Info("Creating upstream " + upurlstr)
		upurl, err := url.Parse(upurlstr)
		if err != nil {
			log.Error("Failed to set upstream for url " + upurlstr)
			return err
		}
		reverseProxy := httputil.NewSingleHostReverseProxy(upurl)
		// Provides the ability to update the response before sending it to the client
		reverseProxy.ModifyResponse = l.ModifyResponse
		// What to show on error
		reverseProxy.ErrorHandler = l.ErrorHandler
		// Modify request before sending it to the upstream
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
		upstream.Proxy = reverseProxy
	}
	l.ups = ups
	return nil
}
