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
	"github.com/jptosso/coraza-waf/pkg/profile"
	"github.com/jptosso/coraza-waf/pkg/utils"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
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
			if err != nil {
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
			pdata, err := utils.OpenFile(location.Profile)
			if err != nil {
				return err
			}
			pf, err := profile.ParseProfile(pdata)
			if err != nil {
				return err
			}

			waf, err := pf.Build()
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
	tx.ParseResponseObjectHeaders(response)
	//phases 4 and 5
	tx.ExecutePhase(3)
	if tx.Disrupted {
		response.Header = http.Header{}
		response.Header.Add("Content-Type", "text/html")
		response.Status = "500 Failed"
		response.StatusCode = 500
		body, err := errorCgi(tx, l.ErrorCgi)
		if err != nil {
			log.Error("Failed to send error page")
		}
		response.Body = ioutil.NopCloser(strings.NewReader(string(body)))
		tx.ExecutePhase(5)
		return nil
	}
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
	if ups.Upstream.Ssl {
		req.URL.Scheme = "https"
	}
}

func (l *Location) ErrorHandler(responsewriter http.ResponseWriter, request *http.Request, err error) {
	ctx := request.Context()
	ups := ctx.Value("ups").(*ProxyCtx)
	tx := ups.Tx
	tx.ExecutePhase(5)
	responsewriter.Header().Add("Content-Type", "text/html")
	responsewriter.WriteHeader(500)
	if l.ErrorCgi != "" {
		stdout, err := errorCgi(tx, l.ErrorCgi)
		if err != nil {
			io.WriteString(responsewriter, "System error, contact administrator.")
			log.Error(err)
		} else {
			io.WriteString(responsewriter, string(stdout))
		}
	} else {
		io.WriteString(responsewriter, fmt.Sprintf("Gateway Error\n<!-- TX: %s -->\n", tx.Collections["id"].GetFirstString()))
	}
	if err != nil {
		log.Error(err)
	}
}

func (l *Location) RequestHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("Intercepting request and selecting upstream")
	//TODO lock?
	//l.mux.Lock()
	//defer l.mux.Unlock()
	//TODO revisar si se puede sobreescribir heading parser
	p := l.GetNextUpstream()
	tx := l.Waf.NewTransaction()
	ctx := context.WithValue(r.Context(), "ups", &ProxyCtx{tx, p})
	// this will assign the new TX to the parent context pointer
	r = r.WithContext(ctx)
	//phase 1, 2 y 3
	err := tx.ParseRequestObjectHeaders(r)
	if err != nil {

	}
	tx.ExecutePhase(1)
	if tx.Disrupted {
		l.ErrorHandler(w, r, nil)
		return
	}
	err = tx.ParseRequestObjectBody(r)
	if err != nil {

	}
	tx.ExecutePhase(2)
	if tx.Disrupted {
		l.ErrorHandler(w, r, nil)
		return
	}
	w.Header().Set("X-Coraza-Version", "1.0")
	w.Header().Set("X-Transaction-Id", tx.Id)
	log.Debug("Serving to upstream")
	p.Proxy.ServeHTTP(w, r)
}

func (l *Location) GetNextUpstream() *UpstreamServer {
	//round robin, weight, etc...
	log.Debug("Serving upstream")
	return l.ups.Servers[0]
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
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
			// Apparently TLSHandshakeTimeout generates the error TLS handshake error from...
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			//DisableCompression: true,
		}
		//reverseProxy.Transport = nil
		upstream.Proxy = reverseProxy
	}
	l.ups = ups
	return nil
}

func getTriggeredRules(tx *engine.Transaction) string {
	buff := ""
	for _, tr := range tx.MatchedRules {
		if tr.Id == 0 {
			continue
		}
		buff += " " + strconv.Itoa(tr.Id)
	}
	return buff
}

func errorCgi(tx *engine.Transaction, file string) ([]byte, error) {
	cmd := exec.Command(file)
	cmd.Env = os.Environ()
	rawrule := tx.WafInstance.Rules.FindById(tx.DisruptiveRuleId).Raw
	cmd.Env = append(cmd.Env, "TXID="+tx.Id)
	cmd.Env = append(cmd.Env, "RULES_TRIGGERED="+getTriggeredRules(tx))
	if tx.DisruptiveRuleId != 0 {
		cmd.Env = append(cmd.Env, "DISRUPTIVE_RULE_ID="+strconv.Itoa(tx.DisruptiveRuleId))
		cmd.Env = append(cmd.Env, "DISRUPTIVE_RULE="+rawrule)
		cmd.Env = append(cmd.Env, "DISRUPTIVE_RULE_MACROED="+tx.MacroExpansion(rawrule))
	}
	for k, v := range tx.Collections["tx"].Data {
		for i, data := range v {
			cmd.Env = append(cmd.Env, fmt.Sprintf("TX_%s_%d=%s", k, i, data))
		}
	}
	return cmd.Output()
}
