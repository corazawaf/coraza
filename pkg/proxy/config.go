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
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/engine"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
)

type UpstreamServer struct {
	Server          string `yaml:"server"`
	Port            int    `yaml:"port"`
	Path            string `yaml:"path"`
	Ssl             bool   `yaml:"ssl"`
	Weight          int    `yaml:"weight"`
	HealthCheckPath string

	// Non YAML fields
	Proxy *httputil.ReverseProxy
}

type Upstream struct {
	Hash     string            `yaml:"hash"`
	Strategy string            `yaml:"strategy"`
	Servers  []*UpstreamServer `yaml:"servers"`
}

type Ssl struct {
	PrivateKey  string   `yaml:"private_key"`
	Certificate string   `yaml:"certificate"`
	Protocols   []string `yaml:"protocols"`
	Ciphers     []string `yaml:"ciphers"`
}

type Proxy struct {
	Headers              []interface{} `yaml:"headers"`
	ClientMaxBodySize    string        `yaml:"client_max_body_size"`
	ClientBodyBufferSize string        `yaml:"client_body_buffer_size"`
	ConnectionTimeout    int           `yaml:"connection_timeout"`
	SendTimeout          int           `yaml:"send_timeout"`
	ReadTimeout          int           `yaml:"read_timeout"`
	Buffers              string        `yaml:"buffers"`
}

type Location struct {
	Path      string `yaml:"path"`
	PathTrail bool   `yaml:"path_trail"`
	Profile   string `yaml:"profile"`
	ErrorCgi  string `yaml:"error_cgi"`
	AccessLog string `yaml:"access_log"`
	Upstream  string `yaml:"upstream"`

	//Private non YAML fields
	Listeners []*http.ServeMux
	Waf       *engine.Waf
	mux       *sync.RWMutex
	ups       *Upstream
	server    *Server

	// Amount of characters to strip on url, basically len(Path)
	padding int
}

type Server struct {
	Listen    []string    `yaml:"listen"`
	Hostnames []string    `yaml:"hostnames"`
	Locations []*Location `yaml:"locations"`
	Ssl       *Ssl        `yaml:"ssl"`
	Proxy     *Proxy      `yaml:"proxy"`
}

type Config struct {
	Concurrency string      `yaml:"concurrency"`
	LogLevel string `yaml:"loglevel"`
	ErrorLog    string      `yaml:"error_log"`
	Pid         string      `yaml:"pid"`
	Redis       string      `yaml:"redis"`
	Upstreams   []*Upstream `yaml:"upstreams"`
	Servers     []*Server   `yaml:"servers`
}

func ParseConfig(data []byte) (*Config, error) {
	config := Config{}
	err := yaml.Unmarshal([]byte(data), &config)
	if err != nil {
		return nil, err
	}
	log.SetLevel(logleveltoint(config.LogLevel))
	for _, server := range config.Servers {
		for i, listen := range server.Listen {
			spl := strings.SplitN(listen, ":", 2)
			if len(spl) != 2 {
				server.Listen[i] = fmt.Sprintf("0.0.0.0:%s", listen)
			}
		}
		for _, location := range server.Locations {
			location.server = server
			log.Debug(fmt.Sprintf("Loading location %s for server", location.Path))
			location.padding = len(location.Path)
			var ups *Upstream
			for _, upstream := range config.Upstreams {
				if upstream.Hash == location.Upstream {
					ups = upstream
					break
				}
			}
			if ups == nil {
				//log.Error("No upstream %s found location", location.Upstream)
			} else {
				location.SetUpstream(ups)
			}
		}
	}
	return &config, nil
}


func logleveltoint(level string) log.Level {
	return 5
}