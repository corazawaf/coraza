package proxy

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"gopkg.in/yaml.v2"
	"net/http"
	"net/http/httputil"
	"sync"
)

type UpstreamServer struct {
	Address         string `yaml:"address"`
	Port            int    `yaml:"port"`
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
	Path      string `yaml:""`
	PathTrail bool   `yaml:""`
	Policy    string `yaml:""`
	ErrorCgi  string `yaml:""`
	AccessLog string `yaml:""`
	Upstream  string `yaml:""`

	//Private non YAML fields
	Listeners    []*http.ServeMux
	Waf *engine.Waf
	mux         *sync.RWMutex
	ups *Upstream
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
	return &config, nil
}
