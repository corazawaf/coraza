package rproxy

import (
    "github.com/jptosso/coraza/pkg/waf"
    "gopkg.in/yaml.v2"
)

type ConfigUpstreamServer struct {
    Address string `yaml:"address"`
    Schema string `yaml:"schema"`
    Weight string `yaml:"weight"`
}

type ConfigApplication struct {
    Id string `yaml:"id"`
    BalanceMethod string `yaml:"balance_method"`
    Policy string `yaml:"policy"`
    PolicyDatapath string `yaml:"policy_datapath"`
    Hostnames []string `yaml:"hostnames"`
}
type Rproxy struct {
    UpstreamServers []*ConfigUpstreamServer `yaml:"upstreams"`
    Application *ConfigApplication `yaml:"application"`
    Address string `yaml:"address"`
    Port int `yaml:"port"`
    UnixSock string `yaml:"unix_sock"`
    ProfilingPath string `yaml:"profiling_path"`
    AuditLogPath string `yaml:"audit_log_path"`
    ErrorLogPath string `yaml:"error_log_path"`
    PidPath string `yaml:"pid_path"`
    RedisPool []string `yaml:"redis_pool"`//redis :// [[username :] password@] host [: port] [/ database][? [timeout=timeout[d|h|m|s|ms|us|ns]] [&_database=database_]]
}


type Config struct {
    Rproxy *Rproxy
}

func ParseConfig(hs *HttpServer, data []byte) error{
	config := Config{}
    err := yaml.Unmarshal([]byte(data), &config)
    if err != nil {
        return err
    }
    proxy := config.Rproxy
    logger := &waf.Logger{}
    logger.Init()
    app := proxy.Application
    server := Server{
        Address: proxy.Address,
        Port: proxy.Port,
        Hostnames: app.Hostnames,
    }
    server.Init()
    wafinstance := waf.Waf{}
    wafinstance.Init(logger)    
    wafinstance.Datapath = app.PolicyDatapath
    wafparser := waf.Parser{}
    wafparser.Init(&wafinstance)
    err = wafparser.FromFile(app.Policy)
    if err != nil {
        return err
    }
    wafinstance.SortRules()
    location := Location{
        Path: "/",
    }

    location.Init(&wafinstance)
    for _, us := range proxy.UpstreamServers {
        location.AddUpstream(us)
    }
    server.AddLocation(&location) 
    hs.AddServer(&server)
    return  nil
}