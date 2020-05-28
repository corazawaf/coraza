# Reverse Proxy for Coraza WAF

## Introduction
Coraza WAF is built with the golang vanilla http server and reverse proxy, I'm evaluating an alternative with https://github.com/zalando/skipper

## Features
- Load Balancing based on weight and round robin
- Full Coraza WAF support for all phases
- Custom error pages

## Limitations
- One instance per application
- Only one path per application (/)
- Phases 1, 2 and 3 are all run togather
- Golang does not support forking, so daemonization is not possible

## TODO
- ICAP support
- Reload


## Configuration
```
rproxy:
  upstreams:
    - server: 127.0.0.1
      port: 80
      schema: http
  debug_level: warn
  error_cgi: ./custom_error.py
  geoipdb: /tmp/countries.db
  icap_proxy_listener: 0.0.0.0:4444 #not supported yet
  icap_server: 10.10.10.1:1234 #not supported yet
  address: 127.0.0.1
  port: 12345  
  pid_path: /tmp/test.pid
  application:
    id: test-1
    hostnames:
      - asdf.com
    access_log: /tmp/access.log
    audit_log: /tmp/audit.log
    policy: /tmp/policy.conf #Rules file
    policy_datapath: /tmp/policy/ #Absolute path to store data files for operations like pmfromfile
```