#!/bin/bash

user=coraza-waf
pid=/opt/coraza-waf/run/coraza-rpc.pid
config=/etc/coraza-waf/rpc.yaml
# Carry out specific functions when asked to by the system

function start {
  sudo -u $user bash -c '/usr/bin/env coraza-waf -m grpc -f /etc/coraza-waf/rpc.yaml -pid /opt/coraza-waf/run/coraza-rpc.pid > /dev/null 2>&1 &'
}

function stop {
  if test -f "$pid"; then
      sudo -u $user bash -c 'kill $(cat /opt/coraza-waf/run/coraza-rpc.pid)'
  fi
}

case "$1" in
  start)
    echo "Starting Coraza WAF..."
    start
    ;;
  stop)
    echo "Stopping Coraza WAF..."
    stop
    ;;
  restart)
    echo "Stopping Coraza WAF..."
    stop
    echo "Starting Coraza WAF..."
    start
    ;;    
  reload)
    echo "Reloading Coraza WAF"
    sudo -u $user bash -c 'kill -1 $(cat /opt/coraza-waf/run/coraza-rpc.pid)'
    ;;        
  *)
    echo "Usage: coraza-ctl {start|stop|restart|reload}"
    exit 1
    ;;
esac