FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/go

RUN apt update && apt install -y software-properties-common

RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt update && apt install -y \
	redis-server \
	libpcre++-dev \
	build-essential \
	golang-go \
	git-core


RUN mkdir -p /go/src/github.com/jptosso/

COPY . /go/src/github.com/jptosso/coraza-waf/
WORKDIR /go/src/github.com/jptosso/coraza-waf/
RUN make libinjection
RUN make compile
RUN make install

RUN service redis-server start

CMD ["/usr/local/bin/waf-rproxy", "-f", "/etc/coraza/rproxy.yaml"]