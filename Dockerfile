FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/go

RUN apt update && apt install -y software-properties-common

RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt update && apt install -y \
	libpcre++-dev \
	build-essential \
	golang-go \
	git-core


RUN go get -u github.com/jptosso/coraza-waf/...

WORKDIR /go/src/github.com/jptosso/coraza-waf/
RUN ./scripts/debian/package.sh
RUN rm -rf /tmp/coraza-waf-build
RUN rm -rf /go

RUN sudo dpkg -i /tmp/coraza-waf-build/coraza-waf_0.1-1.rpm

CMD ["coraza-waf"]