FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/go

RUN apt update && apt install -y software-properties-common

RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt update && apt install -y \
	build-essential \
	golang-go \
	git-core

RUN mkdir -p /go/src/github.com/jptosso/
WORKDIR /go/src/github.com/jptosso
RUN git clone https://github.com/jptosso/coraza-waf/

WORKDIR /go/src/github.com/jptosso/coraza-waf/
RUN make libinjection
RUN make
RUN make install

RUN rm -rf /tmp/coraza-waf-build
RUN rm -rf /go

EXPOSE 9090/tcp
USER coraza-waf
CMD ["coraza-waf"]