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

RUN mkdir -p /go/src/github.com/jptosso/
WORKDIR /go/src/github.com/jptosso
RUN git clone https://github.com/jptosso/coraza-waf/

WORKDIR /go/src/github.com/jptosso/coraza-waf/
RUN make libinjection
RUN mkdir -p /etc/coraza-waf/profiles/default
RUN mkdir -p /opt/coraza-waf/log/audit
RUN useradd -r -s /bin/false coraza-waf
RUN cp scripts/debian/coraza-waf.service /etc/init.d/coraza-waf
RUN cp examples/skipper/default.conf /etc/coraza-waf/profiles/default/
RUN go build -ldflags "-w -s" cmd/skipper/main.go 
RUN mv main /bin/coraza-waf
RUN cp examples/skipper/routes.eskip /etc/coraza-waf/
RUN cp examples/skipper/skipper.yaml /etc/coraza-waf/
RUN cp examples/skipper/default.conf /etc/coraza-waf/profiles/default/rules.conf
RUN chown -R coraza-waf:root /opt/coraza-waf/log
RUN chown -R root:root /etc/coraza-waf
RUN chown root:root /bin/coraza-waf
RUN find /opt/coraza-waf -type d -exec chmod 755 {} \;
RUN find /etc/coraza-waf -type d -exec chmod 755 {} \;
RUN find /etc/coraza-waf -type f -exec chmod 655 {} \;


RUN rm -rf /tmp/coraza-waf-build
RUN rm -rf /go

RUN apt remove -y build-essential \
	golang-go \
	git-core

EXPOSE 9090/tcp
USER coraza-waf
CMD ["coraza-waf"]