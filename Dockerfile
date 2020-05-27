FROM ubuntu:18.04

RUN export DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y \
	redis-server \
	libpcre++-dev \
	build-essential \
	golang \
	git-core

COPY . /src
WORKDIR /src
RUN make libinjection
RUN make compile
RUN make install

RUN systemctl enable redis-server

CMD ["/usr/local/bin/waf-rproxy", "-f", "/etc/coraza/rproxy.yaml"]