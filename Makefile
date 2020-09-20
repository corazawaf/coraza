# Go parameters
GOCMD=go
ENTRYFILE=cmd/coraza-waf/skipper.go cmd/coraza-waf/main.go
GOBUILD=$(GOCMD) build -ldflags "-w -s" $(ENTRYFILE) -o coraza-waf
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=skipper
BINARY_UNIX=$(BINARY_NAME)

all: waf
waf: 	
		CGO_ENABLED=1 go get ./...
		$(GOBUILD)
test: 
		$(GOTEST) ./...
		$(GOTEST) -v -coverprofile=docs/coverage-waf.out ./...
clean: 
		$(GOCLEAN)
		rm -f $(BINARY_NAME)
libinjection:
		gcc -std=c99 -Wall -Werror -fpic -c pkg/utils/libinjection/src/libinjection_sqli.c -o libinjection_sqli.o 
		gcc -std=c99 -Wall -Werror -fpic -c pkg/utils/libinjection/src/libinjection_xss.c -o libinjection_xss.o
		gcc -std=c99 -Wall -Werror -fpic -c pkg/utils/libinjection/src/libinjection_html5.c -o libinjection_html5.o
		gcc -dynamiclib -shared -o libinjection.so libinjection_sqli.o libinjection_xss.o libinjection_html5.o
		#OS X: update_dyld_shared_cache
		cp *.so /usr/local/lib
		cp *.o /usr/local/lib
		cp pkg/utils/libinjection/src/*.h /usr/local/include/
		chmod 444 /usr/local/include/libinjection*
		ldconfig
eskip:
		git clone https://github.com/zalando/skipper
		cd skipper
		make eskip
		mv bin/eskip ../	
skipper-filter:
		go build -ldflags "-w -s" -linkshared cmd/coraza-waf/skipper.go -o skipper_mod_coraza_waf.so
install: libinjection eskip
		# only for debian by now
		mkdir -p /etc/coraza-waf/profiles/default
		mkdir -p /opt/coraza-waf/log/audit
		id -u coraza-waf &>/dev/null || useradd -r -s /bin/false coraza-waf
		cp scripts/debian/coraza-waf.service /etc/init.d/coraza-waf
		cp examples/skipper/default.conf /etc/coraza-waf/profiles/default/
		mv coraza-waf /bin/coraza-waf
		mv eskip /bin/
		cp examples/skipper/routes.eskip /etc/coraza-waf/
		cp examples/skipper/skipper.yaml /etc/coraza-waf/
		cp examples/skipper/default.conf /etc/coraza-waf/profiles/default/rules.conf
