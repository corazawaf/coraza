# Go parameters
GOCMD=go
ENTRYFILE=cmd/skipper/main.go
GOBUILD=$(GOCMD) build -ldflags "-w -s" $(ENTRYFILE)
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=skipper
BINARY_UNIX=$(BINARY_NAME)

all: libinjection compile
compile: 	
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
		sed -i 's/package skipper/package main/g' pkg/skipper/filter.go > pkg/skipper/filter.go
		go build -ldflags "-w -s" -linkshared pkg/skipper/filter.go -o skipper_mod_coraza_waf.so
		sed -i 's/package main/package skipper/g' pkg/skipper/filter.go > pkg/skipper/filter.go
install:
		# only for debian by now
		mkdir -p /etc/coraza-waf/profiles/default
		mkdir -p /opt/coraza-waf/log/audit
		id -u coraza-waf &>/dev/null || useradd -r -s /bin/false coraza-waf
		cp scripts/debian/coraza-waf.service /etc/init.d/coraza-waf
		cp examples/skipper/default.conf /etc/coraza-waf/profiles/default/
		mv main /bin/coraza-waf
		cp examples/skipper/routes.eskip /etc/coraza-waf/
		cp examples/skipper/skipper.yaml /etc/coraza-waf/
		cp examples/skipper/default.conf /etc/coraza-waf/profiles/default/rules.conf
		update-rc.d coraza-waf defaults
		make eskip
		mv eskip /bin/
		chown -R coraza-waf:root /opt/coraza-waf/log
		chown -R root:root /etc/coraza-waf
		chown root:root /bin/coraza-waf
		chown root:root /bin/eskip
		find /opt/coraza-waf -type d -exec chmod 755 {} \;
		find /etc/coraza-waf -type d -exec chmod 755 {} \;
		find /etc/coraza-waf -type f -exec chmod 655 {} \;
