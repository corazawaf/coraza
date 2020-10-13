# Go parameters
CGOLDFLAGS=-O2 -L$(CURDIR)
GOCMD=GOCACHE=/tmp CGO_CFLAGS="-I/usr/include" CGO_LDFLAGS="$(CGOLDFLAGS)" go
ENTRYFILE=cmd/coraza-waf/*.go
GOBUILD=$(GOCMD) build -mod=vendor -ldflags "-w -s" -o coraza-waf $(ENTRYFILE)
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=skipper
BINARY_UNIX=$(BINARY_NAME)

#For install
BINDIR := /usr/bin
CORDIR := /etc/coraza-waf
OPTDIR := /opt/coraza-waf

all: libinjection waf
waf: 	
		$(GOBUILD)
test: 
		$(GOTEST) ./...
		$(GOTEST) -v -coverprofile=docs/coverage-waf.out ./...
clean: 
		rm -f $(BINARY_NAME) *.so *.o
libinjection:
		gcc -std=c99 -Wall -Werror -fpic -c pkg/utils/libinjection/src/libinjection_sqli.c -o libinjection_sqli.o 
		gcc -std=c99 -Wall -Werror -fpic -c pkg/utils/libinjection/src/libinjection_xss.c -o libinjection_xss.o
		gcc -std=c99 -Wall -Werror -fpic -c pkg/utils/libinjection/src/libinjection_html5.c -o libinjection_html5.o
		gcc -dynamiclib -shared -o libinjection.so libinjection_sqli.o libinjection_xss.o libinjection_html5.o
libinjection-install: libinjection
		#OS X: update_dyld_shared_cache
		cp *.so /usr/local/lib
		cp *.o /usr/local/lib
		cp pkg/utils/libinjection/src/*.h /usr/local/include/
		chmod 444 /usr/local/include/libinjection*
		ldconfig	
protoc:
		protoc -I internal/proto --go_out=plugins=grpc:. internal/proto/*.proto
skipper-filter:
		go build -ldflags "-w -s" -linkshared cmd/coraza-waf/skipper.go -o skipper_mod_coraza_waf.so
install:
		# only for debian by now
		mkdir -p ${DESTDIR}${CORDIR}/profiles/default
		mkdir -p ${DESTDIR}${OPTDIR}/log/audit
		mkdir -p ${DESTDIR}/usr/include
		mkdir -p ${DESTDIR}/usr/lib
		mkdir -p ${DESTDIR}${BINDIR}
		#libinjection
		cp *.so ${DESTDIR}/usr/lib
		cp *.o ${DESTDIR}/usr/lib
		cp pkg/utils/libinjection/src/*.h ${DESTDIR}/usr/include/
		#ldconfig will fail in CI
		ldconfig ||true

		useradd -r -s /bin/false coraza-waf || true
		cp examples/skipper/default.conf ${DESTDIR}${CORDIR}/profiles/default/
		cp coraza-waf ${DESTDIR}${BINDIR}/coraza-waf
		cp examples/skipper/routes.eskip ${DESTDIR}${CORDIR}/
		cp examples/rpc/rpc.yaml ${DESTDIR}${CORDIR}/
		cp examples/skipper/skipper.yaml ${DESTDIR}${CORDIR}/
		cp examples/skipper/default.conf ${DESTDIR}${CORDIR}/profiles/default/rules.conf
		chown -R coraza-waf:root ${DESTDIR}${OPTDIR}/log || true
		chown -R root:root ${DESTDIR}${CORDIR}
		chown root:root ${DESTDIR}${BINDIR}/coraza-waf
		chmod 444 ${DESTDIR}/usr/include/libinjection*
		find ${DESTDIR}${OPTDIR} -type d -exec chmod 755 {} \;
		find ${DESTDIR}${CORDIR} -type d -exec chmod 755 {} \;
		find ${DESTDIR}${CORDIR} -type f -exec chmod 655 {} \;
		# If we want to bind low ports using coraza-waf
		#setcap CAP_NET_BIND_SERVICE=+eip /bin/coraza-waf
