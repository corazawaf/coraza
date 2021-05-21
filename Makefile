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
skipper-filter:
		go build -ldflags "-w -s" -linkshared cmd/coraza-waf/skipper.go -o skipper_mod_coraza_waf.so