# Go parameters
CGOLDFLAGS=-O2 -L$(CURDIR)
GOCMD=GOCACHE=/tmp CGO_CFLAGS="-I/usr/include" CGO_LDFLAGS="$(CGOLDFLAGS)" CGO_ENABLED=1 go
GOTEST=$(GOCMD) test
TMPDIR=/tmp/libinjection
REPO=https://github.com/libinjection/libinjection


all: deps
test: 
		$(GOTEST) ./...
		$(GOTEST) -v -coverprofile=docs/coverage-waf.out ./...
deps:
		git clone $(REPO) $(TMPDIR)
		gcc -std=c99 -Wall -Werror -fpic -c $(TMPDIR)/src/libinjection_sqli.c -o $(TMPDIR)/libinjection_sqli.o 
		gcc -std=c99 -Wall -Werror -fpic -c $(TMPDIR)/src/libinjection_xss.c -o $(TMPDIR)/libinjection_xss.o
		gcc -std=c99 -Wall -Werror -fpic -c $(TMPDIR)/src/libinjection_html5.c -o $(TMPDIR)/libinjection_html5.o
		gcc -dynamiclib -shared -o $(TMPDIR)/libinjection.so $(TMPDIR)/libinjection_sqli.o $(TMPDIR)/libinjection_xss.o $(TMPDIR)/libinjection_html5.o
		cp $(TMPDIR)/*.so /usr/local/lib
		cp $(TMPDIR)/*.o /usr/local/lib
		cp $(TMPDIR)/src/*.h /usr/local/include/
		chmod 444 /usr/local/include/libinjection*
		rm -rf /tmp/libinjection
		echo "Do not forget to run ldconfig"