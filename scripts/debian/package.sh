#!/bin/bash

PACKAGE=coraza-waf
VERSION=0.1-1
TMP_PATH=/tmp/coraza-waf-build/$VERSION
COMPATIBILITY=9


gcc -std=c99 -Wall -Werror -fpic -c pkg/utils/libinjection/src/libinjection_sqli.c -o libinjection_sqli.o 
gcc -std=c99 -Wall -Werror -fpic -c pkg/utils/libinjection/src/libinjection_xss.c -o libinjection_xss.o
gcc -std=c99 -Wall -Werror -fpic -c pkg/utils/libinjection/src/libinjection_html5.c -o libinjection_html5.o
gcc -dynamiclib -shared -o libinjection.so libinjection_sqli.o libinjection_xss.o libinjection_html5.o
			

rm -rf $TMP_PATH
mkdir -p $TMP_PATH/DEBIAN
mkdir -p $TMP_PATH/etc/init.d
mkdir -p $TMP_PATH/etc/coraza-waf/profiles/default
mkdir -p $TMP_PATH/opt/coraza-waf/log/audit
mkdir -p $TMP_PATH/bin
mkdir -p $TMP_PATH/usr/local/include
mkdir -p $TMP_PATH/usr/local/lib

cp *.so $TMP_PATH/usr/local/lib
cp *.o $TMP_PATH/usr/local/lib
cp pkg/utils/libinjection/src/*.h $TMP_PATH/usr/local/include/
chmod 444 $TMP_PATH/usr/local/include/libinjection*

go get ./...
go build cmd/skipper/main.go

cp scripts/debian/coraza-waf.service $TMP_PATH/etc/init.d/coraza-waf
cp examples/skipper/default.conf $TMP_PATH/etc/coraza-waf/profiles/default/
cp scripts/debian/postinst $TMP_PATH/DEBIAN/
cp changelog $TMP_PATH/DEBIAN/
cp LICENSE $TMP_PATH/DEBIAN/license
cp main $TMP_PATH/bin/coraza-waf
cp examples/skipper/* $TMP_PATH/etc/coraza-waf/
echo $COMPATIBILITY > $TMP_PATH/DEBIAN/compat
touch $TMP_PATH/etc/coraza-waf/profiles/default/rules.conf

cd ../
git clone https://github.com/zalando/skipper
cd skipper
make eskip
mv bin/eskip $TMP_PATH/bin/

cat << EOF > $TMP_PATH/DEBIAN/control
Package: $PACKAGE
Version: $VERSION
Section: base
Source: https://github.com/jptosso/coraza-waf/releases/download/%{version}/coraza-waf-%VERSION-linux-amd64.tar.gz
Priority: optional
Architecture: amd64
Homepage: https://jptosso.github.io/coraza-waf/
Maintainer: Juan Pablo Tosso <jptosso@gmail.com>
Description: Coraza Web Application Firewall
EOF

cd $TMP_PATH/..
dpkg-deb --build $PACKAGE_$VERSION