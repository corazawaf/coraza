#!/bin/bash

PACKAGE=coraza-waf
VERSION=0.1-1
TMP_PATH=/tmp/coraza-waf-build/$VERSION
COMPATIBILITY=9

make
rm -rf $TMP_PATH
mkdir -p $TMP_PATH/DEBIAN
mkdir -p $TMP_PATH/etc/init.d
mkdir -p $TMP_PATH/etc/coraza-waf/profiles/default
mkdir -p $TMP_PATH/opt/coraza-waf/log/audit
mkdir -p $TMP_PATH/bin

cp scripts/debian/coraza-waf.service $TMP_PATH/etc/init.d/coraza-waf
cp examples/skipper/default.conf $TMP_PATH/etc/coraza-waf/profiles/default/
cp scripts/debian/postinst $TMP_PATH/DEBIAN/
cp changelog $TMP_PATH/DEBIAN/
cp LICENSE $TMP_PATH/DEBIAN/license
cp main $TMP_PATH/bin/coraza-waf
cp examples/skipper/* $TMP_PATH/etc/coraza-waf/
echo $COMPATIBILITY > $TMP_PATH/DEBIAN/compat
touch $TMP_PATH/etc/coraza-waf/profiles/default/rules.conf


cat << EOF > $TMP_PATH/DEBIAN/control
Package: $PACKAGE
Version: $VERSION
Section: base
Priority: optional
Architecture: all
Depends: libpcre2-dev
Maintainer: Juan Pablo Tosso <jptosso@gmail.com>
Description: Coraza Web Application Firewall
EOF

cd $TMP_PATH/..
dpkg-deb --build $PACKAGE_$VERSION
mv $VERSION.deb $PACKAGE_$VERSION.deb