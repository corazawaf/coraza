#!/bin/bash

PACKAGE=corazawaf
VERSION=0.1alpha.4
TMP_PATH=/tmp/coraza-waf-build/$PACKAGE-$VERSION
COMPATIBILITY=10

make clean
sudo apt update
sudo apt install -y gnupg \
				 dput \
				 dh-make \
				 devscripts \
				 lintian \
				 debhelper \
               	 golang-go \
               	 libpcre++-dev

sudo rm -rf $TMP_PATH
mkdir -p $TMP_PATH
cp -r * $TMP_PATH/
cd $TMP_PATH/
sudo make libinjection-install
pwd

dh_make -p $PACKAGE \
		--single \
		--native \
		--copyright apache \
		--email jptosso@gmail.com
rm debian/*.ex debian/*.EX 
cat scripts/debian/rules > debian/rules
echo $COMPATIBILITY > debian/compat
touch NEWS install-sh missing Makefile.am README AUTHORS ChangeLog
cp LICENSE COPYING

perl -i -pe "s/unstable/$(lsb_release -cs)/" debian/changelog

cat << EOF > debian/postinst
#!/bin/bash
useradd -r -s /bin/false coraza-waf ||true
chown -R coraza-waf:root /opt/coraza-waf/log
chown -R root:root /etc/coraza-waf
find /opt/coraza-waf -type d -exec chmod 755 {} \;
find /etc/coraza-waf -type d -exec chmod 755 {} \;
find /etc/coraza-waf -type f -exec chmod 655 {} \;
chown -R root:root /bin/coraza-waf
#update-rc.d coraza-waf defaults
ldconfig
#TODO add inittab for autorespawn
EOF

cat << EOF > debian/control
Source: corazawaf
Section: base
Priority: optional
Maintainer: Juan Pablo Tosso <jptosso@gmail.com>
Build-Depends: debhelper (>=10),
               libpcre++-dev,
               golang-go,
               build-essential

Package: $PACKAGE
Architecture: amd64
Depends: libpcre++-dev
Homepage: https://jptosso.github.io/coraza-waf/
Description: Coraza Web Application Firewall
EOF

perl -i -0777 -pe "s/(Copyright: ).+\n +.+/\${1}$(date +%Y) Juan Pablo Tosso <jptosso@gmail.com>/" debian/copyright
debuild -S