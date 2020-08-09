---
title: Install in Linux
keywords: modsecurity, apache, coraza, waf, opensource
last_updated: July 16, 2020
sidebar: mydoc_sidebar
permalink: install-linux.html
folder: mydoc
---

## CentOS / RedHat

Using curl:
```
# It will attempt to prompt sudo password, if you are not using an interactive shell run it as root user.
$ curl -sL https://corazawaf.githubpages.io/install_1.0 | bash -
```

Without curl:

Download the latest RPM package from (github)[https://github.com/jptosso/coraza-waf/releases]
```
$ rpm vh coraza-waf.rpm
```

From repo:
```
$ sudo yum-config-manager \
    --add-repo \
    https://download.coraza.tech/linux/centos/coraza-waf.repo
$ sudo yum install coraza-waf
```

## Install from source

### Tested linux distributions

* Ubuntu 18.04LTS+
* CentOS 7
* RedHat 7
* Debian 10

### Build Command

```
$ export GOPATH=$(pwd)
$ export PATH=$PATH:$GOPATH/bin
$ make deps
$ make
$ sudo make install
$ make check
```


## Installing Coraza WAF with Nginx

Coraza WAF provides a high quality reverse proxy based on Skipper but in case you are more familiar with Nginx, there is a way you can make the best from both technologies.

/etc/coraza/routes.eskip
```
samplesite:
        Path("/")
        -> setRequestHeader("Host", "www.samplesite.abcdef")
        -> corazaWaf("/path/to/config.conf")
        -> "https://www.samplesite.abcdef";
```

/etc/nginx/sites-enabled/test-site.conf
```
server {
       listen 80;
       listen [::]:80;

       server_name www.samplesite.abcdef;

       location / {
               proxy_pass http://127.0.0.1:9000/
       }
}
```

## Selinux

Not supported yet.

## Upgrade Coraza WAF installation

If there is a pre-built image for your distribution it should be enough to update your it with your package manager, otherwise you might run the installation process again. The installation process won't delete any existing setting.

Keep in mind that each major upgrade might deprecate, change or add features that could break compatibility with your current settings, read them before you upgrade. Every release note is available under the "Release Notes" section of this site.