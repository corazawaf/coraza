@echo checking requirements..
if ! [ -x "$(command -v git)" ]; then
  echo 'Error: git is not installed.' >&2
  exit 1
fi
if ! [ -x "$(command -v pip)" ]; then
  echo 'Error: pip is not installed.' >&2
  exit 1
fi
if ! [ -x "$(command -v coraza-rproxy)" ]; then
  echo 'Error: Coraza Reverse Proxy (coraza-rproxy) is not installed.' >&2
  exit 1
fi
if ! [ -x "$(command -v python)" ]; then
  echo 'Error: python is not installed.' >&2
  exit 1
fi
if ! [ -x "$(command -v py.test)" ]; then
  echo 'Error: py.test is not installed, try "pip install pytest".' >&2
  exit 1
fi

@echo Cloning OWASP CRS project...
rm -rf crs
git clone https://github.com/SpiderLabs/owasp-modsecurity-crs crs

@echo Installing OWASP CRS
cat <<- EOF > crs/owasp-crs.conf
  SecAction "id:900005,\
    phase:1,\
    nolog,\
    pass,\
    ctl:ruleEngine=DetectionOnly,\
    ctl:ruleRemoveById=910000,\
    setvar:tx.paranoia_level=4,\
    setvar:tx.crs_validate_utf8_encoding=1,\
    setvar:tx.arg_name_length=100,\
    setvar:tx.arg_length=400,\
    setvar:tx.crs_setup_version=300"
EOF
cat crs/csr-setup.conf.example >> crs/owasp-crs.conf
cat crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-901-INITIALIZATION.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-903.9003-NEXTCLOUD-EXCLUSION-RULES.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-903.9004-DOKUWIKI-EXCLUSION-RULES.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-903.9005-CPANEL-EXCLUSION-RULES.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-903.9006-XENFORO-EXCLUSION-RULES.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-910-IP-REPUTATION.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-912-DOS-PROTECTION.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-913-SCANNER-DETECTION.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-934-APPLICATION-ATTACK-NODEJS.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf >> crs/owasp-crs.conf
cat crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf >> crs/owasp-crs.conf
cat crs/rules/RESPONSE-950-DATA-LEAKAGES.conf >> crs/owasp-crs.conf
cat crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf >> crs/owasp-crs.conf
cat crs/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf >> crs/owasp-crs.conf
cat crs/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf >> crs/owasp-crs.conf
cat crs/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf >> crs/owasp-crs.conf
cat crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf >> crs/owasp-crs.conf
cat crs/rules/RESPONSE-980-CORRELATION.conf >> crs/owasp-crs.conf

@echo Patching CRS configurations...
rm crs/tests/regression/config.ini && cp utils/config.ini crs/tests/regression/
cd crs/tests/regression/
pip install requirements.txt

@echo Starting Coraza Reverse Proxy
coraza-rproxy -f ../data/config.yml

@echo Running tests...
py.test -v CRS_Tests.py --ruledir_recurse=tests/

@echo Cleaning...
cd ..
rm -rf crs


#TODO kill coraza-rproxy