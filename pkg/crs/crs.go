// Copyright 2020 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crs

import (
	"errors"
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"os"
	"path"
	"strconv"
	"strings"
)

type Crs struct {
	TemplateDir                  string   `yaml:"template_dir"`
	DefaultParanoia              int      `yaml:"default_paranoia"`
	EnforceUrlEncoded            bool     `yaml:"enforce_reqbody_url_encoded"`
	InboundAnomalyScoreThreshold int      `yaml:"inbound_anomaly_score_threshold"`
	OutboundScoreThreshold       int      `yaml:"outbound_anomaly_score_threshold"`
	Exclusions                   []string `yaml:"exclusions"`
	AllowedHttpMethods           []string `yaml:"allowed_http_methods"`
	AllowedReqContentType        []string `yaml:"allowed_request_content_type"`
	AllowedHttpVersions          []string `yaml:"allowed_http_versions"`
	AllowedReqCharset            []string `yaml:"allowed_request_ct_charset"`
	ForbiddenFileExtensions      []string `yaml:"forbidden_file_extensions"`
	ForbiddenRequestHeaders      []string `yaml:"forbidden_request_headers"`
	StaticFileExtensions         []string `yaml:"static_extensions"`
	CountryBlock                 []string `yaml:"country_block"`
	MaxNumArgs                   int      `yaml:"max_num_args"`
	MaxArgNameLength             int      `yaml:"max_arg_name_length"`
	MaxArgValueLength            int      `yaml:"max_arg_value_length"`
	MaxTotalArgsLength           int      `yaml:"max_total_args_length"`
	MaxFileSize                  int64    `yaml:"max_file_size`
	MaxCombinedFileSize          int64    `yaml:"max_combined_file_size"`
	SamplingPercentage           int      `yaml:"sampling_percentage"`
	DosBlockTimeout              int      `yaml:"dos_block_timeout"`
	DosCounterThreshold          int      `yaml:"dos_counter_threshold"`
	DosBurstTimeSlice            int      `yaml:"dos_burst_time_slice"`
	ValidateUtf8Encoding         bool     `yaml:"validate_utf8_encoding"`
	ReputationBlock              bool     `yaml:"reputation_block"`
	ReputationBlockDuration      int      `yaml:"reputation_block_duration"`
	IpWhitelist                  []string `yaml:"ip_whitelist"`
	Mode                         string   `yaml:"mode"`
	//BlockBlSearchIp              bool
	//BlockBlSuspiciousIp          bool
	//BlockBlHarvesterIp           bool
	//BlockBlSpammerIp             bool

	waf *engine.Waf
}

func (c *Crs) Init(waf *engine.Waf) error {
	if waf == nil {
		return errors.New("WAF cannot be nil")
	}
	c.waf = waf
	return nil
}

func (c *Crs) Build() error {
	if !dirExists(c.TemplateDir) {
		return errors.New("Template dir must exist")
	}
	files := []string{
		"REQUEST-901-INITIALIZATION.conf",
		"REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf",
		"REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf",
		"REQUEST-903.9003-NEXTCLOUD-EXCLUSION-RULES.conf",
		"REQUEST-903.9004-DOKUWIKI-EXCLUSION-RULES.conf",
		"REQUEST-903.9005-CPANEL-EXCLUSION-RULES.conf",
		"REQUEST-903.9006-XENFORO-EXCLUSION-RULES.conf",
		"REQUEST-905-COMMON-EXCEPTIONS.conf",
		"REQUEST-910-IP-REPUTATION.conf",
		"REQUEST-911-METHOD-ENFORCEMENT.conf",
		"REQUEST-912-DOS-PROTECTION.conf",
		"REQUEST-913-SCANNER-DETECTION.conf",
		"REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
		"REQUEST-921-PROTOCOL-ATTACK.conf",
		"REQUEST-930-APPLICATION-ATTACK-LFI.conf",
		"REQUEST-931-APPLICATION-ATTACK-RFI.conf",
		"REQUEST-932-APPLICATION-ATTACK-RCE.conf",
		"REQUEST-933-APPLICATION-ATTACK-PHP.conf",
		"REQUEST-934-APPLICATION-ATTACK-NODEJS.conf",
		"REQUEST-941-APPLICATION-ATTACK-XSS.conf",
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
		"REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
		"REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
		"REQUEST-949-BLOCKING-EVALUATION.conf",
		"RESPONSE-950-DATA-LEAKAGES.conf",
		"RESPONSE-951-DATA-LEAKAGES-SQL.conf",
		"RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
		"RESPONSE-953-DATA-LEAKAGES-PHP.conf",
		"RESPONSE-954-DATA-LEAKAGES-IIS.conf",
		"RESPONSE-959-BLOCKING-EVALUATION.conf",
		"RESPONSE-980-CORRELATION.conf",
	}
	for i, f := range files {
		p := path.Join(c.TemplateDir, f)
		if !utils.FileExists(p) {
			return errors.New("File " + p + " must exist")
		}
		files[i] = p
	}
	replace := map[string]string{
		"paranoia_level":                       strconv.Itoa(c.DefaultParanoia),
		"executing_paranoia_level":             strconv.Itoa(c.DefaultParanoia),
		"enforce_bodyproc_urlencoded":          boolToString(c.EnforceUrlEncoded),
		"inbound_anomaly_score_threshold":      strconv.Itoa(c.InboundAnomalyScoreThreshold),
		"outbound_anomaly_score_threshold":     strconv.Itoa(c.OutboundScoreThreshold),
		"allowed_methods":                      strings.Join(c.AllowedHttpMethods, " "),
		"allowed_request_content_type":         joinAndEnclose(c.AllowedReqContentType, "|"),
		"allowed_http_versions":                strings.Join(c.AllowedHttpVersions, " "),
		"allowed_request_content_type_charset": strings.Join(c.AllowedReqCharset, "|"),
		"restricted_extensions":                strings.Join(c.ForbiddenFileExtensions, "/ "),
		"restricted_headers":                   joinAndEnclose(c.ForbiddenRequestHeaders, "/"),
		"static_extensions":                    joinAndEnclose(c.StaticFileExtensions, "/"),
		"high_risk_country_codes":              strings.Join(c.CountryBlock, " "),
		"max_num_args":                         strconv.Itoa(c.MaxNumArgs),
		"arg_name_length":                      strconv.Itoa(c.MaxArgNameLength),
		"arg_length":                           strconv.Itoa(c.MaxArgValueLength),
		"total_arg_length":                     strconv.Itoa(c.MaxTotalArgsLength),
		"max_file_size":                        strconv.FormatInt(c.MaxFileSize, 10),
		"combined_file_sizes":                  strconv.FormatInt(c.MaxCombinedFileSize, 10),
		"sampling_percentage":                  strconv.Itoa(c.SamplingPercentage),
		"dos_block_timeout":                    strconv.Itoa(c.DosBlockTimeout),
		"dos_counter_threshold":                strconv.Itoa(c.DosCounterThreshold),
		"dos_burst_time_slice":                 strconv.Itoa(c.DosBurstTimeSlice),
		"crs_validate_utf8_encoding":           boolToString(c.ValidateUtf8Encoding),
		"do_reput_block":                       boolToString(c.ReputationBlock),
		"reput_block_duration":                 strconv.Itoa(c.ReputationBlockDuration),
		"ip_whitelist":                         strings.Join(c.IpWhitelist, ","),
		"crs_setup_version":                    "300",
		"critical_anomaly_score":               "5",
		"error_anomaly_score":                  "4",
		"warning_anomaly_score":                "3",
		"notice_anomaly_score":                 "2",
	}
	buff := ""
	var err error
	p, _ := parser.NewParser(c.waf)
	switch c.Mode {
	case "strict":
		buff = `SecDefaultAction "phase:1,log,auditlog,deny,status:403"` + "\n" 
		buff += `SecDefaultAction "phase:2,log,auditlog,deny,status:403"` + "\n"
		break
	case "scoring":
		buff = `SecDefaultAction "phase:1,log,auditlog,pass"` + "\n" 
		buff += `SecDefaultAction "phase:2,log,auditlog,pass"` + "\n"
		break
	default:
		buff = c.Mode + "\n"
	}
	err = p.FromString(buff)
	if err != nil {
		return err
	}
	buff = "SecAction \"id:900000,pass,phase:1,t:none,"
	for k, v := range replace {
		buff += fmt.Sprintf("setvar:'tx.%s=%s',", k, v)
	}
	for _, e := range c.Exclusions {
		buff += fmt.Sprintf("setvar:'tx.crs_exclusions_%s=1',", e)
	}
	buff += "nolog\"\n"
	err = p.FromString(buff)
	if err != nil {
		return err
	}
	if c.IpWhitelist != nil && len(c.IpWhitelist) > 0 {
		err = p.FromString(`SecRule REMOTE_ADDR "@ipMatch %{tx.ip_whitelist}" "id:900001, phase:1,pass,nolog,ctl:ruleEngine=Off"`)
		if err != nil {
			return err
		}
	}
	for _, f := range files {
		err = p.FromFile(f)
		if err != nil {
			return err
		}
	}
	c.waf.Rules.Sort()
	return nil
}

func NewCrs(waf *engine.Waf) (*Crs, error) {
	c := &Crs{
		DefaultParanoia:    1,
		AllowedHttpMethods: []string{"GET", "HEAD", "POST", "OPTIONS"},
		IpWhitelist:        []string{"127.0.0.1"},
	}
	err := c.Init(waf)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func joinAndEnclose(arr []string, enclose string) string {
	res := make([]string, len(arr))
	for i, e := range arr {
		res[i] = enclose + e + enclose
	}
	return strings.Join(res, " ")
}

func boolToString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func dirExists(dir string) bool {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}
