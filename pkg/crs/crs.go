package crs

import (
	"errors"
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"os"
	"strconv"
	"strings"
)

type Crs struct {
	DefaultParanoia              int
	EnforceUrlEncoded            bool
	InboundAnomalyScoreThreshold int
	OutboundScoreThreshold       int
	Exclusions                   map[string][]string // Path and application
	AllowedHttpMethods           []string
	AllowedReqContentType        []string
	AllowedHttpVersions          []string
	AllowedReqCharset            []string
	ForbiddenFileExtensions      []string
	ForbiddenRequestHeaders      []string
	StaticFileExtensions         []string
	CountryBlock                 []string
	MaxNumArgs                   int
	MaxArgNameLength             int
	MaxArgValueLength            int
	MaxTotalArgLength            int
	MaxFileSize                  int64
	MaxCombinedFileSize          int64
	SamplingPercentaje           int
	//BlockBlSearchIp              bool
	//BlockBlSuspiciousIp          bool
	//BlockBlHarvesterIp           bool
	//BlockBlSpammerIp             bool

	DosBlockTimeout         int
	DosCounterThreshold     int
	DosBurstTimeSlice       int
	ValidateUtf8Encoding    bool
	ReputationBlock         bool
	ReputationBlockDuration int
	IpWhitelist             []string

	IpKey      string
	SessionKey string

	files []string
	waf      *engine.Waf
}

func (c *Crs) Init(templatepath string, waf *engine.Waf) error {
	if waf == nil {
		return errors.New("WAF cannot be nil")
	}
	if !dirExists(templatepath) {
		return errors.New("Template dir must exist")
	}
	c.files = []string{}
	files := []string{
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
	for _, f := range files{
		if !utils.FileExists(templatepath + f){
			return errors.New("File " + f + " must exist")
		}
		c.files = append(c.files, templatepath + f)
	}
	c.waf = waf
	return nil
}

func (c *Crs) Build() error {
	replace := map[string]string{
		"paranoia_level":                       strconv.Itoa(c.DefaultParanoia),
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
		"total_arg_length":                     strconv.Itoa(c.MaxTotalArgLength),
		"max_file_size":                        strconv.FormatInt(c.MaxFileSize, 10),
		"combined_file_sizes":                  strconv.FormatInt(c.MaxCombinedFileSize, 10),
		"sampling_percentage":                  strconv.Itoa(c.SamplingPercentaje),
		"dos_block_timeout":                    strconv.Itoa(c.DosBlockTimeout),
		"dos_counter_threshold":                strconv.Itoa(c.DosCounterThreshold),
		"dos_burst_time_slice":                 strconv.Itoa(c.DosBurstTimeSlice),
		"crs_validate_utf8_encoding":           boolToString(c.ValidateUtf8Encoding),
		"do_reput_block":                       boolToString(c.ReputationBlock),
		"reput_block_duration":                 strconv.Itoa(c.ReputationBlockDuration),
		"ip_whitelist":                         strings.Join(c.IpWhitelist, ","),
	}
	buff := "SecAction \"id:900000,nolog,phase:1,t:none,"
	for k, v := range replace {
		buff += fmt.Sprintf("setvar:tx.%s=%s,", k, v)
	}
	for _, e := range c.Exclusions {
		buff += fmt.Sprintf("setvar:tx.crs_exclusions_%s=1,", e)
	}
	buff += "pass\"\n"
	var err error
	p, _ := parser.NewParser(c.waf)
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
	for _, f := range c.files {
		err = p.FromFile(f)
		if err != nil{
			return err
		}
	}
	return nil
}

func NewCrs(template string, waf *engine.Waf) (*Crs, error) {
	c := &Crs{
		DefaultParanoia:    1,
		AllowedHttpMethods: []string{"GET", "HEAD", "POST", "OPTIONS"},
		IpWhitelist:        []string{"127.0.0.1"},
	}
	err := c.Init(template, waf)
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
