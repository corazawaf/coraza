package profile

import (
	"errors"
	"github.com/jptosso/coraza-waf/pkg/crs"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"gopkg.in/yaml.v2"
)

type Profile struct {
	Key    string         `yaml:""`
	Rules  string         `yaml:""`
	Config *ProfileConfig `yaml:"config"`
}

type ProfileConfig struct {
	ArgumentSeparator       string               `yaml:"argument_separator"`
	DefaultActions          string               `yaml:"default_actions"`
	Geoipdb                 string               `yaml:"geoipdb"`
	TmpDir                  string               `yaml:"tmp_dir"`
	UnicodeMap              string               `yaml:"unicode_map"`
	UnicodePage             int                  `yaml:"unicode_page"`
	CollectionTimeout       int                  `yaml:"collection_timeout"`
	PcreMatchLimit          int                  `yaml:"pcre_match_limit"`
	PcreMatchLimitRecursion int                  `yaml:"pcre_match_limit_recursion"`
	PreRules                string               `yaml:"pre_rules"`
	AfterRules              string               `yaml:"after_rules"`
	FileUpload              *ProfileFileUpload   `yaml:"file_upload"`
	RequestBody             *ProfileRequestBody  `yaml:"request_body"`
	ResponseBody            *ProfileResponseBody `yaml:"response_body"`
	Features                *ProfileFeatures     `yaml:"features"`
	Audit                   *ProfileAudit        `yaml:"audit"`
	Crs                     *crs.Crs             `yaml:"crs"`
}

type ProfileFileUpload struct {
	Path      string `yaml:""`
	Limit     int    `yaml:""`
	FileMode  int    `yaml:""`
	KeepFiles bool   `yaml:""`
}

type ProfileRequestBody struct {
	InMemoryLimit int64 `yaml:""`
	Limit         int64 `yaml:""`
	LimitAction   int   `yaml:""`
}

type ProfileResponseBody struct {
	InMemoryLimit int64    `yaml:""`
	Limit         int64    `yaml:""`
	LimitAction   int      `yaml:""`
	MimeTypes     []string `yaml:""`
}

type ProfileFeatures struct {
	Crs                bool `yaml:"crs"`
	Audit              bool `yaml:""`
	Rules              bool `yaml:""`
	ContentInjection   bool `yaml:""`
	RequestBodyAccess  bool `yaml:""`
	ResponseBodyAccess bool `yaml:""`
	BodyInspection     bool `yaml:""`
}

type ProfileAudit struct {
	Files          []string `yaml:""`
	Directory      string   `yaml:""`
	DirMode        int      `yaml:""`
	FileMode       int      `yaml:""`
	RelevantStatus string   `yaml:""`
	LogParts       []string `yaml:""`
}

func ParseProfile(data []byte) (*Profile, error) {
	profile := Profile{}
	err := yaml.Unmarshal([]byte(data), &profile)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

// 1. Initialize WAF and load prerules
// 2. Load rules from the "rules" file
// 3. Load rules from the CRS feature
// 4. Load after rules
func (profile *Profile) Build() (*engine.Waf, error) {
	waf := engine.NewWaf()
	if profile.Config == nil {
		return nil, errors.New("Invalid WAF profile")
	}
	pp, _ := parser.NewParser(waf)
	err := pp.FromString(profile.Config.PreRules)
	if err != nil {
		return nil, err
	}
	if profile.Rules != "" {
		err := pp.FromFile(profile.Rules)
		if err != nil {
			return nil, err
		}
	}

	if profile.Config.Features.Crs {
		if profile.Config.Crs == nil {
			return nil, errors.New("config.crs is required if CRS feature is enabled.")
		}
		profile.Config.Crs.Init(waf)
		profile.Config.Crs.Build()
	}
	buff := ""
	err = pp.FromString(buff)
	if err != nil {
		return nil, err
	}

	return waf, nil
}
