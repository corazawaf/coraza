// Copyright 2021 Juan Pablo Tosso
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

package seclang

import (
	"bufio"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	engine "github.com/jptosso/coraza-waf/v2"
	utils "github.com/jptosso/coraza-waf/v2/utils"
	"go.uber.org/zap"
)

// Parser provides functions to evaluate (compile) SecLang directives
type Parser struct {
	configfile            string
	configdir             string
	nextChain             bool
	Waf                   *engine.Waf
	DisabledDirectives    []string
	DisabledRuleActions   []string
	DisabledRuleOperators []string
	lastRule              *engine.Rule

	defaultActions []string
	currentLine    int
}

// FromFile imports directives from a file
// It will return error if any directive fails to parse
// or arguments are invalid
func (p *Parser) FromFile(profilePath string) error {
	p.configfile = profilePath
	p.configdir = filepath.Dir(profilePath)
	file, err := utils.OpenFile(profilePath, "")
	if err != nil {
		p.Waf.Logger.Error(err.Error(),
			zap.String("path", profilePath),
		)
		return err
	}

	err = p.FromString(string(file))
	if err != nil {
		p.Waf.Logger.Error(err.Error(),
			zap.String("path", profilePath),
		)
		return err
	}
	//TODO validar el error de scanner.Err()
	return nil
}

// FromString imports directives from a string
// It will return error if any directive fails to parse
// or arguments are invalid
func (p *Parser) FromString(data string) error {
	scanner := bufio.NewScanner(strings.NewReader(data))
	var linebuffer = ""
	pattern := regexp.MustCompile(`\\(\s+)?$`)
	for scanner.Scan() {
		p.currentLine++
		line := scanner.Text()
		linebuffer += strings.TrimSpace(line)
		//Check if line ends with \
		match := pattern.MatchString(line)
		if !match {
			err := p.evaluate(linebuffer)
			if err != nil {
				return err
			}
			linebuffer = ""
		} else {
			linebuffer = strings.TrimSuffix(linebuffer, "\\")
		}
	}
	return nil
}

func (p *Parser) evaluate(data string) error {
	if data == "" || data[0] == '#' {
		return nil
	}
	//first we get the directive
	spl := strings.SplitN(data, " ", 2)
	opts := ""
	if len(spl) == 2 {
		opts = spl[1]
	}
	p.Waf.Logger.Debug("parsing directive",
		zap.String("directive", data),
	)
	directive := spl[0]

	if len(opts) >= 3 && opts[0] == '"' && opts[len(opts)-1] == '"' {
		opts = strings.Trim(opts, `"`)
	}

	if utils.StringInSlice(directive, p.DisabledDirectives) {
		return fmt.Errorf("%s directive is disabled", directive)
	}

	directives := map[string]Directive{
		"secwebappid":                   directiveSecWebAppId,
		"secuploadkeepfiles":            directiveSecUploadKeepFiles,
		"secuploadfilemode":             directiveSecUploadFileMode,
		"secuploadfilelimit":            directiveSecUploadFileLimit,
		"secuploaddir":                  directiveSecUploadDir,
		"sectmpdir":                     directiveSecTmpDir,
		"secserversignature":            directiveSecServerSignature,
		"secsensorid":                   directiveSecSensorId,
		"secruleremovebytag":            directiveSecRuleRemoveByTag,
		"secruleremovebymsg":            directiveSecRuleRemoveByMsg,
		"secruleremovebyid":             directiveSecRuleRemoveById,
		"secruleengine":                 directiveSecRuleEngine,
		"secrule":                       directiveSecRule,
		"secresponsebodymimetypesclear": directiveSecResponseBodyMimeTypesClear,
		"secresponsebodymimetype":       directiveSecResponseBodyMimeType,
		"secresponsebodylimitaction":    directiveSecResponseBodyLimitAction,
		"secresponsebodylimit":          directiveSecResponseBodyLimit,
		"secresponsebodyaccess":         directiveSecResponseBodyAccess,
		"secrequestbodynofileslimit":    directiveSecRequestBodyNoFilesLimit,
		"secrequestbodylimitaction":     directiveSecRequestBodyLimitAction,
		"secrequestbodylimit":           directiveSecRequestBodyLimit,
		"secrequestbodyinmemorylimit":   directiveSecRequestBodyInMemoryLimit,
		"secrequestbodyaccess":          directiveSecRequestBodyAccess,
		"secremoterulesfailaction":      directiveSecRemoteRulesFailAction,
		"secremoterules":                directiveSecRemoteRules,
		"secpcrematchlimitrecursion":    directiveSecPcreMatchLimitRecursion,
		"secpcrematchlimit":             directiveSecPcreMatchLimit,
		"secmarker":                     directiveSecMarker,
		"sechttpblkey":                  directiveSecHttpBlKey,
		"sechashparam":                  directiveSecHashParam,
		"sechashmethodrx":               directiveSecHashMethodRx,
		"sechashmethodpm":               directiveSecHashMethodPm,
		"sechashkey":                    directiveSecHashKey,
		"sechashengine":                 directiveSecHashEngine,
		"secgsblookupdb":                directiveSecGsbLookupDb,
		"secdefaultaction":              directiveSecDefaultAction,
		"secdatadir":                    directiveSecDataDir,
		"seccontentinjection":           directiveSecContentInjection,
		"secconnwritestatelimit":        directiveSecConnWriteStateLimit,
		"secconnreadstatelimit":         directiveSecConnReadStateLimit,
		"secconnengine":                 directiveSecConnEngine,
		"seccomponentsignature":         directiveSecComponentSignature,
		"seccollectiontimeout":          directiveSecCollectionTimeout,
		"secauditlogrelevantstatus":     directiveSecAuditLogRelevantStatus,
		"secauditlogparts":              directiveSecAuditLogParts,
		"secauditlog":                   directiveSecAuditLog,
		"secauditengine":                directiveSecAuditEngine,
		"secaction":                     directiveSecAction,
		"secdebuglog":                   directiveSecDebugLog,
		"secdebugloglevel":              directiveSecDebugLogLevel,

		//Unsupported Directives
		"secargumentseparator":     directiveUnsupported,
		"seccookieformat":          directiveUnsupported,
		"secruleupdatetargetbytag": directiveUnsupported,
		"secruleupdatetargetbymsg": directiveUnsupported,
		"secruleupdatetargetbyid":  directiveUnsupported,
		"secruleupdateactionbyid":  directiveUnsupported,
		"secrulescript":            directiveUnsupported,
		"secruleperftime":          directiveUnsupported,
	}
	d := directives[strings.ToLower(directive)]
	if d == nil {
		return p.log("Unsupported directive " + directive)
	}
	return d(p, opts)
}

// ParseRule will take a rule string and create a rule struct
// Rules without operator will become SecActions
func (p *Parser) ParseRule(data string, withOperator bool) (*engine.Rule, error) {
	var err error
	rp := NewRuleParser(p)
	rp.Configdir = p.configdir

	for _, da := range p.defaultActions {
		err = rp.ParseDefaultActions(da)
		if err != nil {
			return nil, err
		}
	}
	actions := ""
	if withOperator {
		spl := strings.SplitN(data, " ", 2)
		vars := spl[0]

		//regex: "(?:[^"\\]|\\.)*"
		r := regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
		matches := r.FindAllString(data, -1)
		operator := utils.RemoveQuotes(matches[0])
		if utils.StringInSlice(operator, p.DisabledRuleOperators) {
			return nil, fmt.Errorf("%s rule operator is disabled", operator)
		}
		err = rp.ParseVariables(vars)
		if err != nil {
			return nil, err
		}
		err = rp.ParseOperator(operator)
		if err != nil {
			return nil, err
		}
		if len(matches) > 1 {
			actions = utils.RemoveQuotes(matches[1])
			err = rp.ParseActions(actions)
			if err != nil {
				return nil, err
			}
		}
	} else {
		//quoted actions separated by comma (,)
		actions = utils.RemoveQuotes(data)
		err = rp.ParseActions(actions)
		if err != nil {
			return nil, err
		}
	}

	rule := rp.Rule()
	rule.Raw = "SecRule " + data

	if p.nextChain {
		p.nextChain = false
		parent := p.lastRule
		rule.ParentId = parent.Id
		lastchain := parent
		for lastchain.Chain != nil {
			lastchain = lastchain.Chain
		}

		*lastchain = *rule
		if rule.Chain != nil {
			p.nextChain = true
		}
		return nil, nil
	}
	if rule.Chain != nil {
		p.nextChain = true
	}
	p.lastRule = rule
	return rule, nil
}

// AddDEfaultActions compiles an actions string
// Requires a phase and a disruptive action, example:
// AddDefaultActions("deny,phase:1,log")
func (p *Parser) AddDefaultActions(data string) error {
	p.defaultActions = append(p.defaultActions, data)
	return nil
}

func (p *Parser) log(msg string) error {
	msg = fmt.Sprintf("[Parser] [Line %d] %s", p.currentLine, msg)
	p.Waf.Logger.Error(msg,
		zap.Int("line", p.currentLine),
	)
	return errors.New(msg)
}

// GetDefaultActions returns the default actions as an
// array of strings, they are not evaluated yet
func (p *Parser) GetDefaultActions() []string {
	return p.defaultActions
}

// NewParser creates a new parser from a WAF instance
// Rules and settings will be associated with the supplied waf
func NewParser(waf *engine.Waf) (*Parser, error) {
	if waf == nil {
		return nil, errors.New("must use a valid waf instance")
	}
	p := &Parser{
		Waf:                waf,
		defaultActions:     []string{},
		DisabledDirectives: []string{},
	}
	return p, nil
}
