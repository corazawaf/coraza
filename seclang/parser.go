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

	engine "github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/utils"
	"go.uber.org/zap"
)

// Parser provides functions to evaluate (compile) SecLang directives
type Parser struct {
	configfile string
	configdir  string
	nextChain  bool
	RuleEngine string
	Waf        *engine.Waf
	lastRule   *engine.Rule

	defaultActions []string
	currentLine    int
}

// FromFile imports directives from a file
// It will return error if any directive fails to parse
// or arguments are invalid
func (p *Parser) FromFile(profilePath string) error {
	if !utils.FileExists(profilePath) {
		p.Waf.Logger.Error("cannot read configurations file",
			zap.String("path", profilePath),
		)
		return errors.New("invalid profile path")
	}
	p.configfile = profilePath
	p.configdir = filepath.Dir(profilePath)
	file, err := utils.OpenFile(profilePath)
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

	directives := map[string]Directive{
		"SecWebAppId":                   directiveSecWebAppId,
		"SecUploadKeepFiles":            directiveSecUploadKeepFiles,
		"SecUploadFileMode":             directiveSecUploadFileMode,
		"SecUploadFileLimit":            directiveSecUploadFileLimit,
		"SecUploadDir":                  directiveSecUploadDir,
		"SecTmpDir":                     directiveSecTmpDir,
		"SecServerSignature":            directiveSecServerSignature,
		"SecSensorId":                   directiveSecSensorId,
		"SecRuleRemoveByTag":            directiveSecRuleRemoveByTag,
		"SecRuleRemoveByMsg":            directiveSecRuleRemoveByMsg,
		"SecRuleRemoveById":             directiveSecRuleRemoveById,
		"SecRuleEngine":                 directiveSecRuleEngine,
		"SecRule":                       directiveSecRule,
		"SecResponseBodyMimeTypesClear": directiveSecResponseBodyMimeTypesClear,
		"SecResponseBodyMimeType":       directiveSecResponseBodyMimeType,
		"SecResponseBodyLimitAction":    directiveSecResponseBodyLimitAction,
		"SecResponseBodyLimit":          directiveSecResponseBodyLimit,
		"SecResponseBodyAccess":         directiveSecResponseBodyAccess,
		"SecRequestBodyNoFilesLimit":    directiveSecRequestBodyNoFilesLimit,
		"SecRequestBodyLimitAction":     directiveSecRequestBodyLimitAction,
		"SecRequestBodyLimit":           directiveSecRequestBodyLimit,
		"SecRequestBodyInMemoryLimit":   directiveSecRequestBodyInMemoryLimit,
		"SecRequestBodyAccess":          directiveSecRequestBodyAccess,
		"SecRemoteRulesFailAction":      directiveSecRemoteRulesFailAction,
		"SecRemoteRules":                directiveSecRemoteRules,
		"SecPcreMatchLimitRecursion":    directiveSecPcreMatchLimitRecursion,
		"SecPcreMatchLimit":             directiveSecPcreMatchLimit,
		"SecMarker":                     directiveSecMarker,
		"SecInterceptOnError":           directiveSecInterceptOnError,
		"SecHttpBlKey":                  directiveSecHttpBlKey,
		"SecHashParam":                  directiveSecHashParam,
		"SecHashMethodRx":               directiveSecHashMethodRx,
		"SecHashMethodPm":               directiveSecHashMethodPm,
		"SecHashKey":                    directiveSecHashKey,
		"SecHashEngine":                 directiveSecHashEngine,
		"SecGsbLookupDb":                directiveSecGsbLookupDb,
		"SecGeoLookupDb":                directiveSecGeoLookupDb,
		"SecDefaultAction":              directiveSecDefaultAction,
		"SecDataDir":                    directiveSecDataDir,
		"SecContentInjection":           directiveSecContentInjection,
		"SecConnWriteStateLimit":        directiveSecConnWriteStateLimit,
		"SecConnReadStateLimit":         directiveSecConnReadStateLimit,
		"SecConnEngine":                 directiveSecConnEngine,
		"SecComponentSignature":         directiveSecComponentSignature,
		"SecCollectionTimeout":          directiveSecCollectionTimeout,
		"SecAuditLogRelevantStatus":     directiveSecAuditLogRelevantStatus,
		"SecAuditLogParts":              directiveSecAuditLogParts,
		"SecAuditLog":                   directiveSecAuditLog,
		"SecAuditEngine":                directiveSecAuditEngine,
		"SecAction":                     directiveSecAction,
		"SecUnicodeMap":                 directiveSecUnicodeMap,
		"SecDebugLog":                   directiveSecDebugLog,
		"SecDebugLogLevel":              directiveSecDebugLogLevel,

		//Unsupported Directives
		"SecAuditLogType":            directiveUnsupported,
		"SecArgumentSeparator":       directiveUnsupported,
		"SecCookieFormat":            directiveUnsupported,
		"SecStatusEngine":            directiveUnsupported,
		"SecXmlExternalEntity":       directiveUnsupported,
		"SecStreamOutBodyInspection": directiveUnsupported,
		"SecRuleUpdateTargetByTag":   directiveUnsupported,
		"SecRuleUpdateTargetByMsg":   directiveUnsupported,
		"SecRuleUpdateTargetById":    directiveUnsupported,
		"SecRuleUpdateActionById":    directiveUnsupported,
		"SecRuleScript":              directiveUnsupported,
		"SecRulePerfTime":            directiveUnsupported,
	}
	d := directives[directive]
	if d == nil {
		return p.log("Unsupported directive " + directive)
	}
	return d(p, opts)
}

// ParseRule will take a rule string and create a rule struct
// Rules without operator will become SecActions
func (p *Parser) ParseRule(data string, withOperator bool) (*engine.Rule, error) {
	var err error
	rp := NewRuleParser()
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
		vars := utils.RemoveQuotes(spl[0])

		//regex: "(?:[^"\\]|\\.)*"
		r := regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
		matches := r.FindAllString(data, -1)
		operator := utils.RemoveQuotes(matches[0])
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

		lastchain.Chain = rule
		if rule.HasChain {
			p.nextChain = true
		}
		return nil, nil
	}
	if rule.HasChain {
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
		Waf:            waf,
		defaultActions: []string{},
	}
	return p, nil
}
