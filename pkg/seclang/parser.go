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

	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/utils"
	log "github.com/sirupsen/logrus"
)

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

func (p *Parser) Init(waf *engine.Waf) {
	p.Waf = waf
	p.defaultActions = []string{}
}

func (p *Parser) FromFile(profilePath string) error {
	if !utils.FileExists(profilePath) {
		return errors.New("invalid profile path")
	}
	p.configfile = profilePath
	p.configdir = filepath.Dir(profilePath) + "/"
	file, err := utils.OpenFile(profilePath)
	if err != nil {
		p.log("Cannot open profile path " + profilePath)
		return err
	}

	err = p.FromString(string(file))
	if err != nil {
		log.Error("Cannot parse configurations")
		return err
	}
	//TODO validar el error de scanner.Err()
	return nil
}

func (p *Parser) FromString(data string) error {
	scanner := bufio.NewScanner(strings.NewReader(data))
	var linebuffer = ""
	for scanner.Scan() {
		line := scanner.Text()
		linebuffer += strings.TrimSpace(line)
		//Check if line ends with \
		// TODO fix performance issue in the following line:
		match, _ := regexp.MatchString(`\\(\s+)?$`, line)
		if !match {
			err := p.Evaluate(linebuffer)
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

func (p *Parser) Evaluate(data string) error {
	if data == "" || data[0] == '#' {
		return nil
	}
	//first we get the directive
	spl := strings.SplitN(data, " ", 2)
	if len(spl) != 2 {
		return p.log("Invalid syntaxis, expected [directive] [options] for:" + data)
	}
	log.Debug("Parsing directive: " + data)
	directive := spl[0]
	opts := spl[1]

	if len(opts) >= 3 && opts[0] == '"' && opts[len(opts)-1] == '"' {
		opts = strings.Trim(opts, `"`)
	}

	directives := map[string]Directive{
		"SecComponentSignature":         directiveSecComponentSignature,
		"SecMarker":                     directiveSecMarker,
		"SecAction":                     directiveSecAction,
		"SecRule":                       directiveSecRule,
		"SecResponseBodyAccess":         directiveSecResponseBodyAccess,
		"SecRequestBodyLimit":           directiveSecRequestBodyLimit,
		"SecRequestBodyAccess":          directiveSecRequestBodyAccess,
		"SecRuleEngine":                 directiveSecRuleEngine,
		"SecWebAppId":                   directiveSecWebAppId,
		"SecTmpDir":                     directiveSecTmpDir,
		"SecAuditEngine":                directiveSecAuditEngine,
		"SecCollectionTimeout":          directiveSecCollectionTimeout,
		"SecAuditLogRelevantStatus":     directiveSecAuditLogRelevantStatus,
		"SecAuditLogParts":              directiveSecAuditLogParts,
		"SecAuditLog":                   directiveSecAuditLog,
		"SecDefaultAction":              directiveSecDefaultAction,
		"SecGeoLookupDb":                directiveSecGeoLookupDb,
		"SecSensorId":                   directiveSecSensorId,
		"SecRemoteRules":                directiveSecRemoteRules,
		"SecRemoteRulesFailAction":      directiveSecRemoteRulesFailAction,
		"SecRequestBodyInMemoryLimit":   directiveSecRequestBodyInMemoryLimit,
		"SecRequestBodyLimitAction":     directiveSecRequestBodyLimitAction,
		"SecResponseBodyLimit":          directiveSecResponseBodyLimit,
		"SecResponseBodyLimitAction":    directiveSecResponseBodyLimitAction,
		"SecResponseBodyMimeType":       directiveSecResponseBodyMimeType,
		"SecResponseBodyMimeTypesClear": directiveSecResponseBodyMimeTypesClear,
		"SecRuleRemoveById":             directiveSecRuleRemoveById,
		"SecRuleRemoveByMsg":            directiveSecRuleRemoveByMsg,
		"SecRuleRemoveByTag":            directiveSecRuleRemoveByTag,
		"SecServerSignature":            directiveSecServerSignature,

		//Unsupported Directives
		"SecXmlExternalEntity":       directiveUnsupported,
		"SecUploadKeepFiles":         directiveUnsupported,
		"SecUploadFileMode":          directiveUnsupported,
		"SecUploadFileLimit":         directiveUnsupported,
		"SecUploadDir":               directiveUnsupported,
		"SecStreamOutBodyInspection": directiveUnsupported,
		"SecRuleUpdateTargetByTag":   directiveUnsupported,
		"SecRuleUpdateTargetByMsg":   directiveUnsupported,
		"SecRuleUpdateTargetById":    directiveUnsupported,
		"SecRuleUpdateActionById":    directiveUnsupported,
		"SecRuleScript":              directiveUnsupported,
		"SecRulePerfTime":            directiveUnsupported,
		"SecConnWriteStateLimit":     directiveSecConnWriteStateLimit,
		"SecConnReadStateLimit":      directiveSecConnReadStateLimit,
		"SecPcreMatchLimitRecursion": directiveSecPcreMatchLimitRecursion,
		"SecPcreMatchLimit":          directiveSecPcreMatchLimit,
		"SecInterceptOnError":        directiveSecInterceptOnError,
		"SecHttpBlKey":               directiveSecHttpBlKey,
		"SecGsbLookupDb":             directiveSecGsbLookupDb,
		"SecHashMethodPm":            directiveSecHashMethodPm,
		"SecHashMethodRx":            directiveSecHashMethodRx,
		"SecHashParam":               directiveSecHashParam,
		"SecHashKey":                 directiveSecHashKey,
		"SecHashEngine":              directiveSecHashEngine,
		"SecContentInjection":        directiveSecContentInjection,
		"SecConnEngine":              directiveSecConnEngine,
	}
	d := directives[directive]
	if d == nil {
		return p.log("Unsupported directive " + directive)
	}
	return d(p, opts)
}

func (p *Parser) ParseRule(data string, withOperator bool) (*engine.Rule, error) {
	var err error
	rp := NewRuleParser()
	rp.Configdir = p.Waf.Datapath

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

	rule := rp.GetRule()
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

func (p *Parser) AddDefaultActions(data string) error {
	p.defaultActions = append(p.defaultActions, data)
	return nil
}

func (p *Parser) log(msg string) error {
	msg = fmt.Sprintf("[Parser] [Line %d] %s", p.currentLine, msg)
	log.Error(msg)
	return errors.New(msg)
}

func (p *Parser) GetDefaultActions() []string {
	return p.defaultActions
}

func NewParser(waf *engine.Waf) (*Parser, error) {
	if waf == nil {
		return nil, errors.New("must use a valid waf instance")
	}
	p := &Parser{}
	p.Init(waf)
	return p, nil
}
