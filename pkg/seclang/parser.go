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
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/utils"
	regex "github.com/jptosso/coraza-waf/pkg/utils/regex"
	log "github.com/sirupsen/logrus"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Parser struct {
	configfile string
	configdir  string
	nextChain  bool
	RuleEngine string
	waf        *engine.Waf
	lastRule   *engine.Rule

	defaultActions []string
	currentLine    int
}

func (p *Parser) Init(waf *engine.Waf) {
	p.waf = waf
	p.defaultActions = []string{}
}

func (p *Parser) FromFile(profilePath string) error {
	if !utils.FileExists(profilePath) {
		return errors.New("Invalid profile path")
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
	validations := map[string]string{
		"SecAuditEngine":            `^(On|Off|RelevantOnly)$`,
		"SecAuditLog":               `^(\|\/|https:\/\/|\/)?.*$`,
		"SecAuditLogDirMode":        `^([0-7]{3,5}|default)$`,
		"SecAuditLogFileMode":       `^([0-7]{3,5}|default)$`,
		"SecAuditLogParts":          `^[A-KZ]{1,12}$`, // Does not validate repetitions
		"SecAuditLogRelevantStatus": `.*?`,
		"SecAuditLogStorageDir":     `^\/.*?`, // Requires more love
		"SecAuditLogType":           `^(Concurrent|HTTPS)$`,
		"SecCollectionTimeout":      `^[\d]{1,9}$`, // Maybe validate a real int value?
		"SecConnEngine":             `^(On|Off|DetectOnly)$`,
		"SecContentInjection":       `^(On|Off)$`,
		"SecDefaultAction":          `.*?`,
		"SecHashEngine":             `^(On|Off)$`,
	}
	for key, regex := range validations {
		if directive == key {
			re, _ := regexp.Compile(regex)
			if !re.MatchString(opts) {
				return p.log("Invalid arguments for directive " + directive + ", got " + opts)
			}
			break
		}
	}
	switch directive {
	case "SecAuditEngine":
		switch opts {
		case "On":
			p.waf.AuditEngine = engine.AUDIT_LOG_ENABLED
		case "Off":
			p.waf.AuditEngine = engine.AUDIT_LOG_DISABLED
		case "RelevantOnly":
			p.waf.AuditEngine = engine.AUDIT_LOG_RELEVANT
		}
	case "SecAuditLog":
		p.waf.AuditLogPath = opts
		break
	case "SecAuditLogDirMode":
		mode := 0600
		if opts != "default" {
			mode, _ = strconv.Atoi(opts)
		}
		p.waf.AuditLogDirMode = mode
		break
	case "SecAuditLogFileMode":
		mode := 0600
		if opts != "default" {
			mode, _ = strconv.Atoi(opts)
		}
		p.waf.AuditLogFileMode = mode
		break
	case "SecAuditLogParts":
		p.waf.AuditLogParts = []rune{}
		for _, c := range opts {
			p.waf.AuditLogParts = append(p.waf.AuditLogParts, c)
		}
		break
	case "SecAuditLogRelevantStatus":
		p.waf.AuditLogRelevantStatus = regex.MustCompile(opts, 0)
		break
	case "SecAuditLogStorageDir":
		p.waf.AuditLogStorageDir = opts
		//TODO validate access to directory
		break
	case "SecAuditLogType":
		switch opts {
		case "Concurrent":
			p.waf.AuditLogType = engine.AUDIT_LOG_CONCURRENT
			break
		case "HTTPS":
			p.waf.AuditLogType = engine.AUDIT_LOG_HTTPS
			break
		}
		break
	case "SecCollectionTimeout":
		//p.waf.CollectionTimeout, _ = strconv.Atoi(opts)
		break
	case "SecConnEngine":
		/*
			switch opts{
			case "On":
				p.waf.ConnEngine = engine.CONN_ENGINE_ON
				break
			case "Off":
				p.waf.ConnEngine = engine.CONN_ENGINE_OFF
				break
			case "DetectOnly":
				p.waf.ConnEngine = engine.CONN_ENGINE_DETECTONLY
				break
			}
			break
		*/
	case "SecContentInjection":
		//p.waf.ContentInjection = (opts == "On")
		break
	case "SecDefaultAction":
		p.AddDefaultActions(opts)
		break
	case "SecHashEngine":
		// p.waf.HashEngine = (opts == "On")
		break
	case "SecHashKey":
		//p.waf.HashKey = opts
		break
	case "SecHashParam":

		break
	case "SecHashMethodRx":

		break
	case "SecHashMethodPm":

		break
	case "SecGeoLookupDb":
		p.waf.InitGeoip(opts)
		break
	case "SecGsbLookupDb":

		break
	case "SecHttpBlKey":
		//p.waf.HttpBlKey = opts
		break
	case "SecInterceptOnError":
		//p.waf.InterceptOnError = (opts == "On")
		break
	case "SecPcreMatchLimit":
		// p.waf.PcreMatchLimit, _ = strconv.Atoi(opts)
		break
	case "SecPcreMatchLimitRecursion":
		//TODO PCRE RECURSIONLIMIT is hardcoded inside the binary :( we have to figure out something
		p.log("SecPcreMatchLimitRecursion is not supported yet.")
		break
	case "SecConnReadStateLimit":
		// p.waf.ConnReadStateLimit, _ = strconv.Atoi(opts)
		p.log("SecConnReadStateLimit is not supported yet.")
		break
	case "SecSensorId":
		p.waf.SensorId = opts
		break
	case "SecConnWriteStateLimit":
		// p.waf.ConnWriteStateLimit, _ = strconv.Atoi(opts)
		p.log("SecConnWriteStateLimit is not supported yet.")
		break
	case "SecRemoteRules":
		data, err := utils.OpenFile(opts)
		if err != nil || p.FromString(string(data)) != nil {
			if p.waf.AbortOnRemoteRulesFail {
				return p.log("Failed to parse remote rules")
			} else {
				return err
			}
		}
		break
	case "SecRemoteRulesFailAction":
		p.waf.AbortOnRemoteRulesFail = (opts == "Abort")
		break
	case "SecRequestBodyInMemoryLimit":
		p.waf.RequestBodyInMemoryLimit, _ = strconv.ParseInt(opts, 10, 64)
		break
	case "SecRequestBodyLimitAction":
		p.waf.RejectOnRequestBodyLimit = (opts == "Reject")
		break
	case "SecResponseBodyLimit":
		p.waf.ResponseBodyLimit, _ = strconv.ParseInt(opts, 10, 64)
		break
	case "SecResponseBodyLimitAction":
		p.waf.RejectOnResponseBodyLimit = (opts == "Reject")
		break
	case "SecResponseBodyMimeType":
		p.waf.ResponseBodyMimeTypes = strings.Split(opts, " ")
		break
	case "SecResponseBodyMimeTypesClear":
		p.waf.ResponseBodyMimeTypes = []string{}
		break
	case "SecRulePerfTime":
		p.log("SecRulePerfTime is not supported yet.")
		break
	case "SecRuleRemoveById":
		id, _ := strconv.Atoi(opts)
		p.waf.Rules.DeleteById(id)
		break
	case "SecRuleRemoveByMsg":
		for _, r := range p.waf.Rules.FindByMsg(opts) {
			p.waf.Rules.DeleteById(r.Id)
		}
		break
	case "SecRuleRemoveByTag":
		for _, r := range p.waf.Rules.FindByTag(opts) {
			p.waf.Rules.DeleteById(r.Id)
		}
		break
	case "SecRuleScript":
		p.log("SecRuleScript is not supported yet.")
		break
	case "SecRuleUpdateActionById":
		//r := p.waf.FindRuleById(0)
		p.log("SecRuleUpdateActionById is not supported yet.")
		break
	case "SecRuleUpdateTargetById":
		/*spl := strings.SplitN(opts, " ", 2)
		id, _ := strconv.Atoi(spl[0])
		p.waf.Rules.FindById(id)
		*/
		p.log("SecRuleUpdateTargetById is not supported yet.")
		break
	case "SecRuleUpdateTargetByMsg":
		/*
			spl := strings.SplitN(opts, " ", 2)
			for _, r := range p.waf.FindRulesByMsg(spl[0]){

			}
		*/
		p.log("SecRuleUpdateTargetByMsg is not supported yet.")
		break
	case "SecRuleUpdateTargetByTag":
		/*
			spl := strings.SplitN(opts, " ", 2)
			for r := range p.waf.FindRulesByTag(spl[0]){

			}*/
		break
	case "SecServerSignature":
		p.waf.ServerSignature = opts
		break
	case "SecStreamOutBodyInspection":
		//p.waf.StreamOutBodyInspection = (opts == "Abort")
		break
	case "SecTmpDir":
		p.waf.TmpDir = opts
		break
	case "SecUploadDir":
		//p.waf.UploadDir = opts
		break
	case "SecUploadFileLimit":
		//p.waf.UploadFileLimit, _ = strconv.Atoi(opts)
		break
	case "SecUploadFileMode":
		//p.waf.UploadFileMode, _ = strconv.Atoi(opts)
		break
	case "SecUploadKeepFiles":
		break
	case "SecWebAppId":
		p.waf.WebAppId = opts
		break
	case "SecXmlExternalEntity":
		break
	case "SecRuleEngine":
		p.waf.RuleEngine = (opts == "On")
	case "SecRequestBodyAccess":
		p.waf.RequestBodyAccess = (opts == "On")
	case "SecRequestBodyLimit":
		limit, _ := strconv.ParseInt(opts, 10, 64)
		p.waf.RequestBodyLimit = limit
	case "SecResponseBodyAccess":
		p.waf.ResponseBodyAccess = (opts == "On")
	case "SecRule":
		rule, err := p.ParseRule(opts, true)
		if err != nil {
			p.log(fmt.Sprintf("Failed to compile rule (%s): %s", err, opts))
			return err
		} else {
			p.waf.Rules.Add(rule)
		}
	case "SecAction":
		rule, err := p.ParseRule(opts, false)
		if err != nil {
			p.log(fmt.Sprintf("Failed to compile rule (%s): %s", err, opts))
			return err
		}
		p.waf.Rules.Add(rule)
		log.Debug("Added special secaction rule")
	case "SecMarker":
		rule, err := p.ParseRule(`"id:1, pass, nolog"`, false)
		if err != nil {
			p.log("Error creating secmarker rule")
			return err
		}
		rule.SecMark = opts
		rule.Id = 0
		rule.Phase = 0
		p.waf.Rules.Add(rule)
		log.Debug("Added special secmarker rule")
	case "SecComponentSignature":
		p.waf.ComponentSignature = opts
	default:
		return p.log("Unsupported directive: " + directive)
	}
	return nil
}

func (p *Parser) ParseRule(data string, withOperator bool) (*engine.Rule, error) {
	var err error
	rp := NewRuleParser()
	rp.Configdir = p.waf.Datapath

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
		return nil, errors.New("Must use a valid waf instance")
	}
	p := &Parser{}
	p.Init(waf)
	return p, nil
}
