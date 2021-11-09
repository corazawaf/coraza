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
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"

	engine "github.com/jptosso/coraza-waf/v2"
	utils "github.com/jptosso/coraza-waf/v2/utils"
	"github.com/jptosso/coraza-waf/v2/utils/geoip"
	"go.uber.org/zap"
)

type Directive = func(p *Parser, opts string) error

func directiveSecComponentSignature(p *Parser, opts string) error {
	p.Waf.ComponentNames = append(p.Waf.ComponentNames, opts)
	return nil
}

func directiveSecMarker(p *Parser, opts string) error {
	rule, _ := p.ParseRule(`"id:1, pass, nolog"`, false)
	rule.SecMark = opts
	rule.Id = 0
	rule.Phase = 0
	if err := p.Waf.Rules.Add(rule); err != nil {
		if perr := p.log(fmt.Sprintf("Failed to compile rule (%s): %s", err, opts)); perr != nil {
			return perr // can't write to log, return this instead
		}
		return err
	}
	p.Waf.Logger.Debug("added secmark rule")
	return nil
}

func directiveSecAction(p *Parser, opts string) error {
	rule, err := p.ParseRule(opts, false)
	if err != nil {
		if perr := p.log(fmt.Sprintf("Failed to compile rule (%s): %s", err, opts)); perr != nil {
			return perr // can't write to log, return this instead
		}
		return err
	}
	if err := p.Waf.Rules.Add(rule); err != nil {
		if perr := p.log(fmt.Sprintf("Failed to compile rule (%s): %s", err, opts)); perr != nil {
			return perr // can't write to log, return this instead
		}
		return err
	}
	p.Waf.Logger.Debug("Added SecAction",
		zap.String("rule", opts),
	)
	return nil
}

func directiveSecRule(p *Parser, opts string) error {
	rule, err := p.ParseRule(opts, true)
	if err != nil {
		if perr := p.log(fmt.Sprintf("Failed to compile rule (%s): %s", err, opts)); perr != nil {
			return perr // can't write to log, return this instead
		}
		return err
	}
	return p.Waf.Rules.Add(rule)
}

func directiveSecResponseBodyAccess(p *Parser, opts string) error {
	p.Waf.ResponseBodyAccess = (opts == "On")
	return nil
}

func directiveSecRequestBodyLimit(p *Parser, opts string) error {
	limit, _ := strconv.ParseInt(opts, 10, 64)
	p.Waf.RequestBodyLimit = limit
	return nil
}

func directiveSecRequestBodyAccess(p *Parser, opts string) error {
	p.Waf.RequestBodyAccess = (opts == "On")
	return nil
}

func directiveSecRuleEngine(p *Parser, opts string) error {
	switch strings.ToLower(opts) {
	case "on":
		p.Waf.RuleEngine = engine.RULE_ENGINE_ON
	case "off":
		p.Waf.RuleEngine = engine.RULE_ENGINE_OFF
	case "detectiononly":
		p.Waf.RuleEngine = engine.RULE_ENGINE_DETECTONLY
	default:
		return errors.New("invalid SecRuleEngine argument")
	}
	return nil
}

func directiveUnsupported(p *Parser, opts string) error {
	return nil
}

func directiveSecWebAppId(p *Parser, opts string) error {
	p.Waf.WebAppId = opts
	return nil
}

func directiveSecTmpDir(p *Parser, opts string) error {
	p.Waf.TmpDir = opts
	return nil
}

func directiveSecServerSignature(p *Parser, opts string) error {
	p.Waf.ServerSignature = opts
	return nil
}

func directiveSecRuleRemoveByTag(p *Parser, opts string) error {
	for _, r := range p.Waf.Rules.FindByTag(opts) {
		p.Waf.Rules.DeleteById(r.Id)
	}
	return nil
}

func directiveSecRuleRemoveByMsg(p *Parser, opts string) error {
	for _, r := range p.Waf.Rules.FindByMsg(opts) {
		p.Waf.Rules.DeleteById(r.Id)
	}
	return nil
}

func directiveSecRuleRemoveById(p *Parser, opts string) error {
	id, _ := strconv.Atoi(opts)
	p.Waf.Rules.DeleteById(id)
	return nil
}

func directiveSecResponseBodyMimeTypesClear(p *Parser, opts string) error {
	p.Waf.ResponseBodyMimeTypes = []string{}
	return nil
}

func directiveSecResponseBodyMimeType(p *Parser, opts string) error {
	p.Waf.ResponseBodyMimeTypes = strings.Split(opts, " ")
	return nil
}

func directiveSecResponseBodyLimitAction(p *Parser, opts string) error {
	p.Waf.RejectOnResponseBodyLimit = (opts == "Reject")
	return nil
}

func directiveSecResponseBodyLimit(p *Parser, opts string) error {
	var err error
	p.Waf.ResponseBodyLimit, err = strconv.ParseInt(opts, 10, 64)
	return err
}

func directiveSecRequestBodyLimitAction(p *Parser, opts string) error {
	p.Waf.RejectOnRequestBodyLimit = (opts == "Reject")
	return nil
}

func directiveSecRequestBodyInMemoryLimit(p *Parser, opts string) error {
	p.Waf.RequestBodyInMemoryLimit, _ = strconv.ParseInt(opts, 10, 64)
	return nil
}

func directiveSecRemoteRulesFailAction(p *Parser, opts string) error {
	p.Waf.AbortOnRemoteRulesFail = (opts == "Abort")
	return nil
}

func directiveSecRemoteRules(p *Parser, opts string) error {
	spl := strings.SplitN(opts, " ", 2)
	url := opts
	key := ""
	if len(spl) == 2 {
		key = spl[0]
		url = spl[1]
	}
	data, err := utils.OpenFile(url, true, key)
	if err != nil || p.FromString(string(data)) != nil {
		if p.Waf.AbortOnRemoteRulesFail {
			return p.log("Failed to parse remote rules")
		} else {
			return nil
		}
	}
	return nil
}

func directiveSecConnWriteStateLimit(p *Parser, opts string) error {
	return nil
}

func directiveSecSensorId(p *Parser, opts string) error {
	p.Waf.SensorId = opts
	return nil
}

func directiveSecConnReadStateLimit(p *Parser, opts string) error {
	return nil
}

func directiveSecPcreMatchLimitRecursion(p *Parser, opts string) error {
	return nil
}

func directiveSecPcreMatchLimit(p *Parser, opts string) error {
	return nil
}

func directiveSecHttpBlKey(p *Parser, opts string) error {
	return nil
}

func directiveSecGsbLookupDb(p *Parser, opts string) error {
	return nil
}

func directiveSecGeoLookupDb(p *Parser, opts string) error {
	spl := strings.SplitN(opts, " ", 2)
	module := spl[0]
	args := utils.ArgsToMap(spl[1])
	var err error
	switch module {
	case "maxminddb":
		db := &geoip.Maxminddb{}
		err = db.Init(args)
		if err != nil {
			return err
		}
		p.Waf.GeoDb = db
	case "ip2location":
		db := &geoip.Ip2Location{}
		err = db.Init(args)
		if err != nil {
			return err
		}
		p.Waf.GeoDb = db
	default:
		return fmt.Errorf("invalid geoip engine %s", module)
	}
	return nil
}

func directiveSecHashMethodPm(p *Parser, opts string) error {
	return nil
}

func directiveSecHashMethodRx(p *Parser, opts string) error {
	return nil
}

func directiveSecHashParam(p *Parser, opts string) error {
	return nil
}

func directiveSecHashKey(p *Parser, opts string) error {
	return nil
}

func directiveSecHashEngine(p *Parser, opts string) error {
	return nil
}

func directiveSecDefaultAction(p *Parser, opts string) error {
	return p.AddDefaultActions(opts)
}

func directiveSecContentInjection(p *Parser, opts string) error {
	p.Waf.ContentInjection = parseBoolean(opts)
	return nil
}

func directiveSecConnEngine(p *Parser, opts string) error {
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
	return nil
}

func directiveSecCollectionTimeout(p *Parser, opts string) error {
	//p.waf.CollectionTimeout, _ = strconv.Atoi(opts)
	return nil
}

func directiveSecAuditLog(p *Parser, opts string) error {
	if len(opts) == 0 {
		return errors.New("syntax error: SecAuditLog [concurrent/https/...] [parameters]")
	}
	spl := strings.SplitN(opts, " ", 2)
	args := utils.ArgsToMap(spl[1])
	return p.Waf.AddAuditLogger(spl[0], args)
}

func directiveSecAuditLogRelevantStatus(p *Parser, opts string) error {
	var err error
	p.Waf.AuditLogRelevantStatus, err = regexp.Compile(opts)
	return err
}

func directiveSecAuditLogParts(p *Parser, opts string) error {
	p.Waf.AuditLogParts = []rune(opts)
	return nil
}

func directiveSecAuditEngine(p *Parser, opts string) error {
	switch opts {
	case "On":
		p.Waf.AuditEngine = engine.AUDIT_LOG_ENABLED
	case "Off":
		p.Waf.AuditEngine = engine.AUDIT_LOG_DISABLED
	case "RelevantOnly":
		p.Waf.AuditEngine = engine.AUDIT_LOG_RELEVANT
	}
	return nil
}

func directiveSecDataDir(p *Parser, opts string) error {
	//TODO validations
	p.Waf.DataDir = opts
	return nil
}

func directiveSecUploadKeepFiles(p *Parser, opts string) error {
	p.Waf.UploadKeepFiles = parseBoolean(opts)
	return nil
}

func directiveSecUploadFileMode(p *Parser, opts string) error {
	fm, err := strconv.ParseInt(opts, 8, 32)
	p.Waf.UploadFileMode = fs.FileMode(fm)
	return err
}

func directiveSecUploadFileLimit(p *Parser, opts string) error {
	var err error
	p.Waf.UploadFileLimit, err = strconv.Atoi(opts)
	return err
}

func directiveSecUploadDir(p *Parser, opts string) error {
	// TODO validations
	p.Waf.UploadDir = opts
	return nil
}

func directiveSecRequestBodyNoFilesLimit(p *Parser, opts string) error {
	var err error
	p.Waf.RequestBodyNoFilesLimit, err = strconv.ParseInt(opts, 10, 64)
	return err
}

func directiveSecUnicodeMap(p *Parser, opts string) error {
	unicode, err := utils.NewUnicode(opts)
	p.Waf.Unicode = unicode
	return err
}

func directiveSecDebugLog(p *Parser, opts string) error {
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{
		opts,
	}
	cfg.Level = p.Waf.LoggerAtomicLevel
	logger, err := cfg.Build()
	if err != nil {
		return err
	}
	p.Waf.Logger = logger
	return nil
}

func directiveSecDebugLogLevel(p *Parser, opts string) error {
	lvl, err := strconv.Atoi(opts)
	if err != nil {
		return err
	}
	return p.Waf.SetLogLevel(lvl)
}

func parseBoolean(data string) bool {
	data = strings.ToLower(data)
	return data == "on"
}
