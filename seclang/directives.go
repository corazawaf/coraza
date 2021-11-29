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

	"github.com/jptosso/coraza-waf/v2/types"
	"go.uber.org/zap"
)

type Directive = func(p *Parser, opts string) error

func directiveSecComponentSignature(p *Parser, opts string) error {
	p.Waf.ComponentNames = append(p.Waf.ComponentNames, opts)
	return nil
}

func directiveSecMarker(p *Parser, opts string) error {
	rule, _ := p.parseRule(`"id:1, pass, nolog"`, false)
	rule.SecMark = opts
	rule.ID = 0
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
	rule, err := p.parseRule(opts, false)
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
	rule, err := p.parseRule(opts, true)
	if err != nil {
		if perr := p.log(fmt.Sprintf("Failed to compile rule (%s): %s", err, opts)); perr != nil {
			return perr // can't write to log, return this instead
		}
		return err
	}
	return p.Waf.Rules.Add(rule)
}

func directiveSecResponseBodyAccess(p *Parser, opts string) error {
	p.Waf.ResponseBodyAccess = (strings.ToLower(opts) == "on")
	return nil
}

func directiveSecRequestBodyLimit(p *Parser, opts string) error {
	limit, _ := strconv.ParseInt(opts, 10, 64)
	p.Waf.RequestBodyLimit = limit
	return nil
}

func directiveSecRequestBodyAccess(p *Parser, opts string) error {
	p.Waf.RequestBodyAccess = (strings.ToLower(opts) == "on")
	return nil
}

func directiveSecRuleEngine(p *Parser, opts string) error {
	engine, err := types.ParseRuleEngineStatus(opts)
	p.Waf.RuleEngine = engine
	return err
}

func directiveUnsupported(p *Parser, opts string) error {
	return nil
}

func directiveSecWebAppId(p *Parser, opts string) error {
	p.Waf.WebAppID = opts
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
		p.Waf.Rules.DeleteById(r.ID)
	}
	return nil
}

func directiveSecRuleRemoveByMsg(p *Parser, opts string) error {
	for _, r := range p.Waf.Rules.FindByMsg(opts) {
		p.Waf.Rules.DeleteById(r.ID)
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
	p.Waf.RejectOnResponseBodyLimit = (strings.ToLower(opts) == "reject")
	return nil
}

func directiveSecResponseBodyLimit(p *Parser, opts string) error {
	var err error
	p.Waf.ResponseBodyLimit, err = strconv.ParseInt(opts, 10, 64)
	return err
}

func directiveSecRequestBodyLimitAction(p *Parser, opts string) error {
	p.Waf.RejectOnRequestBodyLimit = (strings.ToLower(opts) == "reject")
	return nil
}

func directiveSecRequestBodyInMemoryLimit(p *Parser, opts string) error {
	p.Waf.RequestBodyInMemoryLimit, _ = strconv.ParseInt(opts, 10, 64)
	return nil
}

func directiveSecRemoteRulesFailAction(p *Parser, opts string) error {
	p.Waf.AbortOnRemoteRulesFail = (strings.ToLower(opts) == "abort")
	return nil
}

func directiveSecRemoteRules(p *Parser, opts string) error {
	return fmt.Errorf("not implemented")
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
	return p.addDefaultActions(opts)
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
	// p.waf.CollectionTimeout, _ = strconv.Atoi(opts)
	return nil
}

func directiveSecAuditLog(p *Parser, opts string) error {
	if len(opts) == 0 {
		return errors.New("syntax error: SecAuditLog [concurrent/https/serial/...]")
	}
	return p.Waf.SetAuditLogger(strings.ToLower(opts))
}

func directiveSecAuditLogFormat(p *Parser, opts string) error {
	if len(opts) == 0 {
		return errors.New("syntax error: SecAuditLogFormat [json/json2/native/...]")
	}
	return p.Waf.SetAuditLoggerFormat(strings.ToLower(opts))
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
	au, err := types.ParseAuditEngineStatus(opts)
	p.Waf.AuditEngine = au
	return err
}

func directiveSecDataDir(p *Parser, opts string) error {
	// TODO validations
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

func directiveSecDebugLog(p *Parser, opts string) error {
	return p.Waf.SetDebugLogPath(opts)
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

var (
	_ Directive = directiveSecAction
	_ Directive = directiveSecAuditEngine
	_ Directive = directiveSecAuditLog
	_ Directive = directiveSecAuditLogFormat
	_ Directive = directiveSecAuditLogParts
	_ Directive = directiveSecAuditLogRelevantStatus
	_ Directive = directiveSecContentInjection
	_ Directive = directiveSecDataDir
	_ Directive = directiveSecDefaultAction
	_ Directive = directiveSecDebugLog
	_ Directive = directiveSecDebugLogLevel
	_ Directive = directiveSecHashEngine
	_ Directive = directiveSecHashKey
	_ Directive = directiveSecHashMethodPm
	_ Directive = directiveSecHashMethodRx
	_ Directive = directiveSecHashParam
	_ Directive = directiveSecHttpBlKey
	_ Directive = directiveSecMarker
	_ Directive = directiveSecRemoteRules
	_ Directive = directiveSecSensorId
)

var directivesMap = map[string]Directive{
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
	"secauditlogformat":             directiveSecAuditLogFormat,

	// Unsupported Directives
	"secargumentseparator":     directiveUnsupported,
	"seccookieformat":          directiveUnsupported,
	"secruleupdatetargetbytag": directiveUnsupported,
	"secruleupdatetargetbymsg": directiveUnsupported,
	"secruleupdatetargetbyid":  directiveUnsupported,
	"secruleupdateactionbyid":  directiveUnsupported,
	"secrulescript":            directiveUnsupported,
	"secruleperftime":          directiveUnsupported,
}

func RegisterDirective(name string, directive Directive) {
	directivesMap[name] = directive
}
