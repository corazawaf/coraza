// Copyright 2022 Juan Pablo Tosso
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

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/types"
)

// DirectiveOptions contains the parsed options for a directive
type DirectiveOptions struct {
	Waf       *coraza.Waf
	Config    types.Config
	Arguments string
	Path      []string
}

// Directive type is used to extend the secland directives
type Directive = func(options *DirectiveOptions) error

func directiveSecComponentSignature(options *DirectiveOptions) error {
	options.Waf.ComponentNames = append(options.Waf.ComponentNames, options.Arguments)
	return nil
}

func directiveSecMarker(options *DirectiveOptions) error {
	rule := coraza.NewRule()
	rule.Raw = fmt.Sprintf("SecMarker %s", options.Arguments)
	rule.SecMark = options.Arguments
	rule.ID = 0
	rule.Phase = 0
	rule.Line = options.Config.Get("parser_last_line", 0).(int)
	rule.File = options.Config.Get("parser_config_file", "").(string)
	if err := options.Waf.Rules.Add(rule); err != nil {
		return newCompileRuleError(err, options.Arguments)
	}
	options.Waf.Logger.Debug("added secmark rule")
	return nil
}

func directiveSecAction(options *DirectiveOptions) error {
	rule, err := ParseRule(RuleOptions{
		WithOperator: false,
		Waf:          options.Waf,
		Config:       options.Config,
		Directive:    "SecAction",
		Data:         options.Arguments,
	})
	if err != nil {
		return newCompileRuleError(err, options.Arguments)
	}
	if err := options.Waf.Rules.Add(rule); err != nil {
		return newCompileRuleError(err, options.Arguments)
	}
	options.Waf.Logger.Debug("Added SecAction: %s", options.Arguments)
	return nil
}

func directiveSecRule(options *DirectiveOptions) error {
	ignoreErrors := options.Config.Get("ignore_rule_compilation_errors", false).(bool)
	rule, err := ParseRule(RuleOptions{
		WithOperator: true,
		Waf:          options.Waf,
		Config:       options.Config,
		Directive:    "SecRule",
		Data:         options.Arguments,
	})
	if err != nil && !ignoreErrors {
		return newCompileRuleError(err, options.Arguments)
	} else if err != nil && ignoreErrors {
		options.Waf.Logger.Debug("Ignoring rule compilation error for rule %s: %v", options.Arguments, err)
		return nil
	}
	err = options.Waf.Rules.Add(rule)
	if err != nil && !ignoreErrors {
		return err
	} else if err != nil && ignoreErrors {
		options.Waf.Logger.Debug("Ignoring rule compilation error for rule %s: %v", options.Arguments, err)
		return nil
	}
	return nil
}

func directiveSecResponseBodyAccess(options *DirectiveOptions) error {
	b, err := parseBoolean(strings.ToLower(options.Arguments))
	if err != nil {
		return newDirectiveError(err, "SecResponseBodyAccess")
	}
	options.Waf.ResponseBodyAccess = b
	return nil
}

func directiveSecRequestBodyLimit(options *DirectiveOptions) error {
	limit, _ := strconv.ParseInt(options.Arguments, 10, 64)
	options.Waf.RequestBodyLimit = limit
	return nil
}

func directiveSecRequestBodyAccess(options *DirectiveOptions) error {
	b, err := parseBoolean(strings.ToLower(options.Arguments))
	if err != nil {
		return newDirectiveError(err, "SecRequestBodyAccess")
	}
	options.Waf.RequestBodyAccess = b
	return nil
}

func directiveSecRuleEngine(options *DirectiveOptions) error {
	engine, err := types.ParseRuleEngineStatus(options.Arguments)
	options.Waf.RuleEngine = engine
	return err
}

func directiveUnsupported(options *DirectiveOptions) error {
	return nil
}

func directiveSecWebAppID(options *DirectiveOptions) error {
	options.Waf.WebAppID = options.Arguments
	return nil
}

func directiveSecTmpDir(options *DirectiveOptions) error {
	options.Waf.TmpDir = options.Arguments
	return nil
}

func directiveSecServerSignature(options *DirectiveOptions) error {
	options.Waf.ServerSignature = options.Arguments
	return nil
}

func directiveSecRuleRemoveByTag(options *DirectiveOptions) error {
	for _, r := range options.Waf.Rules.FindByTag(options.Arguments) {
		options.Waf.Rules.DeleteByID(r.ID)
	}
	return nil
}

func directiveSecRuleRemoveByMsg(options *DirectiveOptions) error {
	for _, r := range options.Waf.Rules.FindByMsg(options.Arguments) {
		options.Waf.Rules.DeleteByID(r.ID)
	}
	return nil
}

func directiveSecRuleRemoveByID(options *DirectiveOptions) error {
	id, _ := strconv.Atoi(options.Arguments)
	options.Waf.Rules.DeleteByID(id)
	return nil
}

func directiveSecResponseBodyMimeTypesClear(options *DirectiveOptions) error {
	options.Waf.ResponseBodyMimeTypes = []string{}
	return nil
}

func directiveSecResponseBodyMimeType(options *DirectiveOptions) error {
	options.Waf.ResponseBodyMimeTypes = strings.Split(options.Arguments, " ")
	return nil
}

func directiveSecResponseBodyLimitAction(options *DirectiveOptions) error {
	options.Waf.RejectOnResponseBodyLimit = strings.ToLower(options.Arguments) == "reject"
	return nil
}

func directiveSecResponseBodyLimit(options *DirectiveOptions) error {
	var err error
	options.Waf.ResponseBodyLimit, err = strconv.ParseInt(options.Arguments, 10, 64)
	return err
}

func directiveSecRequestBodyLimitAction(options *DirectiveOptions) error {
	options.Waf.RejectOnRequestBodyLimit = strings.ToLower(options.Arguments) == "reject"
	return nil
}

func directiveSecRequestBodyInMemoryLimit(options *DirectiveOptions) error {
	options.Waf.RequestBodyInMemoryLimit, _ = strconv.ParseInt(options.Arguments, 10, 64)
	return nil
}

func directiveSecRemoteRulesFailAction(options *DirectiveOptions) error {
	options.Waf.AbortOnRemoteRulesFail = strings.ToLower(options.Arguments) == "abort"
	return nil
}

func directiveSecRemoteRules(options *DirectiveOptions) error {
	return fmt.Errorf("not implemented")
}

func directiveSecConnWriteStateLimit(options *DirectiveOptions) error {
	return nil
}

func directiveSecSensorID(options *DirectiveOptions) error {
	options.Waf.SensorID = options.Arguments
	return nil
}

func directiveSecConnReadStateLimit(options *DirectiveOptions) error {
	return nil
}

func directiveSecPcreMatchLimitRecursion(options *DirectiveOptions) error {
	return nil
}

func directiveSecPcreMatchLimit(options *DirectiveOptions) error {
	return nil
}

func directiveSecHTTPBlKey(options *DirectiveOptions) error {
	return nil
}

func directiveSecGsbLookupDb(options *DirectiveOptions) error {
	return nil
}

func directiveSecHashMethodPm(options *DirectiveOptions) error {
	return nil
}

func directiveSecHashMethodRx(options *DirectiveOptions) error {
	return nil
}

func directiveSecHashParam(options *DirectiveOptions) error {
	return nil
}

func directiveSecHashKey(options *DirectiveOptions) error {
	return nil
}

func directiveSecHashEngine(options *DirectiveOptions) error {
	return nil
}

func directiveSecDefaultAction(options *DirectiveOptions) error {
	da, ok := options.Config.Get("rule_default_actions", []string{}).([]string)
	if !ok {
		da = []string{}
	}
	da = append(da, options.Arguments)
	options.Config.Set("rule_default_actions", da)
	return nil
}

func directiveSecContentInjection(options *DirectiveOptions) error {
	b, err := parseBoolean(options.Arguments)
	if err != nil {
		return newDirectiveError(err, "SecContentInjection")
	}
	options.Waf.ContentInjection = b
	return nil
}

func directiveSecConnEngine(options *DirectiveOptions) error {
	/*
		switch opts{
		case "On":
			w.ConnEngine = engine.CONN_ENGINE_ON
			break
		case "Off":
			w.ConnEngine = engine.CONN_ENGINE_OFF
			break
		case "DetectOnly":
			w.ConnEngine = engine.CONN_ENGINE_DETECTONLY
			break
		}
		break
	*/
	return nil
}

func directiveSecCollectionTimeout(options *DirectiveOptions) error {
	// w.CollectionTimeout, _ = strconv.Atoi(opts)
	return nil
}

func directiveSecAuditLog(options *DirectiveOptions) error {
	if len(options.Arguments) == 0 {
		return errors.New("syntax error: SecAuditLog /some/absolute/path.log")
	}
	options.Config.Set("auditlog_file", options.Arguments)
	if err := options.Waf.AuditLogWriter.Init(options.Config); err != nil {
		return err
	}
	return nil
}

func directiveSecAuditLogType(options *DirectiveOptions) error {
	if len(options.Arguments) == 0 {
		return errors.New("syntax error: SecAuditLogType [concurrent/https/serial/...]")
	}
	writer, err := loggers.GetLogWriter(options.Arguments)
	if err != nil {
		return err
	}
	if err := writer.Init(options.Config); err != nil {
		return err
	}
	options.Waf.AuditLogWriter = writer
	return nil
}

func directiveSecAuditLogFormat(options *DirectiveOptions) error {
	if len(options.Arguments) == 0 {
		return errors.New("syntax error: SecAuditLogFormat [json/native/...]")
	}
	formatter, err := loggers.GetLogFormatter(options.Arguments)
	if err != nil {
		return err
	}
	options.Config.Set("auditlog_formatter", formatter)
	if err := options.Waf.AuditLogWriter.Init(options.Config); err != nil {
		return err
	}
	return nil
}

func directiveSecAuditLogDir(options *DirectiveOptions) error {
	if len(options.Arguments) == 0 {
		return errors.New("syntax error: SecAuditLogDir /some/absolute/path")
	}
	options.Config.Set("auditlog_dir", options.Arguments)
	if err := options.Waf.AuditLogWriter.Init(options.Config); err != nil {
		return err
	}
	return nil
}

func directiveSecAuditLogDirMode(options *DirectiveOptions) error {
	if len(options.Arguments) == 0 {
		return errors.New("syntax error: SecAuditLogDirMode [0777/0700/...]")
	}
	auditLogDirMode, err := strconv.ParseInt(options.Arguments, 8, 32)
	if err != nil {
		return err
	}
	options.Config.Set("auditlog_dir_mode", fs.FileMode(auditLogDirMode))
	if err := options.Waf.AuditLogWriter.Init(options.Config); err != nil {
		return err
	}
	return nil
}

func directiveSecAuditLogFileMode(options *DirectiveOptions) error {
	if len(options.Arguments) == 0 {
		return errors.New("syntax error: SecAuditLogFileMode [0777/0700/...]")
	}
	auditLogFileMode, err := strconv.ParseInt(options.Arguments, 8, 32)
	if err != nil {
		return err
	}
	options.Config.Set("auditlog_file_mode", fs.FileMode(auditLogFileMode))
	if err := options.Waf.AuditLogWriter.Init(options.Config); err != nil {
		return err
	}
	return nil
}

func directiveSecAuditLogRelevantStatus(options *DirectiveOptions) error {
	var err error
	options.Waf.AuditLogRelevantStatus, err = regexp.Compile(options.Arguments)
	return err
}

func directiveSecAuditLogParts(options *DirectiveOptions) error {
	options.Waf.AuditLogParts = types.AuditLogParts(options.Arguments)
	return nil
}

func directiveSecAuditEngine(options *DirectiveOptions) error {
	au, err := types.ParseAuditEngineStatus(options.Arguments)
	options.Waf.AuditEngine = au
	return err
}

func directiveSecDataDir(options *DirectiveOptions) error {
	// TODO validations
	options.Waf.DataDir = options.Arguments
	return nil
}

func directiveSecUploadKeepFiles(options *DirectiveOptions) error {
	b, err := parseBoolean(options.Arguments)
	if err != nil {
		return newDirectiveError(err, "SecUploadKeepFiles")
	}
	options.Waf.UploadKeepFiles = b
	return nil
}

func directiveSecUploadFileMode(options *DirectiveOptions) error {
	fm, err := strconv.ParseInt(options.Arguments, 8, 32)
	options.Waf.UploadFileMode = fs.FileMode(fm)
	return err
}

func directiveSecUploadFileLimit(options *DirectiveOptions) error {
	var err error
	options.Waf.UploadFileLimit, err = strconv.Atoi(options.Arguments)
	return err
}

func directiveSecUploadDir(options *DirectiveOptions) error {
	// TODO validations
	options.Waf.UploadDir = options.Arguments
	return nil
}

func directiveSecRequestBodyNoFilesLimit(options *DirectiveOptions) error {
	var err error
	options.Waf.RequestBodyNoFilesLimit, err = strconv.ParseInt(options.Arguments, 10, 64)
	return err
}

func directiveSecDebugLog(options *DirectiveOptions) error {
	return options.Waf.SetDebugLogPath(options.Arguments)
}

func directiveSecDebugLogLevel(options *DirectiveOptions) error {
	lvl, err := strconv.Atoi(options.Arguments)
	if err != nil {
		return err
	}
	return options.Waf.SetDebugLogLevel(lvl)
}

func directiveSecRuleUpdateTargetByID(options *DirectiveOptions) error {
	spl := strings.SplitN(options.Arguments, " ", 2)
	if len(spl) != 2 {
		return errors.New("syntax error: SecRuleUpdateTargetById id \"VARIABLES\"")
	}
	id, err := strconv.Atoi(spl[0])
	if err != nil {
		return err
	}
	rule := options.Waf.Rules.FindByID(id)
	rp := &RuleParser{
		rule:           rule,
		options:        RuleOptions{},
		defaultActions: map[types.RulePhase][]ruleAction{},
	}
	return rp.ParseVariables(strings.Trim(spl[1], "\""))
}

func directiveSecIgnoreRuleCompilationErrors(options *DirectiveOptions) error {
	b, err := parseBoolean(options.Arguments)
	if err != nil {
		return newDirectiveError(err, "SecIgnoreRuleCompilationErrors")
	}
	if b {
		options.Waf.Logger.Warn(`Coraza is running in Compatibility Mode (SecIgnoreRuleCompilationErrors On)
		, which may cause unexpected behavior on faulty rules.`)
	}
	options.Config.Set("ignore_rule_compilation_errors", b)
	return nil
}

func newCompileRuleError(err error, opts string) error {
	return fmt.Errorf("failed to compile rule (%s): %s", err, opts)
}

func newDirectiveError(err error, directive string) error {
	return fmt.Errorf("syntax error for directive %s: %s", directive, err)
}

func parseBoolean(data string) (bool, error) {
	data = strings.ToLower(data)
	switch data {
	case "on":
		return true, nil
	case "off":
		return false, nil
	default:
		return false, errors.New("syntax error: [on/off]")
	}
}

var (
	_ Directive = directiveSecAction
	_ Directive = directiveSecAuditEngine
	_ Directive = directiveSecAuditLog
	_ Directive = directiveSecAuditLogType
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
	_ Directive = directiveSecHTTPBlKey
	_ Directive = directiveSecMarker
	_ Directive = directiveSecRemoteRules
	_ Directive = directiveSecSensorID
	_ Directive = directiveSecRuleUpdateTargetByID
)

// RegisterDirective registers a directive to the seclang processor.
// All WAF instances will share the same directive map.
func RegisterDirective(name string, directive Directive) {
	directivesMap[strings.ToLower(name)] = directive
}

var directivesMap = map[string]Directive{
	"secwebappid":                    directiveSecWebAppID,
	"secuploadkeepfiles":             directiveSecUploadKeepFiles,
	"secuploadfilemode":              directiveSecUploadFileMode,
	"secuploadfilelimit":             directiveSecUploadFileLimit,
	"secuploaddir":                   directiveSecUploadDir,
	"sectmpdir":                      directiveSecTmpDir,
	"secserversignature":             directiveSecServerSignature,
	"secsensorid":                    directiveSecSensorID,
	"secruleremovebytag":             directiveSecRuleRemoveByTag,
	"secruleremovebymsg":             directiveSecRuleRemoveByMsg,
	"secruleremovebyid":              directiveSecRuleRemoveByID,
	"secruleengine":                  directiveSecRuleEngine,
	"secrule":                        directiveSecRule,
	"secresponsebodymimetypesclear":  directiveSecResponseBodyMimeTypesClear,
	"secresponsebodymimetype":        directiveSecResponseBodyMimeType,
	"secresponsebodylimitaction":     directiveSecResponseBodyLimitAction,
	"secresponsebodylimit":           directiveSecResponseBodyLimit,
	"secresponsebodyaccess":          directiveSecResponseBodyAccess,
	"secrequestbodynofileslimit":     directiveSecRequestBodyNoFilesLimit,
	"secrequestbodylimitaction":      directiveSecRequestBodyLimitAction,
	"secrequestbodylimit":            directiveSecRequestBodyLimit,
	"secrequestbodyinmemorylimit":    directiveSecRequestBodyInMemoryLimit,
	"secrequestbodyaccess":           directiveSecRequestBodyAccess,
	"secremoterulesfailaction":       directiveSecRemoteRulesFailAction,
	"secremoterules":                 directiveSecRemoteRules,
	"secpcrematchlimitrecursion":     directiveSecPcreMatchLimitRecursion,
	"secpcrematchlimit":              directiveSecPcreMatchLimit,
	"secmarker":                      directiveSecMarker,
	"sechttpblkey":                   directiveSecHTTPBlKey,
	"sechashparam":                   directiveSecHashParam,
	"sechashmethodrx":                directiveSecHashMethodRx,
	"sechashmethodpm":                directiveSecHashMethodPm,
	"sechashkey":                     directiveSecHashKey,
	"sechashengine":                  directiveSecHashEngine,
	"secgsblookupdb":                 directiveSecGsbLookupDb,
	"secdefaultaction":               directiveSecDefaultAction,
	"secdatadir":                     directiveSecDataDir,
	"seccontentinjection":            directiveSecContentInjection,
	"secconnwritestatelimit":         directiveSecConnWriteStateLimit,
	"secconnreadstatelimit":          directiveSecConnReadStateLimit,
	"secconnengine":                  directiveSecConnEngine,
	"seccomponentsignature":          directiveSecComponentSignature,
	"seccollectiontimeout":           directiveSecCollectionTimeout,
	"secauditlogrelevantstatus":      directiveSecAuditLogRelevantStatus,
	"secauditlogparts":               directiveSecAuditLogParts,
	"secauditlogdir":                 directiveSecAuditLogDir,
	"secauditlogstoragedir":          directiveSecAuditLogDir,
	"secauditlog":                    directiveSecAuditLog,
	"secauditengine":                 directiveSecAuditEngine,
	"secaction":                      directiveSecAction,
	"secdebuglog":                    directiveSecDebugLog,
	"secdebugloglevel":               directiveSecDebugLogLevel,
	"secauditlogformat":              directiveSecAuditLogFormat,
	"secauditlogtype":                directiveSecAuditLogType,
	"secauditlogfilemode":            directiveSecAuditLogFileMode,
	"secauditlogdirmode":             directiveSecAuditLogDirMode,
	"secignorerulecompilationerrors": directiveSecIgnoreRuleCompilationErrors,

	// Unsupported Directives
	"secargumentseparator":     directiveUnsupported,
	"seccookieformat":          directiveUnsupported,
	"secruleupdatetargetbytag": directiveUnsupported,
	"secruleupdatetargetbymsg": directiveUnsupported,
	"secruleupdatetargetbyid":  directiveSecRuleUpdateTargetByID,
	"secruleupdateactionbyid":  directiveUnsupported,
	"secrulescript":            directiveUnsupported,
	"secruleperftime":          directiveUnsupported,
	"SecUnicodeMap":            directiveUnsupported,
}
