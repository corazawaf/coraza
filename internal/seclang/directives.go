// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:generate go run generator/main.go

package seclang

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/internal/auditlog"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/internal/memoize"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
)

// DirectiveOptions contains the parsed options for a directive. It is mutable and propagated
// across multiple directives, to support collecting the options for audit logs for example.
// TODO(anuraaga): Propagation of config probably should be separated from a directive's options.
type DirectiveOptions struct {
	WAF      *corazawaf.WAF
	Raw      string
	Opts     string
	Path     []string
	Datasets map[string][]string

	// Parser is configuration of the parser, populated by multiple directives and consumed by
	// directives that parse.
	Parser ParserConfig
}

type directive = func(options *DirectiveOptions) error

// Description: Include and evaluate a file or file pattern.
// Syntax: Include [PATH_TO_CONF_FILES]
// ---
// Include loads a file or a list of files from the filesystem using golang Glob syntax.
//
// Example:
// ```apache
// Include /path/coreruleset/rules/*.conf
// ```
//
// Quoting [Glob documentation](https://pkg.go.dev/path/filepath#Glob):
// > The syntax of patterns is the same as in Match. The pattern may describe hierarchical
// > names such as /usr/*/bin/ed (assuming the Separator is ‘/’).
// > Glob ignores file system errors such as I/O errors reading directories. The only possible returned error is ErrBadPattern, when pattern is malformed.
func directiveInclude(_ *DirectiveOptions) error {
	return errors.New("not implemented")
}

var _ directive = directiveInclude

var errEmptyOptions = errors.New("expected options")

// Description: Appends component signature to the Coraza signature.
// Syntax: SecComponentSignature "COMPONENT_NAME/X.Y.Z (COMMENT)"
// ---
// Appends component signature to the Coraza signature.
//
// Example:
// ```apache
// SecComponentSignature "OWASP_CRS/4.18.0"
// ```
func directiveSecComponentSignature(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}
	options.WAF.ComponentNames = append(options.WAF.ComponentNames, options.Opts)
	return nil
}

// Description: Adds a fixed rule marker that can be used as a target in a `skipAfter` action.
// A `SecMarker` directive essentially creates a rule that does nothing and whose only purpose
// is to carry the given ID.
// Syntax: SecMarker [ID|TEXT]
// ---
// The value can be either a number or a text string. The SecMarker directive is available to
// allow you to choose the best way to implement a skip-over. Here is an example used from the
// Core Rule Set:
//
// ```apache
//
//	SecMarker BEGIN_HOST_CHECK
//
//	SecRule &REQUEST_HEADERS:Host "@eq 0" \
//		"id:'960008',skipAfter:END_HOST_CHECK,phase:2,rev:'2.1.1',\
//		t:none,block,msg:'Request Missing a Host Header',\
//		tag:'PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21',\
//		tag:'OWASP_TOP_10/A7',tag:'PCI/6.5.10',\
//		severity:'5',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.notice_anomaly_score},\
//		setvar:tx.protocol_violation_score=+%{tx.notice_anomaly_score},\
//		setvar:tx.%{rule.id}-PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"
//	SecRule REQUEST_HEADERS:Host "^$" \
//		"id:'960008',phase:2,rev:'2.1.1',t:none,block,msg:'Request Missing a Host Header',\
//		tag:'PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21',\
//		tag:'OWASP_TOP_10/A7',tag:'PCI/6.5.10',severity:'5',\
//		setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.notice_anomaly_score},\
//		setvar:tx.protocol_violation_score=+%{tx.notice_anomaly_score},\
//		setvar:tx.%{rule.id}-PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"
//
//	SecMarker END_HOST_CHECK
//
// ```
func directiveSecMarker(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	rule := corazawaf.NewRule()
	rule.Raw_ = fmt.Sprintf("SecMarker %s", options.Opts)
	rule.SecMark_ = options.Opts
	rule.ID_ = 0
	rule.LogID_ = "0"
	rule.Phase_ = 0
	rule.Line_ = options.Parser.LastLine
	rule.File_ = options.Parser.ConfigFile
	if err := options.WAF.Rules.Add(rule); err != nil {
		return err
	}
	options.WAF.Logger.Debug().Msg("Added secmark rule")
	return nil
}

// Description: Unconditionally processes the action list it receives as the first and only parameter.
// Syntax: SecAction "action1,action2,action3,..."
// ----
// This directive is commonly used to set variables and initialize persistent collections using the
// `initcol` action. The syntax of the parameter is identical to that of the third parameter of `SecRule`.
//
// Example:
// ```apache
// SecAction "nolog,phase:1,initcol:RESOURCE=%{REQUEST_FILENAME}"
// ```
func directiveSecAction(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	rule, err := ParseRule(RuleOptions{
		WithOperator: false,
		WAF:          options.WAF,
		ParserConfig: options.Parser,
		Raw:          options.Raw,
		Directive:    "SecAction",
		Data:         options.Opts,
	})
	if err != nil {
		return err
	}
	if err := options.WAF.Rules.Add(rule); err != nil {
		return err
	}
	options.WAF.Logger.Debug().
		Str("actions", options.Opts).
		Msg("Added SecAction")
	return nil
}

// Description: Creates a rule that will analyze the selected variables using
// the selected operator.
// Syntax: SecRule VARIABLES OPERATOR [ACTIONS]
// ---
// Every rule must provide one or more variables along with the operator that should
// be used to inspect them. If no actions are provided, the default list will be used.
// (There is always a default list, even if one was not explicitly set with `SecDefaultAction`.)
// If there are actions specified in a rule, they will be merged with the default list
// to form the final actions that will be used. (The actions in the rule will overwrite
// those in the default list.) Refer to `SecDefaultAction` for more information.
//
// Example:
// ```apache
// SecRule ARGS "@rx attack" "phase:1,log,deny,id:1"
// ```
func directiveSecRule(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	ignoreErrors := options.Parser.IgnoreRuleCompilationErrors
	rule, err := ParseRule(RuleOptions{
		WithOperator: true,
		WAF:          options.WAF,
		ParserConfig: options.Parser,
		Raw:          options.Raw,
		Directive:    "SecRule",
		Data:         options.Opts,
		Datasets:     options.Datasets,
	})
	if err != nil && !ignoreErrors {
		return err
	} else if err != nil && ignoreErrors {
		options.WAF.Logger.Debug().
			Str("rule_id", options.Opts).
			Err(err).
			Msg("Ignoring rule compilation error")
		return nil
	}
	err = options.WAF.Rules.Add(rule)
	if err != nil && !ignoreErrors {
		return err
	} else if err != nil && ignoreErrors {
		options.WAF.Logger.Debug().
			Str("rule_id", options.Opts).
			Err(err).
			Msg("Ignoring rule compilation error")
		return nil
	}
	return nil
}

// Description: Configures whether response bodies are to be buffered.
// Syntax: SecResponseBodyAccess On|Off
// Default: Off
// ---
// This directive is required if you plan to inspect HTML responses and implement
// response blocking. Possible values are:
// - On: buffer response bodies (but only if the response MIME type matches the list
// configured with `SecResponseBodyMimeType`).
// - Off: do not buffer response bodies.
func directiveSecResponseBodyAccess(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	b, err := parseBoolean(strings.ToLower(options.Opts))
	if err != nil {
		return err
	}
	options.WAF.ResponseBodyAccess = b
	return nil
}

// Description: Configures the maximum request body size Coraza will accept for buffering.
// Default: 134217728 (128 Mib)
// Syntax: SecRequestBodyLimit [LIMIT_IN_BYTES]
// ---
// Depends on `SecRequestBodyLimitAction`
// - Reject: Anything over this limit will be rejected with status code 413 (Request Entity Too Large).
// - ProcessPartial: The first N bytes of the request body will be processed.
// There is a hard limit of 1 GiB.
func directiveSecRequestBodyLimit(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	limit, err := strconv.ParseInt(options.Opts, 10, 64)
	if err != nil {
		return err
	}
	options.WAF.RequestBodyLimit = limit
	return nil
}

// Description: Configures whether request bodies will be buffered and processed by Coraza.
// Syntax: SecRequestBodyAccess On|Off
// Default: Off
// ---
// This directive is required if you want to inspect the data transported request bodies
// (e.g., POST parameters). Request buffering is also required in order to make reliable
// blocking possible. The possible values are:
// - On: buffer request bodies
// - Off: do not buffer request bodies
func directiveSecRequestBodyAccess(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	b, err := parseBoolean(strings.ToLower(options.Opts))
	if err != nil {
		return err
	}
	options.WAF.RequestBodyAccess = b
	return nil
}

// Description: Configures the rules engine.
// Syntax: SecRuleEngine On|Off|DetectionOnly
// Default: Off
// ---
// The possible values are:
// - On: process rules
// - Off: do not process rules
// - DetectionOnly: process rules but never executes any disruptive actions
// (block, deny, drop, allow, proxy and redirect)
func directiveSecRuleEngine(options *DirectiveOptions) error {
	engine, err := types.ParseRuleEngineStatus(options.Opts)
	options.WAF.RuleEngine = engine
	return err
}

func directiveUnsupported(options *DirectiveOptions) error {
	return nil
}

func directiveSecWebAppID(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	options.WAF.WebAppID = options.Opts
	return nil
}

func directiveSecServerSignature(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	options.WAF.ServerSignature = utils.MaybeRemoveQuotes(options.Opts)
	return nil
}

// Description: Removes the matching rules from the current configuration context.
// Syntax: SecRuleRemoveByTag [TAG]
// ---
// Normally, you would use `SecRuleRemoveById` to remove rules, but it may occasionally
// be easier to disable an entire group of rules with `SecRuleRemoveByTag`. Matching is
// by case-sensitive string equality.
//
// Example:
// ```apache
// SecRuleRemoveByTag attack-dos
// ```
//
// Note: OWASP CRS has a list of supported tags https://coreruleset.org/docs/rules/metadata/
func directiveSecRuleRemoveByTag(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	options.WAF.Rules.DeleteByTag(options.Opts)
	return nil
}

// Description: Removes the matching rules from the current configuration context.
// Syntax: SecRuleRemoveByMsg MESSAGE
// ---
// Normally, you would use `SecRuleRemoveById` to remove rules, but it may occasionally
// be easier to disable one or more rules with `SecRuleRemoveByMsg`. Matching is
// by case-sensitive string equality.
//
// Example:
// ```apache
// SecRuleRemoveByMsg "Directory Listing"
// ```
func directiveSecRuleRemoveByMsg(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	options.WAF.Rules.DeleteByMsg(options.Opts)
	return nil
}

// Description: Removes the matching rules from the current configuration context.
// Syntax: SecRuleRemoveById ...[ID OR RANGE]
func directiveSecRuleRemoveByID(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	idsOrRanges := strings.Fields(options.Opts)
	for _, idOrRange := range idsOrRanges {
		if idx := strings.Index(idOrRange, "-"); idx == -1 {
			id, err := strconv.Atoi(idOrRange)
			if err != nil {
				return err
			}

			options.WAF.Rules.DeleteByID(id)
		} else {
			if idx == 0 {
				return fmt.Errorf("SecRuleRemoveById: invalid negative id: %s", idOrRange)
			}
			start, err := strconv.Atoi(idOrRange[:idx])
			if err != nil {
				return err
			}

			end, err := strconv.Atoi(idOrRange[idx+1:])
			if err != nil {
				return err
			}

			if start > end {
				return fmt.Errorf("invalid range: %s", idOrRange)
			}

			options.WAF.Rules.DeleteByRange(start, end)
		}
	}

	return nil
}

// Description: Clears the list of MIME types considered for response body buffering,
// allowing you to start populating the list from scratch.
// Syntax: SecResponseBodyMimeTypesClear
func directiveSecResponseBodyMimeTypesClear(options *DirectiveOptions) error {
	if len(options.Opts) > 0 {
		return errors.New("unexpected options")
	}
	options.WAF.ResponseBodyMimeTypes = nil
	return nil
}

// Description: Configures which MIME types are to be considered for response body buffering.
// Syntax: SecResponseBodyMimeType MIMETYPE MIMETYPE ...
// ---
// Multiple SecResponseBodyMimeType directives can be used to add MIME types.
// Use SecResponseBodyMimeTypesClear to clear previously configured MIME types and start over.
//
// Example:
// ```apache
// SecResponseBodyMimeType text/plain text/html text/xml
// ```
func directiveSecResponseBodyMimeType(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	options.WAF.ResponseBodyMimeTypes = strings.Split(options.Opts, " ")
	return nil
}

// Description: Controls what happens once a response body limit, configured with
// `SecResponseBodyLimit`, is encountered.
// Syntax: SecResponseBodyLimitAction Reject|ProcessPartial
// ---
// By default, Coraza will reject a response body that is longer than specified.
// Some web sites, however, will produce very long responses, making it difficult
// to come up with a reasonable limit. Such sites would have to raise the limit
// significantly to function properly, defying the purpose of having the limit in
// the first place (to control memory consumption). With the ability to choose what
// happens once a limit is reached, site administrators can choose to inspect only
// the first part of the response, the part that can fit into the desired limit, and
// let the rest through. Some could argue that allowing parts of responses to go
// uninspected is a weakness. This is true in theory, but applies only to cases in
// which the attacker controls the output (e.g., can make it arbitrary long). In such
// cases, however, it is not possible to prevent leakage anyway. The attacker could
// compress, obfuscate, or even encrypt data before it is sent back, and therefore
// bypass any monitoring device.
func directiveSecResponseBodyLimitAction(options *DirectiveOptions) error {
	switch strings.ToLower(options.Opts) {
	case "reject":
		options.WAF.ResponseBodyLimitAction = types.BodyLimitActionReject
	case "processpartial":
		options.WAF.ResponseBodyLimitAction = types.BodyLimitActionProcessPartial
	default:
		return errors.New("syntax error: SecResponseBodyLimitAction [Reject/ProcessPartial]")
	}
	return nil
}

// Description: Configures the maximum response body size that will be accepted for buffering.
// Syntax: SecResponseBodyLimit [LIMIT_IN_BYTES]
// Default: 524288 (512 Kib)
// ---
// Depends on `SecResponseBodyLimitAction`
// - Reject: Anything over this limit will be rejected with status code 500 (Internal Server Error).
// - ProcessPartial: The first N bytes of the response body will be processed.
// This setting will not affect the responses with MIME types that are not selected for
// buffering. There is a hard limit of 1 GiB.
func directiveSecResponseBodyLimit(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	limit, err := strconv.ParseInt(options.Opts, 10, 64)
	if err != nil {
		return err
	}
	options.WAF.ResponseBodyLimit = limit
	return nil
}

// Description: Controls what happens once a request body limit, configured with
// SecRequestBodyLimit, is encountered
// Syntax: SecRequestBodyLimitAction Reject|ProcessPartial
// Default: Reject
// ---
// By default, Coraza will reject a request body that is longer than specified to
// avoid OOM issues while buffering the request body prior the inspection.
func directiveSecRequestBodyLimitAction(options *DirectiveOptions) error {
	switch strings.ToLower(options.Opts) {
	case "reject":
		options.WAF.RequestBodyLimitAction = types.BodyLimitActionReject
	case "processpartial":
		options.WAF.RequestBodyLimitAction = types.BodyLimitActionProcessPartial
	default:
		return errors.New("syntax error: SecRequestBodyLimitAction [Reject/ProcessPartial]")
	}
	return nil
}

// Description: Configures the maximum request body size that Coraza will store in memory.
// Default: defaults to RequestBodyLimit
// Syntax: SecRequestBodyInMemoryLimit [LIMIT_IN_BYTES]
// ---
// When a `multipart/form-data` request is being processed, once the in-memory limit is reached,
// the request body will start to be streamed into a temporary file on disk.
func directiveSecRequestBodyInMemoryLimit(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	limit, err := strconv.ParseInt(options.Opts, 10, 64)
	if err != nil {
		return err
	}
	options.WAF.SetRequestBodyInMemoryLimit(limit)
	return nil
}

func directiveSecRemoteRulesFailAction(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	switch strings.ToLower(options.Opts) {
	case "abort":
		options.WAF.AbortOnRemoteRulesFail = true
	case "warn":
		options.WAF.AbortOnRemoteRulesFail = false
	default:
		return errors.New("unknown option")
	}
	return nil
}

func directiveSecRemoteRules(options *DirectiveOptions) error {
	return fmt.Errorf("not implemented")
}

func directiveSecConnWriteStateLimit(options *DirectiveOptions) error {
	return nil
}

func directiveSecSensorID(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	options.WAF.SensorID = options.Opts
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

// Description: Defines the default list of actions, which will be inherited
// by the rules in the same configuration context.
// Default: phase:2,log,auditlog,pass
// Syntax: SecDefaultAction "phase:2,log,auditlog,deny,status:403,tag:'SLA 24/7'"
// ---
// Every rule following a previous `SecDefaultAction` directive in the same configuration
// context will inherit its settings unless more specific actions are used.
//
// Rulesets like OWASP Core Ruleset uses this to define operation modes:
//
// - You can set the default disruptive action to block for phases 1 and 2 and you can force
// a phase 3 rule to be disrupted if the thread score is high.
// - You can set the default disruptive action to deny and each risky rule will interrupt
// the connection.
//
// Important: Every `SecDefaultAction` directive must specify a disruptive action and a processing
// phase and cannot contain metadata actions.
func directiveSecDefaultAction(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	options.Parser.RuleDefaultActions = append(options.Parser.RuleDefaultActions, options.Opts)
	options.Parser.HasRuleDefaultActions = true
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

// Description: Defines the path to the main audit log file (serial logging format)
// or the concurrent logging index file (concurrent logging format).
// Syntax: SecAuditLog [ABSOLUTE_PATH_TO_LOG_FILE]
// ---
//
// Example:
// ```apache
// SecAuditLog "/path/to/audit.log"
// ```
//
// Note: This audit log file is opened on startup when the server typically still runs
// as root. You should not allow non-root users to have write privileges for this file
// or for the directory.
func directiveSecAuditLog(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	options.WAF.AuditLogWriterConfig.Target = options.Opts

	return nil
}

// Description: Configures the type of audit logging mechanism to be used.
// Syntax: SecAuditLogType Serial|Concurrent|HTTPS|Syslog
// ---
// The possible values are:
//
//   - Serial : Audit log entries will be stored in a single file, specified by SecAuditLog.
//     This is convenient for casual use, but it can slow down the server, because only
//     one audit log entry can be written to the file at any one time.
//   - Concurrent : One file per transaction is used for audit logging. This approach is more
//     scalable when heavy logging is required (multiple transactions can be recorded in parallel)
//   - HTTPS : Audit log entries will be sent to the target URL, specified by SecAuditLog.
//   - Syslog : Audit log entries will be sent to the syslog server, specified by SecAuditLog
//     in one of formats: "ADDRESS:PORT" (TCP), "udp://ADDRESS:PORT", or "unixgram:///var/run/syslog".
//
// Example:
// ```apache
// SecAuditLogType Serial
// ```
func directiveSecAuditLogType(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	writer, err := auditlog.GetWriter(options.Opts)
	if err != nil {
		return err
	}
	options.WAF.SetAuditLogWriter(writer)

	return nil
}

// Description: Select the output format of the AuditLogs. The format can be
// the native AuditLogs format, JSON, or OCSF (Open CyberSecurity Schema Framework).
// Syntax: SecAuditLogFormat JSON|JsonLegacy|Native|OCSF
// Default: Native
func directiveSecAuditLogFormat(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	formatter, err := auditlog.GetFormatter(options.Opts)
	if err != nil {
		return err
	}
	options.WAF.AuditLogWriterConfig.Formatter = formatter

	return nil
}

// Description: Configures the directory where concurrent audit log entries are stored.
// Syntax: SecAuditLogStorageDir [PATH_TO_LOG_DIR]
// ---
// This directive is required only when concurrent audit logging is used. Ensure that you
// specify a file system location with adequate disk space.
//
// Example:
// ```apache
// SecAuditLogStorageDir /tmp/auditlogs/
// ```
func directiveSecAuditLogStorageDir(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	options.WAF.AuditLogWriterConfig.Dir = options.Opts

	return nil
}

// Description: Configures the mode (permissions) of any directories created for the
// concurrent audit logs, using an octal mode value as parameter (as used in `chmod`).
// Syntax: SecAuditLogDirMode octal_mode|"default"
// Default: 0600
// ---
// The default mode for new audit log directories (0600) only grants read/write access
// to the owner.
//
// Example:
// ```apache
// SecAuditLogDirMode 02750
// ```
func directiveSecAuditLogDirMode(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	auditLogDirMode, err := strconv.ParseInt(options.Opts, 8, 32)
	if err != nil {
		return err
	}
	options.WAF.AuditLogWriterConfig.DirMode = fs.FileMode(auditLogDirMode)

	return nil
}

// Description: Configures the mode (permissions) of any files created for concurrent
// audit logs using an octal mode (as used in `chmod`). See `SecAuditLogDirMode` for
// controlling the mode of created audit log directories.
// Syntax: SecAuditLogFileMode octal_mode|"default"
// Default: 0600
// ---
// Example:
// ```apache
// SecAuditLogFileMode 00640
// ```
func directiveSecAuditLogFileMode(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	auditLogFileMode, err := strconv.ParseInt(options.Opts, 8, 32)
	if err != nil {
		return err
	}
	options.WAF.AuditLogWriterConfig.FileMode = fs.FileMode(auditLogFileMode)

	return nil
}

// Description: Configures which response status code is to be considered relevant
// for the purpose of audit logging.
// Syntax: SecAuditLogRelevantStatus [REGEX]
// ---
// The main purpose of this directive is to allow you to configure audit logging for
// only the transactions that have the status code that matches the supplied regular
// expression.
//
// Example:
// ```
// SecAuditLogRelevantStatus "^(?:5|40[1235])"
// ```
// This example would log all 5xx and 4xx level status codes,
// except for 404s. Although you could achieve the same effect with a rule in phase 5,
// `SecAuditLogRelevantStatus` is sometimes better, because it continues to work even when
// `SecRuleEngine` is disabled.
//
// Note: Must have `SecAuditEngine` set to `RelevantOnly`. Additionally, the auditlog action
// is present by default in rules, this will make the engine bypass the `SecAuditLogRelevantStatus`
// and send rule matches to the audit log regardless of status. You must specify noauditlog in the
// rules manually or set it in `SecDefaultAction`.
func directiveSecAuditLogRelevantStatus(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	re, err := memoize.Do(options.Opts, func() (any, error) { return regexp.Compile(options.Opts) })
	if err != nil {
		return err
	}

	options.WAF.AuditLogRelevantStatus = re.(*regexp.Regexp)
	return nil
}

// Description: Defines which parts of each transaction are going to be recorded
// in the audit log. Each part is assigned a single letter; when a letter appears
// in the list then the equivalent part will be recorded. See below for the list of
// all parts.
// Syntax: SecAuditLogParts [PARTLETTERS]
// Default: ABCFHZ
// ---
// Example:
// ```apache
// SecAuditLogParts ABCFHZ
// ```
//
// Available audit log parts:
//
// - A: Audit log header (mandatory).
// - B: Request headers.
// - C: Request body (present only if the request body exists and Coraza is configured
// to intercept it. This would require `SecRequestBodyAccess` to be set to on).
// - D: Reserved for intermediary response headers; not implemented yet.
// - E: Intermediary response body (present only if Coraza is configured to intercept
// response bodies, and if the audit log engine is configured to record it. Intercepting
// response bodies requires `SecResponseBodyAccess` to be enabled). Intermediary response
// body is the same as the actual response body unless Coraza intercepts the intermediary
// response body, in which case the actual response body will contain the error message.
// - F: Final response headers.
// - G: Reserved for the actual response body; not implemented yet.
// - H: Audit log trailer.
// - I: This part is a replacement for part C. It will log the same data as C in all cases except when
// `multipart/form-data` encoding in used. In this case, it will log a fake `application/x-www-form-urlencoded`
// body that contains the information about parameters but not about the files. This is handy if
// you don’t want to have (often large) files stored in your audit logs; not implemented yet.
// - J: This part contains information about the files uploaded using `multipart/form-data` encoding; not implemented yet.
// - K: This part contains a full list of every rule that matched (one per line) in the order they were
// matched. The rules are fully qualified and will thus show inherited actions and default operators.
// - Z: Final boundary, signifies the end of the entry (mandatory).
func directiveSecAuditLogParts(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	var err error
	options.WAF.AuditLogParts, err = types.ParseAuditLogParts(options.Opts)
	return err
}

// Description: Configures the audit logging engine.
// Syntax: SecAuditEngine RelevantOnly
// Default: Off
// ---
// The `SecAuditEngine` directive is used to configure the audit engine, which logs complete
// transactions.
//
// The possible values for the audit log engine are as follows:
//   - On: log all transactions
//   - Off: do not log any transactions
//   - RelevantOnly: only the log transactions that have triggered a warning or an error, or have
//     a status code that is considered to be relevant (as determined by the `SecAuditLogRelevantStatus`
//     directive)
//
// Note: If you need to change the audit log engine configuration on a per-transaction basis (e.g.,
// in response to some transaction data), use the `ctl` action.
//
// The following example demonstrates how `SecAuditEngine` is used:
// ```apache
// SecAuditEngine RelevantOnly
// SecAuditLog logs/audit/audit.log
// SecAuditLogParts ABCFHZ
// SecAuditLogType concurrent
// SecAuditLogStorageDir logs/audit
// SecAuditLogRelevantStatus ^(?:5|4(?!04))
// ```
func directiveSecAuditEngine(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	au, err := types.ParseAuditEngineStatus(options.Opts)
	options.WAF.AuditEngine = au
	return err
}

func directiveSecDataDir(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	options.WAF.DataDir = options.Opts
	return nil
}

func directiveSecUploadKeepFiles(options *DirectiveOptions) error {
	b, err := parseBoolean(options.Opts)
	if err != nil {
		return err
	}
	options.WAF.UploadKeepFiles = b
	return nil
}

func directiveSecUploadFileMode(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	fm, err := strconv.ParseInt(options.Opts, 8, 32)
	if err != nil {
		return err
	}
	options.WAF.UploadFileMode = fs.FileMode(fm)
	return nil
}

func directiveSecUploadFileLimit(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	var err error
	options.WAF.UploadFileLimit, err = strconv.Atoi(options.Opts)
	return err
}

func directiveSecUploadDir(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	if environment.HasAccessToFS {
		if err := environment.IsDirWritable(options.Opts); err != nil {
			return fmt.Errorf("filesystem access check: %w. Check SecUploadDir provided dir: %s", err, options.Opts)
		}
	} else {
		return fmt.Errorf("SecUploadDir directive is not effective because of no access to the filesystem")
	}
	options.WAF.UploadDir = options.Opts
	return nil
}

// Description: Configures the maximum request body size Coraza will accept for
// buffering, excluding the size of any files being transported in the request.
// This directive is useful to reduce susceptibility to DoS attacks when someone is
// sending request bodies of very large sizes. Web applications that require file uploads
// must configure `SecRequestBodyLimit` to a high value, but because large files are streamed
// to disk, file uploads will not increase memory consumption. However, it’s still possible
// for someone to take advantage of a large request body limit and send non-upload requests
// with large body sizes. This directive eliminates that loophole.
// Default: 1048576 (1 MB)
// Syntax: SecRequestBodyNoFilesLimit 131072
// ---
// Generally speaking, the default value is not small enough. For most applications, you
// should be able to reduce it down to 128 KB or lower. Anything over the limit will be
// rejected with status code 413 (Request Entity Too Large). There is a hard limit of 1 GiB.
// Note: not implemented yet
func directiveSecRequestBodyNoFilesLimit(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	var err error
	options.WAF.RequestBodyNoFilesLimit, err = strconv.ParseInt(options.Opts, 10, 64)
	return err
}

// Description: Path to the Coraza debug log file.
// Syntax: SecDebugLog [ABSOLUTE_PATH_TO_DEBUG_LOG]
// ---
// Logs will be written to this file. Make sure the process user has write access to the
// directory.
func directiveSecDebugLog(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	return options.WAF.SetDebugLogPath(options.Opts)
}

// Description: Configures the verboseness of the debug log data.
// Default: 3
// Syntax: SecDebugLogLevel [LOG_LEVEL]
// ---
// Depending on the implementation, errors ranging from 1 to 2 might be directly
// logged to the connector error log. For example, level 1 (error) logs will be
// written to caddy server error logs.
// The possible values for the debug log level are:
//
// - 0:   No logging (least verbose)
// - 1:   Error
// - 2:   Warn
// - 3:   Info
// - 4-8: Debug
// - 9:   Trace (most verbose)
//
// Levels outside the 0-9 range will default to level 3 (Info)
func directiveSecDebugLogLevel(options *DirectiveOptions) error {
	lvl, err := strconv.ParseInt(options.Opts, 10, 8)
	if err != nil {
		return err
	}
	return options.WAF.SetDebugLogLevel(debuglog.Level(lvl))
}

// Description: Updates the target (variable) list of the specified rule(s).
// Syntax: SecRuleUpdateTargetById ID TARGET1[|TARGET2|TARGET3]
// ---
// This directive will append variables to the specified rule with the targets provided in the second parameter.
// The rule ID can be single IDs or ranges of IDs. The targets are separated by a pipe character.
func directiveSecRuleUpdateTargetByID(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	idsOrRanges := strings.Fields(options.Opts)
	length := len(idsOrRanges)
	if length < 2 {
		return errors.New("syntax error: SecRuleUpdateTargetById id \"VARIABLES\"")
	}
	// The last element is expected to be the variable(s)
	variables := idsOrRanges[length-1]
	for _, idOrRange := range idsOrRanges[:length-1] {
		if idx := strings.Index(idOrRange, "-"); idx == -1 {
			id, err := strconv.Atoi(idOrRange)
			if err != nil {
				return err
			}
			return updateTargetBySingleID(id, variables, options)
		} else {
			if idx == 0 {
				return fmt.Errorf("SecRuleUpdateTargetById: invalid negative id: %s", idOrRange)
			}
			start, err := strconv.Atoi(idOrRange[:idx])
			if err != nil {
				return err
			}

			end, err := strconv.Atoi(idOrRange[idx+1:])
			if err != nil {
				return err
			}
			if start == end {
				return updateTargetBySingleID(start, variables, options)
			}
			if start > end {
				return fmt.Errorf("invalid range: %s", idOrRange)
			}

			for _, rule := range options.WAF.Rules.GetRules() {
				if rule.ID_ >= start && rule.ID_ <= end {
					rp := RuleParser{
						rule: &rule,
						options: RuleOptions{
							WAF: options.WAF,
						},
						defaultActions: map[types.RulePhase][]ruleAction{},
					}
					if err := rp.ParseVariables(strings.Trim(variables, "\"")); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func updateTargetBySingleID(id int, variables string, options *DirectiveOptions) error {

	rule := options.WAF.Rules.FindByID(id)
	if rule == nil {
		return fmt.Errorf("SecRuleUpdateTargetById: rule \"%d\" not found", id)
	}
	rp := RuleParser{
		rule: rule,
		options: RuleOptions{
			WAF: options.WAF,
		},
		defaultActions: map[types.RulePhase][]ruleAction{},
	}
	return rp.ParseVariables(strings.Trim(variables, "\""))
}

// Description: Updates the action list of the specified rule(s).
// Syntax: SecRuleUpdateActionById ID ACTIONLIST
// ---
// This directive will overwrite the action list of the specified rule with the actions provided in the second parameter.
// It has two limitations: it cannot be used to change the ID or phase of a rule.
// Only the actions that can appear only once are overwritten.
// The actions that are allowed to appear multiple times in a list, will be appended to the end of the list.
// The following example demonstrates how `SecRuleUpdateActionById` is used:
// ```apache
// SecRuleUpdateActionById 12345 "deny,status:403"
// ```
func directiveSecRuleUpdateActionByID(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	idsOrRanges := strings.Fields(options.Opts)
	idsOrRangesLen := len(idsOrRanges)
	if idsOrRangesLen < 2 {
		return errors.New("syntax error: SecRuleUpdateActionById id \"ACTION1,ACTION2,...\"")
	}
	// The last element is expected to be the action(s)
	actions := idsOrRanges[idsOrRangesLen-1]
	for _, idOrRange := range idsOrRanges[:idsOrRangesLen-1] {
		if idx := strings.Index(idOrRange, "-"); idx == -1 {
			id, err := strconv.Atoi(idOrRange)
			if err != nil {
				return err
			}
			return updateActionBySingleID(id, actions, options)
		} else {
			if idx == 0 {
				return fmt.Errorf("SecRuleUpdateActionById: invalid negative id: %s", idOrRange)
			}
			start, err := strconv.Atoi(idOrRange[:idx])
			if err != nil {
				return err
			}

			end, err := strconv.Atoi(idOrRange[idx+1:])
			if err != nil {
				return err
			}
			if start == end {
				return updateActionBySingleID(start, actions, options)
			}
			if start > end {
				return fmt.Errorf("invalid range: %s", idOrRange)
			}

			for _, rule := range options.WAF.Rules.GetRules() {
				if rule.ID_ < start && rule.ID_ > end {
					continue
				}
				rp := RuleParser{
					rule: &rule,
					options: RuleOptions{
						WAF: options.WAF,
					},
					defaultActions: map[types.RulePhase][]ruleAction{},
				}
				if err := rp.ParseActions(strings.Trim(actions, "\"")); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func updateActionBySingleID(id int, actions string, options *DirectiveOptions) error {

	rule := options.WAF.Rules.FindByID(id)
	if rule == nil {
		return fmt.Errorf("SecRuleUpdateActionById: rule \"%d\" not found", id)
	}
	rp := RuleParser{
		rule: rule,
		options: RuleOptions{
			WAF: options.WAF,
		},
		defaultActions: map[types.RulePhase][]ruleAction{},
	}
	return rp.ParseActions(strings.Trim(actions, "\""))
}

// Description: Updates the target (variable) list of the specified rule(s) by tag.
// Syntax: SecRuleUpdateTargetByTag TAG TARGET1[|TARGET2|TARGET3]
// ---
// As an alternative to `SecRuleUpdateTargetById`, this directive will append variables to the specified rule
// with the targets provided in the second parameter. It can be handy for updating an entire group of rules.
// Matching is by case-sensitive string equality.
// This directive will append variables to the specified rule with the targets provided in the second parameter.
// The rule ID can be single IDs or ranges of IDs. The targets are separated by a pipe character.
// Note: OWASP CRS has a list of supported tags https://coreruleset.org/docs/rules/metadata/
func directiveSecRuleUpdateTargetByTag(options *DirectiveOptions) error {
	tagAndvars := strings.Fields(options.Opts)
	if len(tagAndvars) != 2 {
		return errors.New("syntax error: SecRuleUpdateTargetByTag tag \"VARIABLES\"")
	}

	for _, rule := range options.WAF.Rules.GetRules() {
		inputTag := strings.Trim(tagAndvars[0], "\"")
		if utils.InSlice(inputTag, rule.Tags_) {
			rp := RuleParser{
				rule: &rule,
				options: RuleOptions{
					WAF: options.WAF,
				},
				defaultActions: map[types.RulePhase][]ruleAction{},
			}
			inputVars := strings.Trim(tagAndvars[1], "\"")
			if err := rp.ParseVariables(inputVars); err != nil {
				return err
			}
		}
	}
	return nil
}

func directiveSecIgnoreRuleCompilationErrors(options *DirectiveOptions) error {
	b, err := parseBoolean(options.Opts)
	if err != nil {
		return err
	}
	if b {
		options.WAF.Logger.Warn().
			Msg(`Running in Compatibility Mode (SecIgnoreRuleCompilationErrors On), 
			which may cause unexpected behavior on faulty rules.`)
	}
	options.Parser.IgnoreRuleCompilationErrors = b
	return nil
}

func directiveSecDataset(options *DirectiveOptions) error {
	if len(options.Opts) == 0 {
		return errEmptyOptions
	}

	name, d, ok := strings.Cut(options.Opts, " ")
	if !ok {
		return errors.New("syntax error: SecDataset name `\n...\n`")
	}
	if _, ok := options.Datasets[name]; ok {
		options.WAF.Logger.Warn().
			Str("dataset_name", name).
			Msg("Dataset already exists, overwriting")
	}
	var arr []string
	data := strings.Trim(d, "`")
	for _, s := range strings.Split(data, "\n") {
		s = strings.TrimSpace(s)
		if s == "" || s[0] == '#' {
			continue
		}
		arr = append(arr, s)
	}
	options.Datasets[name] = arr
	return nil
}

// Description: Configures the maximum number of ARGS that will be accepted for processing.
// Default: 1000
// Syntax: SecArgumentsLimit [LIMIT]
// ---
// Exceeding the limit will not be included.
// With JSON body processing, there is nothing to do when exceed the limit.
// Example:
// ```apache
// SecArgumentsLimit 1000
// ```
func directiveSecArgumentsLimit(options *DirectiveOptions) error {
	limit, err := strconv.Atoi(options.Opts)
	if err != nil {
		return err
	}
	if limit <= 0 {
		return errors.New("argument limit should be bigger than 0")
	}
	options.WAF.ArgumentLimit = limit
	return nil
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
