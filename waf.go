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

package coraza

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jptosso/coraza-waf/v2/geo"
	loggers "github.com/jptosso/coraza-waf/v2/loggers"
	"github.com/jptosso/coraza-waf/v2/types"
	"github.com/jptosso/coraza-waf/v2/types/variables"
	utils "github.com/jptosso/coraza-waf/v2/utils/strings"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ErrorLogCallback is used to set a callback function to log errors
// It is triggered when an error is raised by the WAF
// It contains the severity so the cb can decide to log it or not
type ErrorLogCallback = func(rule MatchedRule)

// Waf instances are used to store configurations and rules
// Every web application should have a different Waf instance
// but you can share an instance if you are okwith sharing
// configurations, rules and logging.
// Transactions and SecLang parser requires a Waf instance
// You can use as many Waf instances as you want and they are
// concurrent safe
// All Waf instance fields are inmutable, if you update any
// of them in runtime you might create concurrency issues
type Waf struct {
	// ruleGroup object, contains all rules and helpers
	Rules RuleGroup

	// Audit logger engine
	auditLogger *loggers.Logger

	// Audit mode status
	AuditEngine types.AuditEngineStatus

	// Array of logging parts to be used
	AuditLogParts []rune

	// Status of the content injection for responses and requests
	ContentInjection bool

	// If true, transactions will have access to the request body
	RequestBodyAccess bool

	// Request body page file limit
	RequestBodyLimit int64

	// Request body in memory limit
	RequestBodyInMemoryLimit int64

	// If true, transactions will have access to the response body
	ResponseBodyAccess bool

	// Response body memory limit
	ResponseBodyLimit int64

	// Defines if rules are going to be evaluated
	RuleEngine types.RuleEngineStatus

	// If true, transaction will fail if response size is bigger than the page limit
	RejectOnResponseBodyLimit bool

	// If true, transaction will fail if request size is bigger than the page limit
	RejectOnRequestBodyLimit bool

	// Responses will only be loaded if mime is listed here
	ResponseBodyMimeTypes []string

	// Web Application id, apps sharing the same id will share persistent collections
	WebAppID string

	// Add significant rule components to audit log
	ComponentNames []string

	// Contains the regular expression for relevant status audit logging
	AuditLogRelevantStatus *regexp.Regexp

	// If true WAF engine will fail when remote rules cannot be loaded
	AbortOnRemoteRulesFail bool

	// Instructs the waf to change the Server response header
	ServerSignature string

	// This directory will be used to store page files
	TmpDir string

	// Sensor ID identifies the sensor in ac cluster
	SensorID string

	// Path to store data files (ex. cache)
	DataDir string

	// AUDIT LOG VARIABLES

	// AuditLog contains the log file absolute path
	AuditLog string
	// AuditLogDir contains the concurrent logging directory
	AuditLogDir string
	// AuditLogFormat is the audit log format
	AuditLogFormat string
	// AuditLogType is the audit log type
	AuditLogType string

	UploadKeepFiles         bool
	UploadFileMode          fs.FileMode
	UploadFileLimit         int
	UploadDir               string
	RequestBodyNoFilesLimit int64
	CollectionTimeout       int

	// Used by some functions to support concurrent tasks
	mux *sync.RWMutex

	RequestBodyLimitAction types.RequestBodyLimitAction

	ArgumentSeparator string

	// Used for the debug logger
	Logger *zap.Logger

	geo geo.Reader

	// Used to allow switching the debug level during runtime
	// ctl cannot switch use it as it will update de lvl
	// for the whole Waf instance
	loggerAtomicLevel *zap.AtomicLevel

	errorLogCb ErrorLogCallback
}

// NewTransaction Creates a new initialized transaction for this WAF instance
func (w *Waf) NewTransaction() *Transaction {
	w.mux.RLock()
	defer w.mux.RUnlock()
	tx := &Transaction{
		Waf:                  *w,
		collections:          make([]*Collection, 100), // TODO fix count
		ID:                   utils.SafeRandom(19),
		Timestamp:            time.Now().UnixNano(),
		AuditEngine:          w.AuditEngine,
		AuditLogParts:        w.AuditLogParts,
		RuleEngine:           w.RuleEngine,
		RequestBodyAccess:    true,
		RequestBodyLimit:     134217728,
		ResponseBodyAccess:   true,
		ResponseBodyLimit:    524288,
		ruleRemoveTargetByID: map[int][]ruleVariableParams{},
		ruleRemoveByID:       []int{},
		StopWatches:          map[types.RulePhase]int{},
		RequestBodyBuffer:    NewBodyBuffer(w.TmpDir, w.RequestBodyInMemoryLimit),
		ResponseBodyBuffer:   NewBodyBuffer(w.TmpDir, w.RequestBodyInMemoryLimit),
	}
	for i := range tx.collections {
		tx.collections[i] = NewCollection(variables.RuleVariable(i))
	}

	// set capture variables
	txvar := tx.GetCollection(variables.TX)
	for i := 0; i <= 10; i++ {
		is := strconv.Itoa(i)
		txvar.Set(is, []string{""})
	}

	// Some defaults
	defaults := map[variables.RuleVariable]string{
		variables.FilesCombinedSize:             "0",
		variables.UrlencodedError:               "0",
		variables.FullRequestLength:             "0",
		variables.MultipartBoundaryQuoted:       "0",
		variables.MultipartBoundaryWhitespace:   "0",
		variables.MultipartCrlfLfLines:          "0",
		variables.MultipartDataAfter:            "0",
		variables.MultipartDataBefore:           "0",
		variables.MultipartFileLimitExceeded:    "0",
		variables.MultipartHeaderFolding:        "0",
		variables.MultipartInvalidHeaderFolding: "0",
		variables.MultipartInvalidPart:          "0",
		variables.MultipartInvalidQuoting:       "0",
		variables.MultipartLfLine:               "0",
		variables.MultipartMissingSemicolon:     "0",
		variables.MultipartStrictError:          "0",
		variables.MultipartUnmatchedBoundary:    "0",
		variables.OutboundDataError:             "0",
		variables.ReqbodyError:                  "0",
		variables.ReqbodyProcessorError:         "0",
		variables.RequestBodyLength:             "0",
		variables.Duration:                      "0",
		variables.HighestSeverity:               "0",
		variables.ArgsCombinedSize:              "0",
		variables.UniqueID:                      tx.ID,
		// TODO single variables must be defaulted to empty string
		variables.RemoteAddr:       "",
		variables.ReqbodyProcessor: "",
		variables.RequestBody:      "",
		variables.ResponseBody:     "",
		// others
		// variables.WebAppID: w.WebAppID, not implemented yet
	}
	for v, data := range defaults {
		tx.GetCollection(v).Set("", []string{data})
	}

	// Get all env variables
	env := tx.GetCollection(variables.Env)
	for _, e := range os.Environ() {
		spl := strings.SplitN(e, "=", 2)
		if len(spl) != 2 {
			continue
		}
		env.Set(spl[0], []string{spl[1]})
	}

	w.Logger.Debug("new transaction created", zap.String("event", "NEW_TRANSACTION"), zap.String("txid", tx.ID))

	return tx
}

// UpdateAuditLogger compiles every SecAuditLog directive
// into a single *loggers.Logger
// This is required after updating w.AuditLog* variables
// It doesn't look to effective but the reason for this is
// that we have to reinitialize the logger after updating
// This is not concurrency safe, it should never be called
// after the rules are being used
func (w *Waf) UpdateAuditLogger() error {
	al, err := loggers.NewAuditLogger()
	if err != nil {
		return err
	}
	if w.AuditLog == "" {
		// when there is no path we won't log
		return nil
	}
	if err := al.SetFile(w.AuditLog); err != nil {
		return err
	}

	// SecAuditLogFormat provides a log format, default is native
	if w.AuditLogFormat != "" {
		if err := al.SetFormatter(w.AuditLogFormat); err != nil {
			return err
		}
	} else {
		if err := al.SetFormatter("native"); err != nil {
			return err
		}
	}

	// SecAuditLogDir provides the log directory,
	// there is no default value
	if w.AuditLogDir != "" {
		if err := al.SetDir(w.AuditLogDir); err != nil {
			return err
		}
	}

	// SecAuditLog provides the log type, default is serial
	if w.AuditLogType != "" {
		if err := al.SetWriter(w.AuditLogType); err != nil {
			return err
		}
	} else {
		if err := al.SetWriter("serial"); err != nil {
			return err
		}
	}
	w.auditLogger = al
	return nil
}

// SetDebugLogPath sets the path for the debug log
// If the path is empty, the debug log will be disabled
// note: this is not thread safe
func (w *Waf) SetDebugLogPath(path string) error {
	cfg := zap.NewProductionConfig()
	if path == "" {
		cfg.OutputPaths = []string{}
	} else {
		cfg.OutputPaths = []string{path}
	}
	cfg.Level = *w.loggerAtomicLevel
	logger, err := cfg.Build()
	if err != nil {
		return err
	}
	w.Logger = logger
	return nil
}

// AuditLogger returns the initiated loggers
// Coraza supports unlimited loggers, so you can write for example
// to syslog and a local drive at the same time
// AuditLogger() returns nil if the audit logger is not set
// Please try to use a nil logger...
func (w *Waf) AuditLogger() *loggers.Logger {
	return w.auditLogger
}

// NewWaf creates a new WAF instance with default variables
func NewWaf() *Waf {
	atom := zap.NewAtomicLevel()
	atom.SetLevel(zap.FatalLevel)
	waf := &Waf{
		ArgumentSeparator:        "&",
		AuditEngine:              types.AuditEngineOff,
		AuditLogParts:            []rune("ABCFHZ"),
		mux:                      &sync.RWMutex{},
		RequestBodyInMemoryLimit: 131072,
		RequestBodyLimit:         10000000, // 10mb
		ResponseBodyMimeTypes:    []string{"text/html", "text/plain"},
		ResponseBodyLimit:        524288,
		ResponseBodyAccess:       false,
		RuleEngine:               types.RuleEngineOn,
		Rules:                    NewRuleGroup(),
		TmpDir:                   "/tmp",
		CollectionTimeout:        3600,
		loggerAtomicLevel:        &atom,
		AuditLogRelevantStatus:   regexp.MustCompile(`.*`),
	}
	if err := waf.SetDebugLogPath("/dev/null"); err != nil {
		fmt.Println(err)
	}
	waf.Logger.Debug("a new waf instance was created")
	return waf
}

// SetLogLevel changes the debug level of the Waf instance
func (w *Waf) SetLogLevel(lvl int) error {
	// setlevel is concurrent safe
	switch lvl {
	case 0:
		w.loggerAtomicLevel.SetLevel(zapcore.FatalLevel)
	case 1:
		w.loggerAtomicLevel.SetLevel(zapcore.PanicLevel)
	case 2:
		w.loggerAtomicLevel.SetLevel(zapcore.ErrorLevel)
	case 3:
		w.loggerAtomicLevel.SetLevel(zapcore.WarnLevel)
	case 4:
		w.loggerAtomicLevel.SetLevel(zapcore.InfoLevel)
	case 5:
		w.loggerAtomicLevel.SetLevel(zapcore.DebugLevel)
	default:
		return fmt.Errorf("invalid SecDebugLogLevel value")
	}
	return nil
}

// SetErrorLogCb sets the callback function for error logging
// The errorcallback receives all the error data and some
// helpers to write modsecurity style logs
func (w *Waf) SetErrorLogCb(cb ErrorLogCallback) {
	w.errorLogCb = cb
}

// SetGeoReader is used by directives to assign a geo reader
// This function is not thread safe
func (w *Waf) SetGeoReader(reader geo.Reader) {
	w.geo = reader
}

// Geo returns the geo processor for the current WAF instance
// Geo is nil if the geo processor is not set
// A geo processor requires a Geo plugin to be installed
func (w *Waf) Geo() geo.Reader {
	return w.geo
}
