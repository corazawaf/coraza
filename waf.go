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
	utils "github.com/jptosso/coraza-waf/v2/utils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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
	Rules ruleGroup

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
	WebAppId string

	// Deprecated: ComponentSignature
	ComponentSignature string

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

	// Sensor ID tu, must be unique per cluster nodes
	SensorId string

	// Path to store data files (ex. cache)
	DataDir string

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

	geo geo.GeoReader

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
		Id:                   utils.RandomString(19),
		Timestamp:            time.Now().UnixNano(),
		AuditEngine:          w.AuditEngine,
		AuditLogParts:        w.AuditLogParts,
		RuleEngine:           w.RuleEngine,
		RequestBodyAccess:    true,
		RequestBodyLimit:     134217728,
		ResponseBodyAccess:   true,
		ResponseBodyLimit:    524288,
		ruleRemoveTargetById: map[int][]ruleVariableParams{},
		ruleRemoveById:       []int{},
		StopWatches:          map[types.RulePhase]int{},
		RequestBodyBuffer:    NewBodyReader(w.TmpDir, w.RequestBodyInMemoryLimit),
		ResponseBodyBuffer:   NewBodyReader(w.TmpDir, w.RequestBodyInMemoryLimit),
	}
	for i := range tx.collections {
		tx.collections[i] = NewCollection(variables.RuleVariable(i).Name())
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
		variables.UniqueID:                      tx.Id,
		// TODO single variables must be defaulted to empty string
		variables.RemoteAddr: "",
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

	w.Logger.Debug("new transaction created", zap.String("event", "NEW_TRANSACTION"), zap.String("txid", tx.Id))

	return tx
}

// AddAuditLogger creates a new logger for the current WAF instance
// You may add as many loggers as you want
// Keep in mind loggers may lock go routines
func (w *Waf) SetAuditLogger(engine string) error {
	return w.auditLogger.SetWriter(engine)
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

// Logger returns the initiated loggers
// Coraza supports unlimited loggers, so you can write for example
// to syslog and a local drive at the same time
// AuditLogger() returns nil if the audit logger is not set
// Please try to use a nil logger...
func (w *Waf) AuditLogger() *loggers.Logger {
	return w.auditLogger
}

// NewWaf creates a new WAF instance with default variables
// TODO there is much to fix here:
// - what are the default
func NewWaf() *Waf {
	//default: us-ascii
	atom := zap.NewAtomicLevel()
	atom.SetLevel(zap.InfoLevel)
	encoderCfg := zap.NewProductionEncoderConfig()
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.Lock(os.Stdout),
		atom,
	))
	al, err := loggers.NewAuditLogger()
	if err != nil {
		// TODO this error is wrong
		logger.Fatal("failed to create audit logger", zap.Error(err))
	}
	waf := &Waf{
		ArgumentSeparator:        "&",
		AuditEngine:              types.AuditEngineOff,
		AuditLogParts:            []rune("ABCFHZ"),
		auditLogger:              al,
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
		Logger:                   logger,
		loggerAtomicLevel:        &atom,
		AuditLogRelevantStatus:   regexp.MustCompile(`.*`),
	}
	logger.Debug("a new waf instance was created")
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

func (w *Waf) SetErrorLogCb(cb ErrorLogCallback) {
	w.errorLogCb = cb
}

func (w *Waf) SetGeoReader(reader geo.GeoReader) {
	w.geo = reader
}

func (w *Waf) Geo() geo.GeoReader {
	return w.geo
}
