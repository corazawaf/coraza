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

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/corazawaf/coraza/v2/loggers"
	"github.com/corazawaf/coraza/v2/types"
	"github.com/corazawaf/coraza/v2/types/variables"
	utils "github.com/corazawaf/coraza/v2/utils/strings"
)

// Initializing pool for transactions
var transactionPool = sync.Pool{
	// New optionally specifies a function to generate
	// a value when Get would otherwise return nil.
	New: func() interface{} { return new(Transaction) },
}

// ErrorLogCallback is used to set a callback function to log errors
// It is triggered when an error is raised by the WAF
// It contains the severity so the cb can decide to log it or not
type ErrorLogCallback = func(rule MatchedRule)

// Waf instance is used to store configurations and rules
// Every web application should have a different Waf instance,
// but you can share an instance if you are ok with sharing
// configurations, rules and logging.
// Transactions and SecLang parser requires a Waf instance
// You can use as many Waf instances as you want, and they are
// concurrent safe
// All Waf instance fields are immutable, if you update any
// of them in runtime you might create concurrency issues
type Waf struct {
	// ruleGroup object, contains all rules and helpers
	Rules RuleGroup

	// Audit mode status
	AuditEngine types.AuditEngineStatus

	// Array of logging parts to be used
	AuditLogParts types.AuditLogParts

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

	// If true, the WAF will store the uploaded files in the UploadDir
	// directory
	UploadKeepFiles bool
	// UploadFileMode instructs the waf to set the file mode for uploaded files
	UploadFileMode fs.FileMode
	// UploadFileLimit is the maximum size of the uploaded file to be stored
	UploadFileLimit int
	// UploadDir is the directory where the uploaded files will be stored
	UploadDir string

	RequestBodyNoFilesLimit int64

	RequestBodyLimitAction types.RequestBodyLimitAction

	ArgumentSeparator string

	// ProducerConnector is used by connectors to identify the producer
	// on audit logs, for example, apache-modcoraza
	ProducerConnector string
	// ProducerConnectorVersion is used by connectors to identify the producer
	// version on audit logs
	ProducerConnectorVersion string

	// Used for the debug logger
	Logger *zap.Logger

	// Used to allow switching the debug level during runtime
	// ctl cannot switch use it as it will update de lvl
	// for the whole Waf instance
	loggerAtomicLevel *zap.AtomicLevel

	errorLogCb ErrorLogCallback

	// AuditLogWriter is used to write audit logs
	AuditLogWriter loggers.LogWriter
}

// NewTransaction Creates a new initialized transaction for this WAF instance
func (w *Waf) NewTransaction() *Transaction {
	tx := transactionPool.Get().(*Transaction)
	tx.ID = utils.SafeRandom(19)
	tx.MatchedRules = []MatchedRule{}
	tx.Interruption = nil
	tx.collections = [types.VariablesCount]*Collection{}
	tx.Logdata = ""
	tx.SkipAfter = ""
	tx.AuditEngine = w.AuditEngine
	tx.AuditLogParts = w.AuditLogParts
	tx.ForceRequestBodyVariable = false
	tx.RequestBodyAccess = w.RequestBodyAccess
	tx.RequestBodyLimit = w.RequestBodyLimit
	tx.ResponseBodyAccess = w.ResponseBodyAccess
	tx.ResponseBodyLimit = w.ResponseBodyLimit
	tx.RuleEngine = w.RuleEngine
	tx.HashEngine = false
	tx.HashEnforcement = false
	tx.LastPhase = 0
	tx.RequestBodyBuffer = NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     w.TmpDir,
		MemoryLimit: w.RequestBodyInMemoryLimit,
	})
	tx.ResponseBodyBuffer = NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     w.TmpDir,
		MemoryLimit: w.RequestBodyInMemoryLimit,
	})
	tx.bodyProcessor = nil
	tx.ruleRemoveByID = []int{}
	tx.ruleRemoveTargetByID = map[int][]ruleVariableParams{}
	tx.Skip = 0
	tx.Capture = false
	tx.stopWatches = map[types.RulePhase]int64{}
	tx.Waf = w
	tx.Timestamp = time.Now().UnixNano()
	tx.audit = false

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
		// TODO others
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

// SetDebugLogPath sets the path for the debug log
// If the path is empty, the debug log will be disabled
// note: this is not thread safe
func (w *Waf) SetDebugLogPath(path string) error {
	cfg := zap.NewProductionConfig()
	// sampling would make us loose some debug logs
	cfg.Sampling = nil
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

// NewWaf creates a new WAF instance with default variables
func NewWaf() *Waf {
	atom := zap.NewAtomicLevel()
	atom.SetLevel(zap.FatalLevel)
	logWriter, _ := loggers.GetLogWriter("serial")
	waf := &Waf{
		ArgumentSeparator:        "&",
		AuditLogWriter:           logWriter,
		AuditEngine:              types.AuditEngineOff,
		AuditLogParts:            types.AuditLogParts("ABCFHZ"),
		RequestBodyInMemoryLimit: 131072,
		RequestBodyLimit:         134217728, // 10mb
		ResponseBodyMimeTypes:    []string{"text/html", "text/plain"},
		ResponseBodyLimit:        524288,
		ResponseBodyAccess:       false,
		RuleEngine:               types.RuleEngineOn,
		Rules:                    NewRuleGroup(),
		TmpDir:                   "/tmp",
		loggerAtomicLevel:        &atom,
		AuditLogRelevantStatus:   regexp.MustCompile(`.*`),
		RequestBodyAccess:        false,
	}
	// We initialize a basic audit log writer to /dev/null
	if err := logWriter.Init(types.Config{}); err != nil {
		fmt.Println(err)
	}
	if err := waf.SetDebugLogPath("/dev/null"); err != nil {
		fmt.Println(err)
	}
	waf.Logger.Debug("a new waf instance was created")
	return waf
}

// SetDebugLogLevel changes the debug level of the Waf instance
func (w *Waf) SetDebugLogLevel(lvl int) error {
	// setLevel is concurrent safe
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
// The error callback receives all the error data and some
// helpers to write modsecurity style logs
func (w *Waf) SetErrorLogCb(cb ErrorLogCallback) {
	w.errorLogCb = cb
}
