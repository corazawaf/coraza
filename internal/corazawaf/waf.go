// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	ioutils "github.com/corazawaf/coraza/v3/internal/io"
	stringutils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/internal/sync"
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/types"
)

// ErrorLogCallback is used to set a callback function to log errors
// It is triggered when an error is raised by the WAF
// It contains the severity so the cb can decide to log it or not
type ErrorLogCallback = func(rule types.MatchedRule)

// WAF instance is used to store configurations and rules
// Every web application should have a different WAF instance,
// but you can share an instance if you are ok with sharing
// configurations, rules and logging.
// Transactions and SecLang parser requires a WAF instance
// You can use as many WAF instances as you want, and they are
// concurrent safe
// All WAF instance fields are immutable, if you update any
// of them in runtime you might create concurrency issues
type WAF struct {
	txPool sync.Pool

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
	Logger loggers.DebugLogger

	ErrorLogCb ErrorLogCallback

	// AuditLogWriter is used to write audit logs
	AuditLogWriter loggers.LogWriter
}

// NewTransaction Creates a new initialized transaction for this WAF instance
func (w *WAF) NewTransaction() *Transaction {
	return w.newTransactionWithID(stringutils.RandomString(19))
}

func (w *WAF) NewTransactionWithID(id string) *Transaction {
	if len(strings.TrimSpace(id)) == 0 {
		id = stringutils.RandomString(19)
		w.Logger.Warn("Empty ID passed for new transaction")
	}
	return w.newTransactionWithID(id)
}

// NewTransactionWithID Creates a new initialized transaction for this WAF instance
// Using the specified ID
func (w *WAF) newTransactionWithID(id string) *Transaction {
	tx := w.txPool.Get().(*Transaction)
	tx.id = id
	tx.matchedRules = []types.MatchedRule{}
	tx.interruption = nil
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
	tx.bodyProcessor = nil
	tx.ruleRemoveByID = nil
	tx.ruleRemoveTargetByID = map[int][]ruleVariableParams{}
	tx.Skip = 0
	tx.Capture = false
	tx.stopWatches = map[types.RulePhase]int64{}
	tx.WAF = w
	tx.Timestamp = time.Now().UnixNano()
	tx.audit = false

	// Always non-nil if buffers / collections were already initialized so we don't do any of them
	// based on the presence of RequestBodyBuffer.
	if tx.RequestBodyBuffer == nil {
		tx.RequestBodyBuffer = NewBodyBuffer(types.BodyBufferOptions{
			TmpPath:     w.TmpDir,
			MemoryLimit: w.RequestBodyInMemoryLimit,
		})
		tx.ResponseBodyBuffer = NewBodyBuffer(types.BodyBufferOptions{
			TmpPath:     w.TmpDir,
			MemoryLimit: w.RequestBodyInMemoryLimit,
		})
		tx.variables = *NewTransactionVariables()
		tx.transformationCache = map[transformationKey]*transformationValue{}
	}

	// set capture variables
	for i := 0; i <= 10; i++ {
		is := strconv.Itoa(i)
		tx.variables.tx.Set(is, []string{""})
	}

	// Some defaults
	tx.variables.filesCombinedSize.Set("0")
	tx.variables.urlencodedError.Set("0")
	tx.variables.fullRequestLength.Set("0")
	tx.variables.multipartBoundaryQuoted.Set("0")
	tx.variables.multipartBoundaryWhitespace.Set("0")
	tx.variables.multipartCrlfLfLines.Set("0")
	tx.variables.multipartDataAfter.Set("0")
	tx.variables.multipartDataBefore.Set("0")
	tx.variables.multipartFileLimitExceeded.Set("0")
	tx.variables.multipartHeaderFolding.Set("0")
	tx.variables.multipartInvalidHeaderFolding.Set("0")
	tx.variables.multipartInvalidPart.Set("0")
	tx.variables.multipartInvalidQuoting.Set("0")
	tx.variables.multipartLfLine.Set("0")
	tx.variables.multipartMissingSemicolon.Set("0")
	tx.variables.multipartStrictError.Set("0")
	tx.variables.multipartUnmatchedBoundary.Set("0")
	tx.variables.outboundDataError.Set("0")
	tx.variables.reqbodyError.Set("0")
	tx.variables.reqbodyProcessorError.Set("0")
	tx.variables.requestBodyLength.Set("0")
	tx.variables.duration.Set("0")
	tx.variables.highestSeverity.Set("0")
	tx.variables.uniqueID.Set(tx.id)

	w.Logger.Debug("New transaction created with id %q", tx.id)

	return tx
}

// SetDebugLogPath sets the path for the debug log
// If the path is empty, the debug log will be disabled
// note: this is not thread safe
func (w *WAF) SetDebugLogPath(path string) error {
	if path == "" {
		w.Logger.SetOutput(ioutils.NopCloser(io.Discard))
		return nil
	}

	if path == "/dev/stdout" {
		w.Logger.SetOutput(os.Stdout)
		return nil
	}

	if path == "/dev/stderr" {
		w.Logger.SetOutput(os.Stderr)
		return nil
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		w.Logger.Error("failed to open the file: %s", err.Error())
	}

	w.Logger.SetOutput(f)

	return nil
}

// NewWAF creates a new WAF instance with default variables
func NewWAF() *WAF {
	logger := &stdDebugLogger{
		logger: &log.Logger{},
		Level:  loggers.LogLevelInfo,
	}
	logWriter, err := loggers.GetLogWriter("serial")
	if err != nil {
		logger.Error("error creating serial log writer: %s", err.Error())
	}
	waf := &WAF{
		// Initializing pool for transactions
		txPool:                   sync.NewPool(func() interface{} { return new(Transaction) }),
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
		AuditLogRelevantStatus:   regexp.MustCompile(`.*`),
		RequestBodyAccess:        false,
		Logger:                   logger,
	}
	// We initialize a basic audit log writer that discards output
	if err := logWriter.Init(types.Config{}); err != nil {
		fmt.Println(err)
	}
	if err := waf.SetDebugLogPath(""); err != nil {
		fmt.Println(err)
	}
	waf.Logger.Debug("a new waf instance was created")
	return waf
}

// SetDebugLogLevel changes the debug level of the WAF instance
func (w *WAF) SetDebugLogLevel(lvl int) error {
	// setLevel is concurrent safe
	w.Logger.SetLevel(loggers.LogLevel(lvl))
	return nil
}

// SetErrorLogCb sets the callback function for error logging
// The error callback receives all the error data and some
// helpers to write modsecurity style logs
func (w *WAF) SetErrorLogCb(cb ErrorLogCallback) {
	w.ErrorLogCb = cb
}
