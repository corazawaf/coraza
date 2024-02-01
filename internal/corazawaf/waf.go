// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/auditlog"
	"github.com/corazawaf/coraza/v3/internal/environment"
	stringutils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/internal/sync"
	"github.com/corazawaf/coraza/v3/types"
)

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

	// If true, transactions will have access to the request body
	RequestBodyAccess bool

	// Request body page file limit
	RequestBodyLimit int64

	// Request body in memory limit
	requestBodyInMemoryLimit *int64

	// If true, transactions will have access to the response body
	ResponseBodyAccess bool

	// Response body memory limit
	ResponseBodyLimit int64

	// Defines if rules are going to be evaluated
	RuleEngine types.RuleEngineStatus

	// Responses will only be loaded if mime is listed here
	ResponseBodyMimeTypes []string

	// Web Application id, apps sharing the same id will share persistent collections
	WebAppID string

	// Add significant rule components to audit log
	ComponentNames []string

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

	// Request body in memory limit excluding the size of any files being transported in the request.
	RequestBodyNoFilesLimit int64

	RequestBodyLimitAction types.BodyLimitAction

	ResponseBodyLimitAction types.BodyLimitAction

	ArgumentSeparator string

	// ProducerConnector is used by connectors to identify the producer
	// on audit logs, for example, apache-modcoraza
	ProducerConnector string

	// ProducerConnectorVersion is used by connectors to identify the producer
	// version on audit logs
	ProducerConnectorVersion string

	// Used for the debug logger
	Logger debuglog.Logger

	ErrorLogCb func(rule types.MatchedRule)

	// Audit mode status
	AuditEngine types.AuditEngineStatus

	// Array of logging parts to be used
	AuditLogParts types.AuditLogParts

	// Contains the regular expression for relevant status audit logging
	AuditLogRelevantStatus *regexp.Regexp

	auditLogWriter plugintypes.AuditLogWriter

	// AuditLogWriterConfig is configuration of audit logging, populated by multiple directives and consumed by
	// SecAuditLog.
	AuditLogWriterConfig plugintypes.AuditLogConfig

	auditLogWriterInitialized bool

	// Configures the maximum number of ARGS that will be accepted for processing.
	ArgumentLimit int
}

// Options is used to pass options to the WAF instance
type Options struct {
	ID      string
	Context context.Context
}

// NewTransaction Creates a new initialized transaction for this WAF instance
func (w *WAF) NewTransaction() *Transaction {
	return w.newTransaction(Options{
		ID:      stringutils.RandomString(19),
		Context: context.Background(),
	})
}

// NewTransactionWithOptions Creates a new initialized transaction for this WAF
// instance with the provided options
func (w *WAF) NewTransactionWithOptions(opts Options) *Transaction {
	if opts.ID == "" {
		opts.ID = stringutils.RandomString(19)
	}

	if opts.Context == nil {
		opts.Context = context.Background()
	}

	return w.newTransaction(opts)
}

// NewTransactionWithID Creates a new initialized transaction for this WAF instance
// Using the specified ID
func (w *WAF) newTransaction(opts Options) *Transaction {
	tx := w.txPool.Get().(*Transaction)
	tx.id = opts.ID
	tx.context = opts.Context
	tx.matchedRules = []types.MatchedRule{}
	tx.interruption = nil
	tx.Logdata = "" // Deprecated, this variable is not used. Logdata for each matched rule is stored in the MatchData field.
	tx.SkipAfter = ""
	tx.AuditEngine = w.AuditEngine
	tx.AuditLogParts = w.AuditLogParts
	tx.ForceRequestBodyVariable = false
	tx.RequestBodyAccess = w.RequestBodyAccess
	tx.RequestBodyLimit = int64(w.RequestBodyLimit)
	tx.ResponseBodyAccess = w.ResponseBodyAccess
	tx.ResponseBodyLimit = int64(w.ResponseBodyLimit)
	tx.RuleEngine = w.RuleEngine
	tx.HashEngine = false
	tx.HashEnforcement = false
	tx.lastPhase = 0
	tx.ruleRemoveByID = nil
	tx.ruleRemoveTargetByID = map[int][]ruleVariableParams{}
	tx.Skip = 0
	tx.AllowType = 0
	tx.Capture = false
	tx.stopWatches = map[types.RulePhase]int64{}
	tx.WAF = w
	tx.debugLogger = w.Logger.With(debuglog.Str("tx_id", tx.id))
	tx.Timestamp = time.Now().UnixNano()
	tx.audit = false

	// Always non-nil if buffers / collections were already initialized so we don't do any of them
	// based on the presence of RequestBodyBuffer.
	if tx.requestBodyBuffer == nil {
		// if no requestBodyInMemoryLimit has been set we default to the
		var requestBodyInMemoryLimit int64 = w.RequestBodyLimit
		if w.requestBodyInMemoryLimit != nil {
			requestBodyInMemoryLimit = int64(*w.requestBodyInMemoryLimit)
		}

		tx.requestBodyBuffer = NewBodyBuffer(types.BodyBufferOptions{
			TmpPath:     w.TmpDir,
			MemoryLimit: requestBodyInMemoryLimit,
			Limit:       w.RequestBodyLimit,
		})

		tx.responseBodyBuffer = NewBodyBuffer(types.BodyBufferOptions{
			TmpPath: w.TmpDir,
			// the response body is just buffered in memory. Therefore, Limit and MemoryLimit are equal.
			MemoryLimit: w.ResponseBodyLimit,
			Limit:       w.ResponseBodyLimit,
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
	tx.variables.multipartDataAfter.Set("0")
	tx.variables.outboundDataError.Set("0")
	tx.variables.reqbodyError.Set("0")
	tx.variables.reqbodyProcessorError.Set("0")
	tx.variables.requestBodyLength.Set("0")
	tx.variables.duration.Set("0")
	tx.variables.highestSeverity.Set("0")
	tx.variables.uniqueID.Set(tx.id)

	tx.debugLogger.Debug().Msg("Transaction started")

	return tx
}

func resolveLogPath(path string) (io.Writer, error) {
	if path == "" {
		return io.Discard, nil
	}

	if path == "/dev/stdout" {
		return os.Stdout, nil
	}

	if path == "/dev/stderr" {
		return os.Stderr, nil
	}

	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
}

// SetDebugLogPath sets the path for the debug log
// If the path is empty, the debug log will be disabled
// note: this is not thread safe
func (w *WAF) SetDebugLogPath(path string) error {
	o, err := resolveLogPath(path)
	if err != nil {
		return err
	}

	w.SetDebugLogOutput(o)
	return nil
}

const _1gb = 1073741824

// NewWAF creates a new WAF instance with default variables
func NewWAF() *WAF {
	logger := debuglog.Noop()

	logWriter, err := auditlog.GetWriter("serial")
	if err != nil {
		logger.Error().
			Err(err).
			Msg("error creating serial log writer")
	}

	waf := &WAF{
		// Initializing pool for transactions
		txPool: sync.NewPool(func() interface{} { return new(Transaction) }),
		// These defaults are unavoidable as they are zero values for the variables
		RuleEngine:                types.RuleEngineOn,
		RequestBodyAccess:         false,
		RequestBodyLimit:          _1gb,
		ResponseBodyAccess:        false,
		ResponseBodyLimit:         _1gb,
		auditLogWriter:            logWriter,
		auditLogWriterInitialized: false,
		AuditLogWriterConfig:      auditlog.NewConfig(),
		AuditLogParts: types.AuditLogParts{
			types.AuditLogPartRequestHeaders,
			types.AuditLogPartRequestBody,
			types.AuditLogPartResponseHeaders,
			types.AuditLogPartAuditLogTrailer,
		},
		Logger:        logger,
		ArgumentLimit: 1000,
	}

	if environment.HasAccessToFS {
		waf.TmpDir = os.TempDir()
	}

	waf.Logger.Debug().Msg("A new WAF instance was created")
	return waf
}

func (w *WAF) SetDebugLogOutput(wr io.Writer) {
	w.Logger = w.Logger.WithOutput(wr)
}

// SetDebugLogLevel changes the debug level of the WAF instance
func (w *WAF) SetDebugLogLevel(lvl debuglog.Level) error {
	if !lvl.Valid() {
		return errors.New("invalid log level")
	}

	w.Logger = w.Logger.WithLevel(lvl)
	return nil
}

// SetAuditLogWriter sets the audit log writer
func (w *WAF) SetAuditLogWriter(alw plugintypes.AuditLogWriter) {
	w.auditLogWriter = alw
}

// AuditLogWriter returns the audit log writer. If the writer is not initialized,
// it will be initialized
func (w *WAF) AuditLogWriter() plugintypes.AuditLogWriter {
	if !w.auditLogWriterInitialized {
		if err := w.auditLogWriter.Init(w.AuditLogWriterConfig); err != nil {
			w.Logger.Error().Err(err).Msg("Failed to initialize audit log")
		}
	}

	return w.auditLogWriter
}

// InitAuditLogWriter initializes the audit log writer. If the writer is already
// initialized, it will return an error as initializing the audit log writer twice
// seems to be a bug.
func (w *WAF) InitAuditLogWriter() error {
	if w.auditLogWriterInitialized {
		return errors.New("audit log writer already initialized")
	}

	if err := w.auditLogWriter.Init(w.AuditLogWriterConfig); err != nil {
		return err
	}

	w.auditLogWriterInitialized = true

	return nil
}

// SetErrorCallback sets the callback function for error logging
// The error callback receives all the error data and some
// helpers to write modsecurity style logs
func (w *WAF) SetErrorCallback(cb func(rule types.MatchedRule)) {
	w.ErrorLogCb = cb
}

func (w *WAF) SetRequestBodyInMemoryLimit(limit int64) {
	w.requestBodyInMemoryLimit = &limit
}

func (w *WAF) RequestBodyInMemoryLimit() *int64 {
	return w.requestBodyInMemoryLimit
}

// Validate validates the waf after all the settings have been set.
func (w *WAF) Validate() error {
	if w.RequestBodyLimit <= 0 {
		return errors.New("request body limit should be bigger than 0")
	}

	if w.RequestBodyLimit > _1gb {
		return errors.New("request body limit should be at most 1GB")
	}

	if w.requestBodyInMemoryLimit != nil {
		if *w.requestBodyInMemoryLimit <= 0 {
			return errors.New("request body memory limit should be bigger than 0")
		}

		if w.RequestBodyLimit < *w.requestBodyInMemoryLimit {
			return fmt.Errorf("request body limit should be at least the memory limit")
		}
	}

	if w.ResponseBodyLimit <= 0 {
		return errors.New("response body limit should be bigger than 0")
	}

	if w.ResponseBodyLimit > _1gb {
		return errors.New("response body limit should be at most 1GB")
	}

	if w.ArgumentLimit <= 0 {
		return errors.New("argument limit should be bigger than 0")
	}

	return nil
}
