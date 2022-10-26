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

	"github.com/corazawaf/coraza/v3/collection"
	ioutils "github.com/corazawaf/coraza/v3/internal/io"
	stringutils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/internal/sync"
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Initializing pool for transactions
var transactionPool = sync.NewPool(func() interface{} { return new(Transaction) })

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
	tx := transactionPool.Get().(*Transaction)
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
		tx.Collections = make([]collection.Collection, types.VariablesCount)
		tx.variables.urlencodedError = collection.NewSimple(variables.UrlencodedError)
		tx.Collections[variables.UrlencodedError] = tx.variables.urlencodedError
		tx.variables.responseContentType = collection.NewSimple(variables.ResponseContentType)
		tx.Collections[variables.ResponseContentType] = tx.variables.responseContentType
		tx.variables.uniqueID = collection.NewSimple(variables.UniqueID)
		tx.Collections[variables.UniqueID] = tx.variables.uniqueID
		tx.variables.authType = collection.NewSimple(variables.AuthType)
		tx.Collections[variables.AuthType] = tx.variables.authType
		tx.variables.filesCombinedSize = collection.NewSimple(variables.FilesCombinedSize)
		tx.Collections[variables.FilesCombinedSize] = tx.variables.filesCombinedSize
		tx.variables.fullRequest = collection.NewSimple(variables.FullRequest)
		tx.Collections[variables.FullRequest] = tx.variables.fullRequest
		tx.variables.fullRequestLength = collection.NewSimple(variables.FullRequestLength)
		tx.Collections[variables.FullRequestLength] = tx.variables.fullRequestLength
		tx.variables.inboundDataError = collection.NewSimple(variables.InboundDataError)
		tx.Collections[variables.InboundDataError] = tx.variables.inboundDataError
		tx.variables.matchedVar = collection.NewSimple(variables.MatchedVar)
		tx.Collections[variables.MatchedVar] = tx.variables.matchedVar
		tx.variables.matchedVarName = collection.NewSimple(variables.MatchedVarName)
		tx.Collections[variables.MatchedVarName] = tx.variables.matchedVarName
		tx.variables.multipartBoundaryQuoted = collection.NewSimple(variables.MultipartBoundaryQuoted)
		tx.Collections[variables.MultipartBoundaryQuoted] = tx.variables.multipartBoundaryQuoted
		tx.variables.multipartBoundaryWhitespace = collection.NewSimple(variables.MultipartBoundaryWhitespace)
		tx.Collections[variables.MultipartBoundaryWhitespace] = tx.variables.multipartBoundaryWhitespace
		tx.variables.multipartCrlfLfLines = collection.NewSimple(variables.MultipartCrlfLfLines)
		tx.Collections[variables.MultipartCrlfLfLines] = tx.variables.multipartCrlfLfLines
		tx.variables.multipartDataAfter = collection.NewSimple(variables.MultipartDataAfter)
		tx.Collections[variables.MultipartDataAfter] = tx.variables.multipartDataAfter
		tx.variables.multipartDataBefore = collection.NewSimple(variables.MultipartDataBefore)
		tx.Collections[variables.MultipartDataBefore] = tx.variables.multipartDataBefore
		tx.variables.multipartFileLimitExceeded = collection.NewSimple(variables.MultipartFileLimitExceeded)
		tx.Collections[variables.MultipartFileLimitExceeded] = tx.variables.multipartFileLimitExceeded
		tx.variables.multipartHeaderFolding = collection.NewSimple(variables.MultipartHeaderFolding)
		tx.Collections[variables.MultipartHeaderFolding] = tx.variables.multipartHeaderFolding
		tx.variables.multipartInvalidHeaderFolding = collection.NewSimple(variables.MultipartInvalidHeaderFolding)
		tx.Collections[variables.MultipartInvalidHeaderFolding] = tx.variables.multipartInvalidHeaderFolding
		tx.variables.multipartInvalidPart = collection.NewSimple(variables.MultipartInvalidPart)
		tx.Collections[variables.MultipartInvalidPart] = tx.variables.multipartInvalidPart
		tx.variables.multipartInvalidQuoting = collection.NewSimple(variables.MultipartInvalidQuoting)
		tx.Collections[variables.MultipartInvalidQuoting] = tx.variables.multipartInvalidQuoting
		tx.variables.multipartLfLine = collection.NewSimple(variables.MultipartLfLine)
		tx.Collections[variables.MultipartLfLine] = tx.variables.multipartLfLine
		tx.variables.multipartMissingSemicolon = collection.NewSimple(variables.MultipartMissingSemicolon)
		tx.Collections[variables.MultipartMissingSemicolon] = tx.variables.multipartMissingSemicolon
		tx.variables.multipartStrictError = collection.NewSimple(variables.MultipartStrictError)
		tx.Collections[variables.MultipartStrictError] = tx.variables.multipartStrictError
		tx.variables.multipartUnmatchedBoundary = collection.NewSimple(variables.MultipartUnmatchedBoundary)
		tx.Collections[variables.MultipartUnmatchedBoundary] = tx.variables.multipartUnmatchedBoundary
		tx.variables.outboundDataError = collection.NewSimple(variables.OutboundDataError)
		tx.Collections[variables.OutboundDataError] = tx.variables.outboundDataError
		tx.variables.pathInfo = collection.NewSimple(variables.PathInfo)
		tx.Collections[variables.PathInfo] = tx.variables.pathInfo
		tx.variables.queryString = collection.NewSimple(variables.QueryString)
		tx.Collections[variables.QueryString] = tx.variables.queryString
		tx.variables.remoteAddr = collection.NewSimple(variables.RemoteAddr)
		tx.Collections[variables.RemoteAddr] = tx.variables.remoteAddr
		tx.variables.remoteHost = collection.NewSimple(variables.RemoteHost)
		tx.Collections[variables.RemoteHost] = tx.variables.remoteHost
		tx.variables.remotePort = collection.NewSimple(variables.RemotePort)
		tx.Collections[variables.RemotePort] = tx.variables.remotePort
		tx.variables.reqbodyError = collection.NewSimple(variables.ReqbodyError)
		tx.Collections[variables.ReqbodyError] = tx.variables.reqbodyError
		tx.variables.reqbodyErrorMsg = collection.NewSimple(variables.ReqbodyErrorMsg)
		tx.Collections[variables.ReqbodyErrorMsg] = tx.variables.reqbodyErrorMsg
		tx.variables.reqbodyProcessorError = collection.NewSimple(variables.ReqbodyProcessorError)
		tx.Collections[variables.ReqbodyProcessorError] = tx.variables.reqbodyProcessorError
		tx.variables.reqbodyProcessorErrorMsg = collection.NewSimple(variables.ReqbodyProcessorErrorMsg)
		tx.Collections[variables.ReqbodyProcessorErrorMsg] = tx.variables.reqbodyProcessorErrorMsg
		tx.variables.reqbodyProcessor = collection.NewSimple(variables.ReqbodyProcessor)
		tx.Collections[variables.ReqbodyProcessor] = tx.variables.reqbodyProcessor
		tx.variables.requestBasename = collection.NewSimple(variables.RequestBasename)
		tx.Collections[variables.RequestBasename] = tx.variables.requestBasename
		tx.variables.requestBody = collection.NewSimple(variables.RequestBody)
		tx.Collections[variables.RequestBody] = tx.variables.requestBody
		tx.variables.requestBodyLength = collection.NewSimple(variables.RequestBodyLength)
		tx.Collections[variables.RequestBodyLength] = tx.variables.requestBodyLength
		tx.variables.requestFilename = collection.NewSimple(variables.RequestFilename)
		tx.Collections[variables.RequestFilename] = tx.variables.requestFilename
		tx.variables.requestLine = collection.NewSimple(variables.RequestLine)
		tx.Collections[variables.RequestLine] = tx.variables.requestLine
		tx.variables.requestMethod = collection.NewSimple(variables.RequestMethod)
		tx.Collections[variables.RequestMethod] = tx.variables.requestMethod
		tx.variables.requestProtocol = collection.NewSimple(variables.RequestProtocol)
		tx.Collections[variables.RequestProtocol] = tx.variables.requestProtocol
		tx.variables.requestURI = collection.NewSimple(variables.RequestURI)
		tx.Collections[variables.RequestURI] = tx.variables.requestURI
		tx.variables.requestURIRaw = collection.NewSimple(variables.RequestURIRaw)
		tx.Collections[variables.RequestURIRaw] = tx.variables.requestURIRaw
		tx.variables.responseBody = collection.NewSimple(variables.ResponseBody)
		tx.Collections[variables.ResponseBody] = tx.variables.responseBody
		tx.variables.responseContentLength = collection.NewSimple(variables.ResponseContentLength)
		tx.Collections[variables.ResponseContentLength] = tx.variables.responseContentLength
		tx.variables.responseProtocol = collection.NewSimple(variables.ResponseProtocol)
		tx.Collections[variables.ResponseProtocol] = tx.variables.responseProtocol
		tx.variables.responseStatus = collection.NewSimple(variables.ResponseStatus)
		tx.Collections[variables.ResponseStatus] = tx.variables.responseStatus
		tx.variables.serverAddr = collection.NewSimple(variables.ServerAddr)
		tx.Collections[variables.ServerAddr] = tx.variables.serverAddr
		tx.variables.serverName = collection.NewSimple(variables.ServerName)
		tx.Collections[variables.ServerName] = tx.variables.serverName
		tx.variables.serverPort = collection.NewSimple(variables.ServerPort)
		tx.Collections[variables.ServerPort] = tx.variables.serverPort
		tx.variables.sessionID = collection.NewSimple(variables.Sessionid)
		tx.Collections[variables.Sessionid] = tx.variables.sessionID
		tx.variables.highestSeverity = collection.NewSimple(variables.HighestSeverity)
		tx.Collections[variables.HighestSeverity] = tx.variables.highestSeverity
		tx.variables.statusLine = collection.NewSimple(variables.StatusLine)
		tx.Collections[variables.StatusLine] = tx.variables.statusLine
		tx.variables.inboundErrorData = collection.NewSimple(variables.InboundErrorData)
		tx.Collections[variables.InboundErrorData] = tx.variables.inboundErrorData
		tx.variables.duration = collection.NewSimple(variables.Duration)
		tx.Collections[variables.Duration] = tx.variables.duration
		tx.variables.responseHeadersNames = collection.NewMap(variables.ResponseHeadersNames)
		tx.Collections[variables.ResponseHeadersNames] = tx.variables.responseHeadersNames
		tx.variables.requestHeadersNames = collection.NewMap(variables.RequestHeadersNames)
		tx.Collections[variables.RequestHeadersNames] = tx.variables.requestHeadersNames
		tx.variables.userID = collection.NewSimple(variables.Userid)
		tx.Collections[variables.Userid] = tx.variables.userID

		tx.variables.argsGet = collection.NewMap(variables.ArgsGet)
		tx.Collections[variables.ArgsGet] = tx.variables.argsGet
		tx.variables.argsPost = collection.NewMap(variables.ArgsPost)
		tx.Collections[variables.ArgsPost] = tx.variables.argsPost
		tx.variables.argsPath = collection.NewMap(variables.ArgsPath)
		tx.Collections[variables.ArgsPath] = tx.variables.argsPath
		tx.variables.filesSizes = collection.NewMap(variables.FilesSizes)
		tx.Collections[variables.FilesSizes] = tx.variables.filesSizes
		tx.variables.filesTmpContent = collection.NewMap(variables.FilesTmpContent)
		tx.Collections[variables.FilesTmpContent] = tx.variables.filesTmpContent
		tx.variables.multipartFilename = collection.NewMap(variables.MultipartFilename)
		tx.Collections[variables.MultipartFilename] = tx.variables.multipartFilename
		tx.variables.multipartName = collection.NewMap(variables.MultipartName)
		tx.Collections[variables.MultipartName] = tx.variables.multipartName
		tx.variables.matchedVars = collection.NewMap(variables.MatchedVars)
		tx.Collections[variables.MatchedVars] = tx.variables.matchedVars
		tx.variables.requestCookies = collection.NewMap(variables.RequestCookies)
		tx.Collections[variables.RequestCookies] = tx.variables.requestCookies
		tx.variables.requestHeaders = collection.NewMap(variables.RequestHeaders)
		tx.Collections[variables.RequestHeaders] = tx.variables.requestHeaders
		tx.variables.responseHeaders = collection.NewMap(variables.ResponseHeaders)
		tx.Collections[variables.ResponseHeaders] = tx.variables.responseHeaders
		tx.variables.geo = collection.NewMap(variables.Geo)
		tx.Collections[variables.Geo] = tx.variables.geo
		tx.variables.tx = collection.NewMap(variables.TX)
		tx.Collections[variables.TX] = tx.variables.tx
		tx.variables.rule = collection.NewMap(variables.Rule)
		tx.Collections[variables.Rule] = tx.variables.rule
		tx.variables.env = collection.NewMap(variables.Env)
		tx.Collections[variables.Env] = tx.variables.env
		tx.variables.ip = collection.NewMap(variables.IP)
		tx.Collections[variables.IP] = tx.variables.ip
		tx.variables.files = collection.NewMap(variables.Files)
		tx.Collections[variables.Files] = tx.variables.files
		tx.variables.matchedVarsNames = collection.NewMap(variables.MatchedVarsNames)
		tx.Collections[variables.MatchedVarsNames] = tx.variables.matchedVarsNames
		tx.variables.filesNames = collection.NewMap(variables.FilesNames)
		tx.Collections[variables.FilesNames] = tx.variables.filesNames
		tx.variables.filesTmpNames = collection.NewMap(variables.FilesTmpNames)
		tx.Collections[variables.FilesTmpNames] = tx.variables.filesTmpNames
		tx.variables.requestCookiesNames = collection.NewMap(variables.RequestCookiesNames)
		tx.Collections[variables.RequestCookiesNames] = tx.variables.requestCookiesNames
		tx.variables.responseXML = collection.NewMap(variables.ResponseXML)
		tx.Collections[variables.ResponseXML] = tx.variables.responseXML
		tx.variables.requestXML = collection.NewMap(variables.RequestXML)
		tx.Collections[variables.RequestXML] = tx.variables.requestXML
		tx.variables.multipartPartHeaders = collection.NewMap(variables.MultipartPartHeaders)
		tx.Collections[variables.MultipartPartHeaders] = tx.variables.multipartPartHeaders

		tx.variables.argsCombinedSize = collection.NewCollectionSizeProxy(variables.ArgsCombinedSize, tx.variables.argsGet, tx.variables.argsPost)
		tx.Collections[variables.ArgsCombinedSize] = tx.variables.argsCombinedSize

		// XML is a pointer to RequestXML
		tx.variables.xml = tx.variables.requestXML
		tx.Collections[variables.XML] = tx.variables.requestXML
		tx.variables.args = collection.NewProxy(
			variables.Args,
			tx.variables.argsGet,
			tx.variables.argsPost,
			tx.variables.argsPath,
		)
		tx.Collections[variables.Args] = tx.variables.args

		tx.variables.argsNames = collection.NewTranslationProxy(
			variables.ArgsNames,
			tx.variables.argsGet,
			tx.variables.argsPost,
			tx.variables.argsPath,
		)
		tx.Collections[variables.ArgsNames] = tx.variables.argsNames
		tx.variables.argsGetNames = collection.NewTranslationProxy(
			variables.ArgsGetNames,
			tx.variables.argsGet,
		)
		tx.Collections[variables.ArgsGetNames] = tx.variables.argsGetNames
		tx.variables.argsPostNames = collection.NewTranslationProxy(
			variables.ArgsPostNames,
			tx.variables.argsPost,
		)
		tx.Collections[variables.ArgsPostNames] = tx.variables.argsPostNames
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
