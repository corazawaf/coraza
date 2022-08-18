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
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/collection"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
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
type ErrorLogCallback = func(rule types.MatchedRule)

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
	Logger DebugLogger

	errorLogCb ErrorLogCallback

	// AuditLogWriter is used to write audit logs
	AuditLogWriter loggers.LogWriter
}

// NewTransaction Creates a new initialized transaction for this WAF instance
func (w *Waf) NewTransaction(ctx context.Context) *Transaction {
	tx := transactionPool.Get().(*Transaction)
	tx.ID = utils.SafeRandom(19)
	tx.MatchedRules = []types.MatchedRule{}
	tx.Interruption = nil
	tx.Collections = [types.VariablesCount]collection.Collection{}
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

	tx.Variables.UrlencodedError = collection.NewSimple(variables.UrlencodedError)
	tx.Collections[variables.UrlencodedError] = tx.Variables.UrlencodedError
	tx.Variables.ResponseContentType = collection.NewSimple(variables.ResponseContentType)
	tx.Collections[variables.ResponseContentType] = tx.Variables.ResponseContentType
	tx.Variables.UniqueID = collection.NewSimple(variables.UniqueID)
	tx.Collections[variables.UniqueID] = tx.Variables.UniqueID
	tx.Variables.AuthType = collection.NewSimple(variables.AuthType)
	tx.Collections[variables.AuthType] = tx.Variables.AuthType
	tx.Variables.FilesCombinedSize = collection.NewSimple(variables.FilesCombinedSize)
	tx.Collections[variables.FilesCombinedSize] = tx.Variables.FilesCombinedSize
	tx.Variables.FullRequest = collection.NewSimple(variables.FullRequest)
	tx.Collections[variables.FullRequest] = tx.Variables.FullRequest
	tx.Variables.FullRequestLength = collection.NewSimple(variables.FullRequestLength)
	tx.Collections[variables.FullRequestLength] = tx.Variables.FullRequestLength
	tx.Variables.InboundDataError = collection.NewSimple(variables.InboundDataError)
	tx.Collections[variables.InboundDataError] = tx.Variables.InboundDataError
	tx.Variables.MatchedVar = collection.NewSimple(variables.MatchedVar)
	tx.Collections[variables.MatchedVar] = tx.Variables.MatchedVar
	tx.Variables.MatchedVarName = collection.NewSimple(variables.MatchedVarName)
	tx.Collections[variables.MatchedVarName] = tx.Variables.MatchedVarName
	tx.Variables.MultipartBoundaryQuoted = collection.NewSimple(variables.MultipartBoundaryQuoted)
	tx.Collections[variables.MultipartBoundaryQuoted] = tx.Variables.MultipartBoundaryQuoted
	tx.Variables.MultipartBoundaryWhitespace = collection.NewSimple(variables.MultipartBoundaryWhitespace)
	tx.Collections[variables.MultipartBoundaryWhitespace] = tx.Variables.MultipartBoundaryWhitespace
	tx.Variables.MultipartCrlfLfLines = collection.NewSimple(variables.MultipartCrlfLfLines)
	tx.Collections[variables.MultipartCrlfLfLines] = tx.Variables.MultipartCrlfLfLines
	tx.Variables.MultipartDataAfter = collection.NewSimple(variables.MultipartDataAfter)
	tx.Collections[variables.MultipartDataAfter] = tx.Variables.MultipartDataAfter
	tx.Variables.MultipartDataBefore = collection.NewSimple(variables.MultipartDataBefore)
	tx.Collections[variables.MultipartDataBefore] = tx.Variables.MultipartDataBefore
	tx.Variables.MultipartFileLimitExceeded = collection.NewSimple(variables.MultipartFileLimitExceeded)
	tx.Collections[variables.MultipartFileLimitExceeded] = tx.Variables.MultipartFileLimitExceeded
	tx.Variables.MultipartHeaderFolding = collection.NewSimple(variables.MultipartHeaderFolding)
	tx.Collections[variables.MultipartHeaderFolding] = tx.Variables.MultipartHeaderFolding
	tx.Variables.MultipartInvalidHeaderFolding = collection.NewSimple(variables.MultipartInvalidHeaderFolding)
	tx.Collections[variables.MultipartInvalidHeaderFolding] = tx.Variables.MultipartInvalidHeaderFolding
	tx.Variables.MultipartInvalidPart = collection.NewSimple(variables.MultipartInvalidPart)
	tx.Collections[variables.MultipartInvalidPart] = tx.Variables.MultipartInvalidPart
	tx.Variables.MultipartInvalidQuoting = collection.NewSimple(variables.MultipartInvalidQuoting)
	tx.Collections[variables.MultipartInvalidQuoting] = tx.Variables.MultipartInvalidQuoting
	tx.Variables.MultipartLfLine = collection.NewSimple(variables.MultipartLfLine)
	tx.Collections[variables.MultipartLfLine] = tx.Variables.MultipartLfLine
	tx.Variables.MultipartMissingSemicolon = collection.NewSimple(variables.MultipartMissingSemicolon)
	tx.Collections[variables.MultipartMissingSemicolon] = tx.Variables.MultipartMissingSemicolon
	tx.Variables.MultipartStrictError = collection.NewSimple(variables.MultipartStrictError)
	tx.Collections[variables.MultipartStrictError] = tx.Variables.MultipartStrictError
	tx.Variables.MultipartUnmatchedBoundary = collection.NewSimple(variables.MultipartUnmatchedBoundary)
	tx.Collections[variables.MultipartUnmatchedBoundary] = tx.Variables.MultipartUnmatchedBoundary
	tx.Variables.OutboundDataError = collection.NewSimple(variables.OutboundDataError)
	tx.Collections[variables.OutboundDataError] = tx.Variables.OutboundDataError
	tx.Variables.PathInfo = collection.NewSimple(variables.PathInfo)
	tx.Collections[variables.PathInfo] = tx.Variables.PathInfo
	tx.Variables.QueryString = collection.NewSimple(variables.QueryString)
	tx.Collections[variables.QueryString] = tx.Variables.QueryString
	tx.Variables.RemoteAddr = collection.NewSimple(variables.RemoteAddr)
	tx.Collections[variables.RemoteAddr] = tx.Variables.RemoteAddr
	tx.Variables.RemoteHost = collection.NewSimple(variables.RemoteHost)
	tx.Collections[variables.RemoteHost] = tx.Variables.RemoteHost
	tx.Variables.RemotePort = collection.NewSimple(variables.RemotePort)
	tx.Collections[variables.RemotePort] = tx.Variables.RemotePort
	tx.Variables.ReqbodyError = collection.NewSimple(variables.ReqbodyError)
	tx.Collections[variables.ReqbodyError] = tx.Variables.ReqbodyError
	tx.Variables.ReqbodyErrorMsg = collection.NewSimple(variables.ReqbodyErrorMsg)
	tx.Collections[variables.ReqbodyErrorMsg] = tx.Variables.ReqbodyErrorMsg
	tx.Variables.ReqbodyProcessorError = collection.NewSimple(variables.ReqbodyProcessorError)
	tx.Collections[variables.ReqbodyProcessorError] = tx.Variables.ReqbodyProcessorError
	tx.Variables.ReqbodyProcessorErrorMsg = collection.NewSimple(variables.ReqbodyProcessorErrorMsg)
	tx.Collections[variables.ReqbodyProcessorErrorMsg] = tx.Variables.ReqbodyProcessorErrorMsg
	tx.Variables.ReqbodyProcessor = collection.NewSimple(variables.ReqbodyProcessor)
	tx.Collections[variables.ReqbodyProcessor] = tx.Variables.ReqbodyProcessor
	tx.Variables.RequestBasename = collection.NewSimple(variables.RequestBasename)
	tx.Collections[variables.RequestBasename] = tx.Variables.RequestBasename
	tx.Variables.RequestBody = collection.NewSimple(variables.RequestBody)
	tx.Collections[variables.RequestBody] = tx.Variables.RequestBody
	tx.Variables.RequestBodyLength = collection.NewSimple(variables.RequestBodyLength)
	tx.Collections[variables.RequestBodyLength] = tx.Variables.RequestBodyLength
	tx.Variables.RequestFilename = collection.NewSimple(variables.RequestFilename)
	tx.Collections[variables.RequestFilename] = tx.Variables.RequestFilename
	tx.Variables.RequestLine = collection.NewSimple(variables.RequestLine)
	tx.Collections[variables.RequestLine] = tx.Variables.RequestLine
	tx.Variables.RequestMethod = collection.NewSimple(variables.RequestMethod)
	tx.Collections[variables.RequestMethod] = tx.Variables.RequestMethod
	tx.Variables.RequestProtocol = collection.NewSimple(variables.RequestProtocol)
	tx.Collections[variables.RequestProtocol] = tx.Variables.RequestProtocol
	tx.Variables.RequestURI = collection.NewSimple(variables.RequestURI)
	tx.Collections[variables.RequestURI] = tx.Variables.RequestURI
	tx.Variables.RequestURIRaw = collection.NewSimple(variables.RequestURIRaw)
	tx.Collections[variables.RequestURIRaw] = tx.Variables.RequestURIRaw
	tx.Variables.ResponseBody = collection.NewSimple(variables.ResponseBody)
	tx.Collections[variables.ResponseBody] = tx.Variables.ResponseBody
	tx.Variables.ResponseContentLength = collection.NewSimple(variables.ResponseContentLength)
	tx.Collections[variables.ResponseContentLength] = tx.Variables.ResponseContentLength
	tx.Variables.ResponseProtocol = collection.NewSimple(variables.ResponseProtocol)
	tx.Collections[variables.ResponseProtocol] = tx.Variables.ResponseProtocol
	tx.Variables.ResponseStatus = collection.NewSimple(variables.ResponseStatus)
	tx.Collections[variables.ResponseStatus] = tx.Variables.ResponseStatus
	tx.Variables.ServerAddr = collection.NewSimple(variables.ServerAddr)
	tx.Collections[variables.ServerAddr] = tx.Variables.ServerAddr
	tx.Variables.ServerName = collection.NewSimple(variables.ServerName)
	tx.Collections[variables.ServerName] = tx.Variables.ServerName
	tx.Variables.ServerPort = collection.NewSimple(variables.ServerPort)
	tx.Collections[variables.ServerPort] = tx.Variables.ServerPort
	tx.Variables.Sessionid = collection.NewSimple(variables.Sessionid)
	tx.Collections[variables.Sessionid] = tx.Variables.Sessionid
	tx.Variables.HighestSeverity = collection.NewSimple(variables.HighestSeverity)
	tx.Collections[variables.HighestSeverity] = tx.Variables.HighestSeverity
	tx.Variables.StatusLine = collection.NewSimple(variables.StatusLine)
	tx.Collections[variables.StatusLine] = tx.Variables.StatusLine
	tx.Variables.InboundErrorData = collection.NewSimple(variables.InboundErrorData)
	tx.Collections[variables.InboundErrorData] = tx.Variables.InboundErrorData
	tx.Variables.Duration = collection.NewSimple(variables.Duration)
	tx.Collections[variables.Duration] = tx.Variables.Duration
	tx.Variables.ResponseHeadersNames = collection.NewMap(variables.ResponseHeadersNames)
	tx.Collections[variables.ResponseHeadersNames] = tx.Variables.ResponseHeadersNames
	tx.Variables.RequestHeadersNames = collection.NewMap(variables.RequestHeadersNames)
	tx.Collections[variables.RequestHeadersNames] = tx.Variables.RequestHeadersNames
	tx.Variables.Userid = collection.NewSimple(variables.Userid)
	tx.Collections[variables.Userid] = tx.Variables.Userid
	tx.Variables.ArgsGet = collection.NewMap(variables.ArgsGet)
	tx.Collections[variables.ArgsGet] = tx.Variables.ArgsGet
	tx.Variables.ArgsPost = collection.NewMap(variables.ArgsPost)
	tx.Collections[variables.ArgsPost] = tx.Variables.ArgsPost
	tx.Variables.ArgsPath = collection.NewMap(variables.ArgsPath)
	tx.Collections[variables.ArgsPath] = tx.Variables.ArgsPath
	tx.Variables.FilesSizes = collection.NewMap(variables.FilesSizes)
	tx.Collections[variables.FilesSizes] = tx.Variables.FilesSizes
	tx.Variables.FilesTmpContent = collection.NewMap(variables.FilesTmpContent)
	tx.Collections[variables.FilesTmpContent] = tx.Variables.FilesTmpContent
	tx.Variables.MultipartFilename = collection.NewMap(variables.MultipartFilename)
	tx.Collections[variables.MultipartFilename] = tx.Variables.MultipartFilename
	tx.Variables.MultipartName = collection.NewMap(variables.MultipartName)
	tx.Collections[variables.MultipartName] = tx.Variables.MultipartName
	tx.Variables.MatchedVars = collection.NewMap(variables.MatchedVars)
	tx.Collections[variables.MatchedVars] = tx.Variables.MatchedVars
	tx.Variables.RequestCookies = collection.NewMap(variables.RequestCookies)
	tx.Collections[variables.RequestCookies] = tx.Variables.RequestCookies
	tx.Variables.RequestHeaders = collection.NewMap(variables.RequestHeaders)
	tx.Collections[variables.RequestHeaders] = tx.Variables.RequestHeaders
	tx.Variables.ResponseHeaders = collection.NewMap(variables.ResponseHeaders)
	tx.Collections[variables.ResponseHeaders] = tx.Variables.ResponseHeaders
	tx.Variables.Geo = collection.NewMap(variables.Geo)
	tx.Collections[variables.Geo] = tx.Variables.Geo
	tx.Variables.TX = collection.NewMap(variables.TX)
	tx.Collections[variables.TX] = tx.Variables.TX
	tx.Variables.Rule = collection.NewMap(variables.Rule)
	tx.Collections[variables.Rule] = tx.Variables.Rule
	tx.Variables.Env = collection.NewMap(variables.Env)
	tx.Collections[variables.Env] = tx.Variables.Env
	tx.Variables.IP = collection.NewMap(variables.IP)
	tx.Collections[variables.IP] = tx.Variables.IP
	tx.Variables.Files = collection.NewMap(variables.Files)
	tx.Collections[variables.Files] = tx.Variables.Files
	tx.Variables.MatchedVarsNames = collection.NewMap(variables.MatchedVarsNames)
	tx.Collections[variables.MatchedVarsNames] = tx.Variables.MatchedVarsNames
	tx.Variables.FilesNames = collection.NewMap(variables.FilesNames)
	tx.Collections[variables.FilesNames] = tx.Variables.FilesNames
	tx.Variables.FilesTmpNames = collection.NewMap(variables.FilesTmpNames)
	tx.Collections[variables.FilesTmpNames] = tx.Variables.FilesTmpNames
	tx.Variables.RequestCookiesNames = collection.NewMap(variables.RequestCookiesNames)
	tx.Collections[variables.RequestCookiesNames] = tx.Variables.RequestCookiesNames
	tx.Variables.ResponseXML = collection.NewMap(variables.ResponseXML)
	tx.Collections[variables.ResponseXML] = tx.Variables.ResponseXML
	tx.Variables.RequestXML = collection.NewMap(variables.RequestXML)
	tx.Collections[variables.RequestXML] = tx.Variables.RequestXML

	tx.Variables.ArgsCombinedSize = collection.NewCollectionSizeProxy(variables.ArgsCombinedSize, tx.Variables.ArgsGet, tx.Variables.ArgsPost)
	tx.Collections[variables.ArgsCombinedSize] = tx.Variables.ArgsCombinedSize

	// XML is a pointer to RequestXML
	tx.Variables.XML = tx.Variables.RequestXML
	tx.Collections[variables.XML] = tx.Variables.RequestXML
	tx.Variables.Args = collection.NewProxy(
		variables.Args,
		tx.Variables.ArgsGet,
		tx.Variables.ArgsPost,
		tx.Variables.ArgsPath,
	)
	tx.Collections[variables.Args] = tx.Variables.Args

	tx.Variables.ArgsNames = collection.NewTranslationProxy(
		variables.ArgsNames,
		tx.Variables.ArgsGet,
		tx.Variables.ArgsPost,
		tx.Variables.ArgsPath,
	)
	tx.Collections[variables.ArgsNames] = tx.Variables.ArgsNames
	tx.Variables.ArgsGetNames = collection.NewTranslationProxy(
		variables.ArgsGetNames,
		tx.Variables.ArgsGet,
	)
	tx.Collections[variables.ArgsGetNames] = tx.Variables.ArgsGetNames
	tx.Variables.ArgsPostNames = collection.NewTranslationProxy(
		variables.ArgsPostNames,
		tx.Variables.ArgsPost,
	)
	tx.Collections[variables.ArgsPostNames] = tx.Variables.ArgsPostNames

	// set capture variables
	for i := 0; i <= 10; i++ {
		is := strconv.Itoa(i)
		tx.Variables.TX.Set(is, []string{""})
	}

	// Some defaults
	tx.Variables.FilesCombinedSize.Set("0")
	tx.Variables.UrlencodedError.Set("0")
	tx.Variables.FullRequestLength.Set("0")
	tx.Variables.MultipartBoundaryQuoted.Set("0")
	tx.Variables.MultipartBoundaryWhitespace.Set("0")
	tx.Variables.MultipartCrlfLfLines.Set("0")
	tx.Variables.MultipartDataAfter.Set("0")
	tx.Variables.MultipartDataBefore.Set("0")
	tx.Variables.MultipartFileLimitExceeded.Set("0")
	tx.Variables.MultipartHeaderFolding.Set("0")
	tx.Variables.MultipartInvalidHeaderFolding.Set("0")
	tx.Variables.MultipartInvalidPart.Set("0")
	tx.Variables.MultipartInvalidQuoting.Set("0")
	tx.Variables.MultipartLfLine.Set("0")
	tx.Variables.MultipartMissingSemicolon.Set("0")
	tx.Variables.MultipartStrictError.Set("0")
	tx.Variables.MultipartUnmatchedBoundary.Set("0")
	tx.Variables.OutboundDataError.Set("0")
	tx.Variables.ReqbodyError.Set("0")
	tx.Variables.ReqbodyProcessorError.Set("0")
	tx.Variables.RequestBodyLength.Set("0")
	tx.Variables.Duration.Set("0")
	tx.Variables.HighestSeverity.Set("0")
	tx.Variables.UniqueID.Set(tx.ID)

	w.Logger.Debug("new transaction created with id %q", tx.ID)

	return tx
}

// SetDebugLogPath sets the path for the debug log
// If the path is empty, the debug log will be disabled
// note: this is not thread safe
func (w *Waf) SetDebugLogPath(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		w.Logger.Error("error opening file: %v", err)
	}
	w.Logger.SetOutput(f)
	return nil
}

// NewWaf creates a new WAF instance with default variables
func NewWaf() *Waf {
	logger := &stdDebugLogger{
		logger: &log.Logger{},
		Level:  LogLevelInfo,
	}
	logWriter, err := loggers.GetLogWriter("serial")
	if err != nil {
		logger.Error("error creating serial log writer: %v", err)
	}
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
		AuditLogRelevantStatus:   regexp.MustCompile(`.*`),
		RequestBodyAccess:        false,
		Logger:                   logger,
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
	w.Logger.SetLevel(LogLevel(lvl))
	return nil
}

// SetErrorLogCb sets the callback function for error logging
// The error callback receives all the error data and some
// helpers to write modsecurity style logs
func (w *Waf) SetErrorLogCb(cb ErrorLogCallback) {
	w.errorLogCb = cb
}
