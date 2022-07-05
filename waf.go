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
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
	utils "github.com/corazawaf/coraza/v3/utils/strings"
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
	Logger *DebugLogger

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

	tx.Collections[variables.UrlencodedError] = collection.NewCollectionSimple(variables.UrlencodedError)
	tx.Collections[variables.ResponseContentType] = collection.NewCollectionSimple(variables.ResponseContentType)
	tx.Collections[variables.UniqueID] = collection.NewCollectionSimple(variables.UniqueID)
	tx.Collections[variables.ArgsCombinedSize] = collection.NewCollectionSimple(variables.ArgsCombinedSize)
	tx.Collections[variables.AuthType] = collection.NewCollectionSimple(variables.AuthType)
	tx.Collections[variables.FilesCombinedSize] = collection.NewCollectionSimple(variables.FilesCombinedSize)
	tx.Collections[variables.FullRequest] = collection.NewCollectionSimple(variables.FullRequest)
	tx.Collections[variables.FullRequestLength] = collection.NewCollectionSimple(variables.FullRequestLength)
	tx.Collections[variables.InboundDataError] = collection.NewCollectionSimple(variables.InboundDataError)
	tx.Collections[variables.MatchedVar] = collection.NewCollectionSimple(variables.MatchedVar)
	tx.Collections[variables.MatchedVarName] = collection.NewCollectionSimple(variables.MatchedVarName)
	tx.Collections[variables.MultipartBoundaryQuoted] = collection.NewCollectionSimple(variables.MultipartBoundaryQuoted)
	tx.Collections[variables.MultipartBoundaryWhitespace] = collection.NewCollectionSimple(variables.MultipartBoundaryWhitespace)
	tx.Collections[variables.MultipartCrlfLfLines] = collection.NewCollectionSimple(variables.MultipartCrlfLfLines)
	tx.Collections[variables.MultipartDataAfter] = collection.NewCollectionSimple(variables.MultipartDataAfter)
	tx.Collections[variables.MultipartDataBefore] = collection.NewCollectionSimple(variables.MultipartDataBefore)
	tx.Collections[variables.MultipartFileLimitExceeded] = collection.NewCollectionSimple(variables.MultipartFileLimitExceeded)
	tx.Collections[variables.MultipartHeaderFolding] = collection.NewCollectionSimple(variables.MultipartHeaderFolding)
	tx.Collections[variables.MultipartInvalidHeaderFolding] = collection.NewCollectionSimple(variables.MultipartInvalidHeaderFolding)
	tx.Collections[variables.MultipartInvalidPart] = collection.NewCollectionSimple(variables.MultipartInvalidPart)
	tx.Collections[variables.MultipartInvalidQuoting] = collection.NewCollectionSimple(variables.MultipartInvalidQuoting)
	tx.Collections[variables.MultipartLfLine] = collection.NewCollectionSimple(variables.MultipartLfLine)
	tx.Collections[variables.MultipartMissingSemicolon] = collection.NewCollectionSimple(variables.MultipartMissingSemicolon)
	tx.Collections[variables.MultipartStrictError] = collection.NewCollectionSimple(variables.MultipartStrictError)
	tx.Collections[variables.MultipartUnmatchedBoundary] = collection.NewCollectionSimple(variables.MultipartUnmatchedBoundary)
	tx.Collections[variables.OutboundDataError] = collection.NewCollectionSimple(variables.OutboundDataError)
	tx.Collections[variables.PathInfo] = collection.NewCollectionSimple(variables.PathInfo)
	tx.Collections[variables.QueryString] = collection.NewCollectionSimple(variables.QueryString)
	tx.Collections[variables.RemoteAddr] = collection.NewCollectionSimple(variables.RemoteAddr)
	tx.Collections[variables.RemoteHost] = collection.NewCollectionSimple(variables.RemoteHost)
	tx.Collections[variables.RemotePort] = collection.NewCollectionSimple(variables.RemotePort)
	tx.Collections[variables.ReqbodyError] = collection.NewCollectionSimple(variables.ReqbodyError)
	tx.Collections[variables.ReqbodyErrorMsg] = collection.NewCollectionSimple(variables.ReqbodyErrorMsg)
	tx.Collections[variables.ReqbodyProcessorError] = collection.NewCollectionSimple(variables.ReqbodyProcessorError)
	tx.Collections[variables.ReqbodyProcessorErrorMsg] = collection.NewCollectionSimple(variables.ReqbodyProcessorErrorMsg)
	tx.Collections[variables.ReqbodyProcessor] = collection.NewCollectionSimple(variables.ReqbodyProcessor)
	tx.Collections[variables.RequestBasename] = collection.NewCollectionSimple(variables.RequestBasename)
	tx.Collections[variables.RequestBody] = collection.NewCollectionSimple(variables.RequestBody)
	tx.Collections[variables.RequestBodyLength] = collection.NewCollectionSimple(variables.RequestBodyLength)
	tx.Collections[variables.RequestFilename] = collection.NewCollectionSimple(variables.RequestFilename)
	tx.Collections[variables.RequestLine] = collection.NewCollectionSimple(variables.RequestLine)
	tx.Collections[variables.RequestMethod] = collection.NewCollectionSimple(variables.RequestMethod)
	tx.Collections[variables.RequestProtocol] = collection.NewCollectionSimple(variables.RequestProtocol)
	tx.Collections[variables.RequestURI] = collection.NewCollectionSimple(variables.RequestURI)
	tx.Collections[variables.RequestURIRaw] = collection.NewCollectionSimple(variables.RequestURIRaw)
	tx.Collections[variables.ResponseBody] = collection.NewCollectionSimple(variables.ResponseBody)
	tx.Collections[variables.ResponseContentLength] = collection.NewCollectionSimple(variables.ResponseContentLength)
	tx.Collections[variables.ResponseProtocol] = collection.NewCollectionSimple(variables.ResponseProtocol)
	tx.Collections[variables.ResponseStatus] = collection.NewCollectionSimple(variables.ResponseStatus)
	tx.Collections[variables.ServerAddr] = collection.NewCollectionSimple(variables.ServerAddr)
	tx.Collections[variables.ServerName] = collection.NewCollectionSimple(variables.ServerName)
	tx.Collections[variables.ServerPort] = collection.NewCollectionSimple(variables.ServerPort)
	tx.Collections[variables.Sessionid] = collection.NewCollectionSimple(variables.Sessionid)
	tx.Collections[variables.HighestSeverity] = collection.NewCollectionSimple(variables.HighestSeverity)
	tx.Collections[variables.StatusLine] = collection.NewCollectionSimple(variables.StatusLine)
	tx.Collections[variables.InboundErrorData] = collection.NewCollectionSimple(variables.InboundErrorData)
	tx.Collections[variables.Duration] = collection.NewCollectionSimple(variables.Duration)
	tx.Collections[variables.ResponseHeadersNames] = collection.NewCollectionSimple(variables.ResponseHeadersNames)
	tx.Collections[variables.RequestHeadersNames] = collection.NewCollectionSimple(variables.RequestHeadersNames)
	tx.Collections[variables.Userid] = collection.NewCollectionSimple(variables.Userid)
	tx.Collections[variables.ArgsGet] = collection.NewCollectionMap(variables.ArgsGet)
	tx.Collections[variables.ArgsPost] = collection.NewCollectionMap(variables.ArgsPost)
	tx.Collections[variables.Args] = collection.NewCollectionProxy(
		variables.Args,
		tx.Collections[variables.ArgsGet],
		tx.Collections[variables.ArgsPost],
	)
	tx.Collections[variables.FilesSizes] = collection.NewCollectionMap(variables.FilesSizes)

	tx.Collections[variables.Files] = collection.NewCollectionMap(variables.Files)
	tx.Collections[variables.FilesNames] = collection.NewCollectionTranslationProxy(
		variables.FilesNames,
		tx.Collections[variables.Files],
		nil,
	)
	tx.Collections[variables.FilesTmpContent] = collection.NewCollectionMap(variables.FilesTmpContent)
	tx.Collections[variables.MultipartFilename] = collection.NewCollectionMap(variables.MultipartFilename)
	tx.Collections[variables.MultipartName] = collection.NewCollectionMap(variables.MultipartName)
	tx.Collections[variables.MatchedVars] = collection.NewCollectionMap(variables.MatchedVars)
	tx.Collections[variables.MatchedVarsNames] = collection.NewCollectionTranslationProxy(
		variables.MatchedVarsNames,
		tx.Collections[variables.MatchedVars],
		nil,
	)
	tx.Collections[variables.RequestCookies] = collection.NewCollectionMap(variables.RequestCookies)
	tx.Collections[variables.RequestHeaders] = collection.NewCollectionMap(variables.RequestHeaders)
	tx.Collections[variables.ResponseHeaders] = collection.NewCollectionMap(variables.ResponseHeaders)
	tx.Collections[variables.Geo] = collection.NewCollectionMap(variables.Geo)
	tx.Collections[variables.RequestCookiesNames] = collection.NewCollectionTranslationProxy(
		variables.RequestCookiesNames,
		tx.Collections[variables.RequestCookies],
		nil,
	)
	tx.Collections[variables.FilesTmpNames] = collection.NewCollectionTranslationProxy(
		variables.FilesTmpNames,
		tx.Collections[variables.FilesTmpContent],
		nil,
	)
	tx.Collections[variables.ArgsNames] = collection.NewCollectionTranslationProxy(
		variables.ArgsNames,
		tx.Collections[variables.ArgsGet],
		tx.Collections[variables.ArgsPost],
	)
	tx.Collections[variables.ArgsGetNames] = collection.NewCollectionTranslationProxy(
		variables.ArgsGetNames,
		tx.Collections[variables.ArgsGet],
		nil,
	)
	tx.Collections[variables.ArgsPostNames] = collection.NewCollectionTranslationProxy(
		variables.ArgsPostNames,
		tx.Collections[variables.ArgsPost],
		nil,
	)
	tx.Collections[variables.TX] = collection.NewCollectionMap(variables.TX)
	tx.Collections[variables.Rule] = collection.NewCollectionMap(variables.Rule)
	tx.Collections[variables.XML] = collection.NewCollectionSimple(variables.XML)
	tx.Collections[variables.Env] = collection.NewCollectionMap(variables.Env)
	tx.Collections[variables.IP] = collection.NewCollectionMap(variables.IP)

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
	logger := &DebugLogger{
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
