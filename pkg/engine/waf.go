// Copyright 2020 Juan Pablo Tosso
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

package engine

import (
	"errors"
	"github.com/jptosso/coraza-waf/pkg/engine/persistence"
	pcre "github.com/jptosso/coraza-waf/pkg/utils/pcre"
	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
	"strings"
	"sync"
)

const (
	CONN_ENGINE_OFF        = 0
	CONN_ENGINE_ON         = 1
	CONN_ENGINE_DETECTONLY = 2

	AUDIT_LOG_CONCURRENT = 0
	AUDIT_LOG_HTTPS      = 1
	AUDIT_LOG_SCRIPT     = 2

	AUDIT_LOG_ENABLED  = 0
	AUDIT_LOG_DISABLED = 1
	AUDIT_LOG_RELEVANT = 2

	ERROR_PAGE_DEFAULT = 0
	ERROR_PAGE_SCRIPT  = 1
	ERROR_PAGE_FILE    = 2
	ERROR_PAGE_INLINE  = 3
	ERROR_PAGE_DEBUG   = 4

	REQUEST_BODY_PARSER_DEFAULT = 0
	REQUEST_BODY_PARSER_XML     = 1
	REQUEST_BODY_PARSER_JSON    = 2
)

type Waf struct {
	// RuleGroup object, contains all rules and helpers
	Rules *RuleGroup

	// Audit logger engine
	Logger *Logger

	// Absolute path where rules are going to look for data files or scripts
	Datapath string

	// Audit mode status
	AuditEngine int

	// Log path for audit engine
	AuditLogPath string

	// Log path for audit engine concurrent files
	AuditLogStorageDir string

	// Array of logging parts to be used
	AuditLogParts []rune

	// Audit engine mode
	AuditLogType int

	// CHMOD value for concurrent audit log directories
	AuditLogDirMode int

	// CHMOD value for concurrent log files
	AuditLogFileMode int

	// Path for debug log
	DebugLog string

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
	RuleEngine bool

	// If true, transaction will fail if response size is bigger than the page limit
	RejectOnResponseBodyLimit bool

	// If true, transaction will fail if request size is bigger than the page limit
	RejectOnRequestBodyLimit bool

	// Responses will only be loaded if mime is listed here
	ResponseBodyMimeTypes []string

	// Web Application id, apps sharing the same id will share persistent collections
	WebAppId string

	// This signature is going to be reported in audit logs
	ComponentSignature string

	// Contains the body or path of the error page
	ErrorPageFile string

	// Contains the error page method to be used
	ErrorPageMethod int

	// Contains the regular expression for relevant status audit logging
	AuditLogRelevantStatus pcre.Regexp

	// Contains the GeoIP2 database reader object
	GeoDb *geoip2.Reader

	// If true WAF engine will fail when remote rules cannot be loaded
	AbortOnRemoteRulesFail bool

	// Instructs the waf to change the Server response header
	ServerSignature string

	// This directory will be used to store page files
	TmpDir string

	// Provide acces to the persistence engine
	PersistenceEngine PersistenceEngine

	// Contains the connection uri for the persistence engine
	PersistenceUri string

	// Sensor ID tu, must be unique per cluster nodes
	SensorId string

	mux *sync.RWMutex

	// To be used
	/*
	   StreamOutBodyInspection bool
	   HashKey string
	   HttpBlKey string
	   PcreMatchLimit int
	   ConnReadStateLimit int
	   ConnWriteStateLimit int
	   CollectionTimeout int
	   ConnEngine int
	   ContentInjection bool
	   ForceRequestBodyVariable bool
	   UploadDir string
	   UploadFileLimit int
	   UploadFileMode int
	   InterceptOnError bool
	   DebugLogLevel int
	   HashEnforcement bool
	   HashEngine bool
	*/
}

// Initializes an instance of WAF
func (w *Waf) Init() {
	//TODO replace with SecCacheEngine redis://user:password@localhost:6379
	w.mux = &sync.RWMutex{}
	w.Rules = &RuleGroup{}
	w.Rules.Init()
	w.AuditEngine = AUDIT_LOG_DISABLED
	w.AuditLogType = AUDIT_LOG_CONCURRENT
	w.PersistenceUri = "inmemory"
	w.RequestBodyLimit = 10000000 //10mb
}

func (w *Waf) InitLogger() {
	l := &Logger{}
	var err error
	/*
	   switch w.AuditLogType{
	   default:
	       err = l.InitConcurrent(w.AuditLogPath, w.AuditLogStorageDir)
	   }
	*/
	err = l.InitConcurrent(w.AuditLogPath, w.AuditLogStorageDir)
	if err != nil {
		log.Error("Failed to initialize concurrent logger, concurrent logging will be disabled.")
	}
	w.Logger = l
}

// Initializes Geoip2 database
func (w *Waf) InitGeoip(path string) error {
	var err error
	w.GeoDb, err = geoip2.Open(path)
	if err != nil {
		return err
	}
	return nil
}

// Initializes Persistence Engine
func (w *Waf) InitPersistenceEngine(uri string) error {
	spl := strings.SplitN(uri, ":", 2)
	if len(spl) == 0 {
		return errors.New("Invalid persistence Engine")
	}
	var pe PersistenceEngine
	switch spl[0] {
	case "redis":
		pe = &persistence.RedisEngine{}
	default:
		pe = &persistence.MemoryEngine{}
	}
	err := pe.Init(uri)
	if err != nil {
		return err
	}
	w.PersistenceEngine = pe
	return nil
}

// Returns a new initialized transaction for this WAF instance
func (w *Waf) NewTransaction() *Transaction {
	w.mux.RLock()
	defer w.mux.RUnlock()
	tx := &Transaction{}
	tx.Init(w)
	return tx
}

func NewWaf() *Waf {
	waf := &Waf{}
	waf.Init()
	return waf
}
