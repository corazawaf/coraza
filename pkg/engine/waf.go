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

package engine

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/jptosso/coraza-waf/pkg/engine/loggers"
	"github.com/jptosso/coraza-waf/pkg/engine/persistence"
	"github.com/jptosso/coraza-waf/pkg/utils"
	regex "github.com/jptosso/coraza-waf/pkg/utils/regex"
	"github.com/oschwald/geoip2-golang"
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

	REQUEST_BODY_PROCESSOR_DEFAULT    = 0
	REQUEST_BODY_PROCESSOR_URLENCODED = 1
	REQUEST_BODY_PROCESSOR_XML        = 2
	REQUEST_BODY_PROCESSOR_JSON       = 3
	REQUEST_BODY_PROCESSOR_MULTIPART  = 4

	REQUEST_BODY_LIMIT_ACTION_PROCESS_PARTIAL = 0
	REQUEST_BODY_LIMIT_ACTION_REJECT          = 1

	RULE_ENGINE_ON         = 0
	RULE_ENGINE_DETECTONLY = 1
	RULE_ENGINE_OFF        = 2
)

type Waf struct {
	// RuleGroup object, contains all rules and helpers
	Rules *RuleGroup

	// Audit logger engine
	loggers []loggers.Logger

	// Absolute path where rules are going to look for data files or scripts
	Datapath string

	// Audit mode status
	AuditEngine int

	// Array of logging parts to be used
	AuditLogParts []rune

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
	RuleEngine int

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

	// Contains the regular expression for relevant status audit logging
	AuditLogRelevantStatus regex.Regexp

	// Contains the GeoIP2 database reader object
	GeoDb *geoip2.Reader

	// If true WAF engine will fail when remote rules cannot be loaded
	AbortOnRemoteRulesFail bool

	// Instructs the waf to change the Server response header
	ServerSignature string

	// This directory will be used to store page files
	TmpDir string

	// Provide acces to the persistence engine
	//PersistenceEngine PersistenceEngine

	// Persistence engine
	Persistence persistence.Persistence

	// Sensor ID tu, must be unique per cluster nodes
	SensorId string

	// Path to store data files
	DataDir string

	UploadKeepFiles         bool
	UploadFileMode          uint8
	UploadFileLimit         int
	UploadDir               string
	RequestBodyNoFilesLimit int64
	CollectionTimeout       int

	Unicode *utils.Unicode

	mux *sync.RWMutex

	RequestBodyLimitAction int
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
func (w *Waf) SetPersistenceEngine(uri string) error {
	// Not implemented
	return nil
}

// Returns a new initialized transaction for this WAF instance
func (w *Waf) NewTransaction() *Transaction {
	w.mux.RLock()
	defer w.mux.RUnlock()
	tx := &Transaction{
		Waf:                  w,
		Collections:          make([]*Collection, VARIABLES_COUNT),
		Id:                   utils.RandomString(19),
		Timestamp:            time.Now().UnixNano(),
		AuditEngine:          w.AuditEngine,
		AuditLogParts:        w.AuditLogParts,
		RuleEngine:           w.RuleEngine,
		RequestBodyAccess:    true,
		RequestBodyLimit:     134217728,
		ResponseBodyAccess:   true,
		ResponseBodyLimit:    524288,
		RuleRemoveTargetById: map[int][]*KeyValue{},
		RuleRemoveById:       []int{},
		StopWatches:          map[int]int{},
		RequestBodyBuffer:    NewBodyReader(w.TmpDir, w.RequestBodyInMemoryLimit),
		ResponseBodyBuffer:   NewBodyReader(w.TmpDir, w.RequestBodyInMemoryLimit),
	}
	for i := range tx.Collections {
		tx.Collections[i] = &Collection{}
		tx.Collections[i].Init(VariableToName(byte(i)))
	}

	for i := 0; i <= 10; i++ {
		is := strconv.Itoa(i)
		tx.GetCollection(VARIABLE_TX).Set(is, []string{})
	}
	return tx
}

// AddLogger creates a new logger for the current WAF instance
// You may add as many loggers as you want
// Keep in mind loggers may lock go routines
func (w *Waf) AddLogger(engine string, args []string) error {
	var l loggers.Logger
	switch engine {
	case "modsec":
		l = &loggers.ModsecLogger{}
	case "concurrent":
		l = &loggers.ConcurrentLogger{}
	default:
		return errors.New("invalid logger " + engine)
	}
	if len(args) > 1 {
		args = args[1:]
	}
	err := l.New(args)
	if err != nil {
		return err
	}
	w.loggers = append(w.loggers, l)
	return nil
}

// Logger returns the initiated loggers
// Coraza supports unlimited loggers, so you can write for example
// to syslog and a local drive at the same time
func (w *Waf) Loggers() []loggers.Logger {
	return w.loggers
}

// NewWaf creates a new WAF instance with default variables
func NewWaf() *Waf {
	//default: us-ascii
	waf := &Waf{
		AuditEngine:              AUDIT_LOG_DISABLED,
		AuditLogParts:            []rune("ABCFHZ"),
		loggers:                  []loggers.Logger{},
		mux:                      &sync.RWMutex{},
		RequestBodyInMemoryLimit: 131072,
		RequestBodyLimit:         10000000, //10mb
		ResponseBodyMimeTypes:    []string{"text/html", "text/plain"},
		RuleEngine:               RULE_ENGINE_ON,
		Rules:                    NewRuleGroup(),
		TmpDir:                   "/tmp",
		CollectionTimeout:        3600,
	}
	return waf
}
