package waf

import (
	//"collection"
	//"utils"
	_"fmt"
	"sort"
	"regexp"
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

const (
	CONN_ENGINE_OFF		                 = 0
	CONN_ENGINE_ON		                 = 1
	CONN_ENGINE_DETECTONLY               = 2

	AUDIT_LOG_CONCURRENT                 = 0
	AUDIT_LOG_HTTPS		                 = 1

	AUDIT_LOG_PART_HEADER                = 0 // PART A - JUST FOR COMPATIBILITY, IT DOES NOTHING
	AUDIT_LOG_PART_REQUEST_HEADERS       = 1 // PART B
	AUDIT_LOG_PART_REQUEST_BODY          = 2 // PART C
	AUDIT_LOG_PART_RESERVED_1	         = 3 // PART D
	AUDIT_LOG_PART_INT_RESPONSE_BODY     = 4 // PART E
	AUDIT_LOG_PART_FIN_RESPONSE_BODY	 = 5 // PART F
	AUDIT_LOG_PART_FIN_RESPONSE_HEADERS  = 6 // PART G
	AUDIT_LOG_PART_RESPONSE_BODY 		 = 7 // PART H
	AUDIT_LOG_PART_AUDIT_LOG_TRAIL		 = 8 // PART I
	AUDIT_LOG_PART_FILES_MULTIPART		 = 9 // PART J
	AUDIT_LOG_PART_ALL_MATCHED_RULES	 = 10 // PART K
	AUDIT_LOG_PART_FINAL_BOUNDARY   	 = 11 // PART Z - JUST FOR COMPATIBILITY, IT DOES NOTHING

)

type Waf struct {
	Rules []*Rule
	//int timestamp string transaction ID
	TxAlive map[int]string
	Logger *Logger
	Collections map[string]*utils.PersistentCollection
	Datapath string

	DefaultAction string
    AuditEngine bool
    AuditLogPath1 string
    AuditLogPath2 string
    AuditLogParts []int
    AuditLogStorageDir string
    AuditLogType int
    DebugLog string
    HashKey string
    HttpBlKey string
    InterceptOnError bool
    PcreMatchLimit int
    ConnReadStateLimit int
    SensorId string
    ConnWriteStateLimit int
    AbortOnRemoteRulesFail bool
    CollectionTimeout int
    ConnEngine int
    ContentInjection bool
    DebugLogLevel int
    ForceRequestBodyVariable bool
    RequestBodyAccess bool
    RequestBodyLimit int64
    RequestBodyProcessor bool
    ResponseBodyAccess bool
    ResponseBodyLimit int64
    RuleEngine bool
    HashEngine bool
    HashEnforcement bool	
    AuditLogDirMode int
    AuditLogFileMode int
    RequestBodyInMemoryLimit int64
    RejectOnResponseBodyLimit bool
    ResponseBodyMimeTypes []string
    RejectOnRequestBodyLimit bool
    ServerSignature string
    StreamOutBodyInspection bool
    TmpDir string
    UploadDir string
    UploadFileLimit int
    UploadFileMode int
    WebAppId string
    ComponentSignature string
    AuditLogRelevantStatus *regexp.Regexp
}


func (w *Waf) Init() {
	w.Logger = &Logger{}
    w.Logger.Init()

	err := utils.InitRedis("localhost:6379", "", "")
	if err != nil {
		fmt.Println("Cannot connect to Redis, switching to memory collections.")
	}
}


func (w *Waf) GetField(collection string, key string) []string{
	return []string{}
}

func (w *Waf) SortRules() {
	sort.Slice(w.Rules, func(i, j int) bool {
	  return w.Rules[i].Id < w.Rules[i].Id
	})
}

func (w *Waf) FindRuleById(id int) *Rule{
	return nil
}

func (w *Waf) DeleteRuleById(id int){
	
}

func (w *Waf) FindRulesByMsg(msg string) []*Rule{
	return nil
}

func (w *Waf) FindRulesByTag(tag string) []*Rule{
	return nil
}

func (w *Waf) NewTransaction() *Transaction{
	tx := &Transaction{}
	tx.Init(w)
	return tx
}