package waf

import (
	//"collection"
	//"utils"
	_"fmt"
	"sort"
	"github.com/jptosso/coraza-waf/pkg/utils"
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
    AuditLogParts string
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

}


func (w *Waf) Init() {
	w.Logger = &Logger{}
    w.Logger.Init()
	w.Logger.Debug("Initializing WAF")
	w.DefaultAction = "block"

	err := utils.InitRedis("localhost:6379", "", "")
	if err != nil {
		w.Logger.Fatal("Cannot connect to Redis: %s", err)
	}

	err = utils.InitGeoip("")
	if err != nil {
		w.Logger.Error("Unable to use GeoIP: %s", err)
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