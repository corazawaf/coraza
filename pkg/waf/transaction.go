package waf

import(
	"github.com/jptosso/coraza-waf/pkg/utils"
	"encoding/json"
	"fmt"
    "github.com/jptosso/coraza-waf/pkg/models"
    "time"
    "sync"
    "strings"
    _"errors"
    //"net"
)

type Transaction struct {
    models.Transaction
    WafInstance *Waf `json:"-"`
}

func GetTransaction(waf *Waf, id string) (Transaction, error){
	val, err := utils.RedisClient.Get(utils.Ctx, fmt.Sprintf("tx_%s", id)).Result()
	if err != nil {
		waf.Logger.Fatal(fmt.Sprintf("Unable to retrieve Transaction %s from Redis", id), err)
	}

	var tx *Transaction = &Transaction{}
	if err := json.Unmarshal([]byte(val), tx); err != nil {
		waf.Logger.Fatal(fmt.Sprintf("Unable to deserealize Transaction %s", id), err)
        fmt.Print(err)
	}
    tx.WafInstance = waf
	return *tx, nil
}

func (tx *Transaction) initVars() {
    tx.Collections = map[string]*utils.LocalCollection{}
    
    tx.SetSingleCollection("id", utils.RandomString(19))
    tx.SetSingleCollection("timestamp", fmt.Sprintf("%d", time.Now().Unix()))
    tx.Disrupted = false
    tx.AuditEngine = tx.WafInstance.AuditEngine
    tx.AuditLogParts = tx.WafInstance.AuditLogParts
    tx.DebugLogLevel = tx.WafInstance.DebugLogLevel
    tx.ForceRequestBodyVariable = tx.WafInstance.ForceRequestBodyVariable
    tx.RequestBodyAccess = tx.WafInstance.RequestBodyAccess
    tx.RequestBodyLimit = tx.WafInstance.RequestBodyLimit
    tx.RequestBodyProcessor = tx.WafInstance.RequestBodyProcessor
    tx.ResponseBodyAccess = tx.WafInstance.ResponseBodyAccess
    tx.ResponseBodyLimit = tx.WafInstance.ResponseBodyLimit
    tx.RuleEngine = tx.WafInstance.RuleEngine
    tx.RuleRemoveById = []int{}
    tx.RuleRemoveByMsg = []string{}
    tx.RuleRemoveByTag = []string{}
    tx.RuleRemoveTargetById = nil
    tx.RuleRemoveTargetByMsg = nil
    tx.RuleRemoveTargetByTag = nil
    tx.HashEngine = tx.WafInstance.HashEngine
    tx.HashEnforcement = tx.WafInstance.HashEnforcement
    tx.DefaultAction = tx.WafInstance.DefaultAction
    tx.Skip = 0
    tx.InitTxCollection()
    
    tx.NewPersistentCollections = map[string]string{}
}

func (tx *Transaction) Init(waf *Waf) error{
    tx.WafInstance = waf
	tx.initVars()
    tx.Mux = &sync.RWMutex{}

	//tx.Save() //redundant
    return nil
}

// Temporalmente no vamos a guardar las transacciones
func (tx *Transaction) Save(){
    return
	_, err := tx.ToJSON()
    if err != nil {
        tx.WafInstance.Logger.Fatal("Error parsing JSON Transaction: %s", err)
        return
    }	

    //RedisClient.Set(fmt.Sprintf("tx_%s", tx.Id), jdata, 0)
    //RedisClient.Expire(fmt.Sprintf("tx_%s", tx.Id), 500*time.Second)
}
func (tx *Transaction) Finish(){
    //tx.WafInstance.WriteAudit(tx)
    //RedisClient.Delete("tx_" + tx.Id)
}

func (tx *Transaction) ExecutePhase(phase int) error{
    if phase < 1 || phase > 5 {
        return fmt.Errorf("Phase must be between 1 and 5, %d used", phase)
    }
    usedRules := 0

    for _, r := range tx.WafInstance.Rules {
        //we always execute secmarkers
        if r.Phase == phase || r.SecMark != ""{
            if tx.SkipAfter != ""{
                if r.SecMark != tx.SkipAfter{
                    //skip this rule
                    //fmt.Println("Skipping rule (skipAfter) " + fmt.Sprintf("%d", r.Id) + " to " + tx.SkipAfter + " currently " + r.SecMark)
                    continue
                }else{
                    //fmt.Println("Ending skip")
                    tx.SkipAfter = ""
                }
            }
            if tx.Skip > 0{
                tx.Skip -= 1
                //fmt.Println("Skipping rule (skip) " + fmt.Sprintf("%d", r.Id))
                //Skipping rule
                continue
            }
            //tx.WafInstance.Logger.Debug(fmt.Sprintf("Evaluating rule %d", r.Id))
            r.Evaluate(tx)
            tx.Capture = false //we reset the capture flag on every run
            usedRules++
        }
    }
    if phase == 5{
        //if tx.Log...
        tx.WafInstance.Logger.WriteAudit(tx)
    }
    //tx.WafInstance.Logger.Debug(fmt.Sprintf("%d rules evaluated for transaction %s", usedRules, tx.Id))
    //tx.WafInstance.Logger.Debug(fmt.Sprintf("----------------------- End Phase %d ---------------------", phase))
    return nil
}


func (tx *Transaction) MatchRule(rule *Rule, msgs []string, matched []string){
    mr := &models.MatchedRule{
        Id: rule.Id,
        Action: rule.Action,
        Messages: msgs,
        MatchedData: matched,
    }
    tx.MatchedRules = append(tx.MatchedRules, mr)

}

func (tx *Transaction) InitTxCollection(){
    keys := []string{ "args", "args_post", "args_get", "args_names", "args_post_names", "args_get_names", "query_string", "remote_addr", "request_basename", "request_uri", "tx", "remote_port",
                      "request_body", "request_content_type", "request_content_length", "request_cookies", "request_cookies_names",  "request_line", "files_sizes",
                      "request_filename", "request_headers", "request_headers_names", "request_method", "request_protocol", "request_filename", "full_request",
                      "request_uri", "request_line", "response_body", "response_content_length", "response_content_type", "request_cookies", "request_uri_raw",
                      "response_headers", "response_headers_names", "response_protocol", "response_status", "appid", "id", "timestamp", "files_names", "files",
                      "files_combined_size"}
    
    for _, k := range keys{
        tx.Collections[k] = &utils.LocalCollection{}
        tx.Collections[k].Init()
    }
}

func (tx *Transaction) InitCollection(key string){
    //TODO aplicar macro a value
    tx.Collections[key] = &utils.LocalCollection{}
}

func (tx *Transaction) ToJSON() ([]byte, error){
    return json.Marshal(tx)
}

func (tx *Transaction) SetSingleCollection(key string, value string){
    tx.Collections[key] = &utils.LocalCollection{}
    tx.Collections[key].Init()
    tx.Collections[key].Add("", []string{value})
}

func (tx *Transaction) GetSingleCollection(key string) string{
    key = strings.ToLower(key)
    col := tx.Collections[key]
    if col == nil{
        return ""
    }
    return col.GetFirstString()
}

func (tx *Transaction) GetField(collection string, key string, exceptions map[string][]string) ([]string){
    //return tx.GetVariablesWithNegations(collection, tx.RequestHeaders.Data, rule) TODO
    col := tx.Collections[collection]
    exc := exceptions[collection]
    key = tx.MacroExpansion(key)
    if col == nil{
        return []string{}
    }
    
    return col.GetWithExceptions(key, exc)
}