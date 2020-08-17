package actions

import(
	"strings"
	"strconv"
    "fmt"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Setvar struct {
	Key string
	Value string
    Collection string
}


//this action win run even if rule is not triggered.!
func (a *Setvar) Init(r *engine.Rule, data string) []string {
    //sample: tx.%{rule.id}-WEB_ATTACK/SQL_INJECTION-%{matched_var_name}=%{tx.0}
	if data[0] == '\''{
		data = strings.Trim(data, "'")
	}
    //kv[0] = tx.%{rule.id}-WEB_ATTACK/SQL_INJECTION-%{matched_var_name}
    //kv[1] = %{tx.0}
	kv := strings.SplitN(data, "=", 2)
	kv[0] = strings.ToLower(kv[0])
    //spl[0] = tx
    //spl[1] = %{rule.id}-WEB_ATTACK/SQL_INJECTION-%{matched_var_name}
    spl := strings.SplitN(kv[0], ".", 2)
    //allowed := []string{"tx", "ip", "session"}
    a.Collection = spl[0]
    a.Key = spl[1]
    a.Value = kv[1]
    return []string{}
}

func (a *Setvar) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
    key := tx.MacroExpansion(a.Key)
    value := tx.MacroExpansion(a.Value)
    a.evaluateTxCollection(r, tx, key, value)
}

func (a *Setvar) GetType() int{
	return engine.ACTION_TYPE_NONDISRUPTIVE
}

func (a *Setvar) evaluateTxCollection(r *engine.Rule, tx *engine.Transaction, key string, value string){
    collection := tx.Collections[a.Collection]
    if collection == nil {
        fmt.Println("Invalid Collection " + a.Collection)
        return
    }

    if a.Key[0] == '!'{
        //TODO remove from collection
    }else{
        res := collection.Get(a.Key)
        if len(res) == 0{
            collection.Set(tx.MacroExpansion(a.Key), []string{"0"})
            res = []string{"0"}
        }
        if a.Value[0] == '+'{
            me, _ := strconv.Atoi(tx.MacroExpansion(a.Value[1:]))
            txv, err := strconv.Atoi(res[0])
            if err != nil{
                return
            }
            collection.Set(tx.MacroExpansion(a.Key), []string{strconv.Itoa(me + txv)})
        }else if a.Value[0] == '-'{
            me, _ := strconv.Atoi(tx.MacroExpansion(a.Value[1:]))
            txv, err := strconv.Atoi(res[0])
            if err != nil{
                return
            }
            collection.Set(tx.MacroExpansion(a.Key), []string{strconv.Itoa(txv - me)})
        }else{
            collection.Set(tx.MacroExpansion(a.Key), []string{tx.MacroExpansion(a.Value)})
        }
    }
}