package actions

import(
	"strings"
	"strconv"
    "fmt"
	"github.com/jptosso/coraza/pkg/models"
    "github.com/jptosso/coraza/pkg/utils"
)

type Setvar struct {
	Key string
	Value string
    Collection string
}


//ESTA ACCION SE EJECUTA EN LOS CHAIN AUNQUE NO HAYA MATCH COMPLETO
func (a *Setvar) Init(r *models.Rule, data string, errors []string) () {
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
    a.Collection = spl[0]
    a.Key = spl[1]
    a.Value = kv[1]
}

func (a *Setvar) Evaluate(r *models.Rule, tx *models.Transaction) () {
    key := tx.MacroExpansion(a.Key)
    value := tx.MacroExpansion(a.Value)
    if a.Collection != "tx"{
        a.evaluatePersistantCollection(r, tx, key, value)
    }else{
        a.evaluateTxCollection(r, tx, key, value)
    }
}

func (a *Setvar) GetType() string{
	return ""
}


func (a *Setvar) evaluatePersistantCollection(r *models.Rule, tx *models.Transaction, key string, value string){
    pc := &utils.PersistentCollection{}
    pc.Init(a.Collection, a.Key)
    //pc.New(a.Collection, 100)
    //pc.Save()
}

func (a *Setvar) evaluateTxCollection(r *models.Rule, tx *models.Transaction, key string, value string){
    collection := tx.Collections[a.Collection]
    if collection == nil {
        //fmt.Println("Invalid collection: " + col)
        fmt.Println("Invalid Collection " + a.Collection)
        return
    }

    if a.Key[0] == '!'{
        //ELIMINAR variable de la colección
    }else{
        res := collection.Get(a.Key)
        if len(res) == 0{
            collection.Set(a.Key, []string{"0"})
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