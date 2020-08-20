package actions

import(
	"strings"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

// Initializes a persistent collection and add the data to the standard collections engine.
type InitCol struct {
	Collection string
	Key string
}

func (a *InitCol) Init(r *engine.Rule, data string) string {
	kv := strings.SplitN(data, "=", 2)
	a.Collection = kv[0]
	a.Key = kv[1]
	return ""
}

func (a *InitCol) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	pc := &engine.PersistentCollection{}
    pc.New(nil, tx.WafInstance.WebAppId, a.Collection, a.Key, 10000)
    col := &utils.LocalCollection{}
    col.Init(a.Collection)
    col.Data = pc.GetData()
    tx.Collections[a.Collection] = col
    tx.PersistentCollections[a.Collection] = pc
}

func (a *InitCol) GetType() int{
	return engine.ACTION_TYPE_NONDISRUPTIVE
}
