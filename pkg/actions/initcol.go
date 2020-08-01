package actions

import(
	"strings"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

type InitCol struct {
	Collection string
	Key string
}

func (a *InitCol) Init(r *engine.Rule, data string, errors []string) {
	kv := strings.SplitN(data, "=", 2)
	a.Collection = kv[0]
	a.Key = kv[1]
}

func (a *InitCol) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	pc := &utils.PersistentCollection{}
    pc.New(tx.WafInstance.RedisClient, a.Collection, a.Key, 300)
    pc.Save()
}

func (a *InitCol) GetType() string{
	return ""
}
