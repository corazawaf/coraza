package actions

import(
	"strings"
	"github.com/jptosso/coraza-waf/pkg/models"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

type InitCol struct {
	Collection string
	Key string
}

func (a *InitCol) Init(r *models.Rule, data string, errors []string) {
	kv := strings.SplitN(data, "=", 2)
	a.Collection = kv[0]
	a.Key = kv[1]
}

func (a *InitCol) Evaluate(r *models.Rule, tx *models.Transaction) {
	pc := &utils.PersistentCollection{}
    pc.New(a.Collection, a.Key, 300)
    pc.Save()
}

func (a *InitCol) GetType() string{
	return ""
}
