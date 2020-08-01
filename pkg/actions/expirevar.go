package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	_"github.com/jptosso/coraza-waf/pkg/utils"
	"strings"
	"strconv"
)

type Expirevar struct {
	collection string
	ttl int
	key string
}

func (a *Expirevar) Init(r *engine.Rule, data string, errors []string) () {
	spl := strings.SplitN(data, "=", 2)
	a.ttl, _ = strconv.Atoi(spl[1])
	spl = strings.SplitN(spl[0], ".", 2)
	if len(spl) != 2{
		//... error
	}
	a.collection = spl[0]
	a.key = spl[1]
}

func (a *Expirevar) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	//TODO requires more research
	//ps := &utils.PersistentCollection{}
	//ps.Init(a.collection, a.key)
}

func (a *Expirevar) GetType() string{
	return ""
}
