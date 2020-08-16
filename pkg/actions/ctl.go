package actions

import(
	"strings"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Ctl struct {
	Action string
	Value string
	Collection string
	ColKey string
}

func (a *Ctl) Init(r *engine.Rule, data string, errors []string) () {
	a.Action, a.Value, a.Collection, a.ColKey = parseCtl(data)
}

func (a *Ctl) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	switch a.Action {
	case "ruleRemoveTargetById":
	break
	case "ruleRemoveTargetByTag":
	break
	case "auditEngine":
		
		break
	case "auditLogParts":

		break
	case "debugLogLevel":

	break
	case "forceRequestBodyVariable":

		break
	case "requestBodyAccess":

		break
	case "requestBodyLimit":

	break
	case "requestBodyProcessor":

		break
	case "responseBodyAccess":

	break
	case "responseBodyLimit":

	break
	case "ruleEngine":

		break
	case "ruleRemoveById":

	break
	case "ruleRemoveByMsg":

	break
	case "ruleRemoveTargetByMsg":

	break
	case "hashEngine":

	break
	case "hashEnforcement":

	break
	default:
	}
	
}

func (a *Ctl) GetType() string{
	return ""
}


func parseCtl(data string) (string, string, string, string){
	spl1 := strings.SplitN(data, "=", 2)
	spl2 := strings.SplitN(spl1[1], ";", 2)
	action := spl1[0]
	value := spl2[0]
	collection := ""
	colkey := ""
	if len(spl2) == 2{
		spl3 := strings.SplitN(spl2[1], ":", 2)
		if len(spl3) == 2{
			collection = spl3[0]
			colkey = spl3[1]
		}else{
			colkey = spl3[0]
		}
	}
	return action, value, strings.TrimSpace(strings.ToLower(collection)), strings.TrimSpace(strings.ToLower(colkey))
}
