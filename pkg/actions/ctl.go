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

const (
	CTL_REMOVE_TARGET_BY_ID     	= 0
	CTL_REMOVE_TARGET_BY_TAG    	= 1
	CTL_AUDIT_ENGINE 				= 2
	CTL_AUDIT_LOG_PARTS				= 3
	CTL_DEBUG_LOG_LEVEL 			= 4
	CTL_FORCE_REQUEST_BODY_VAR  	= 5
	CTL_REQUEST_BODY_ACCESS     	= 6
	CTL_REQUEST_BODY_LIMIT			= 7
	CTL_RULE_ENGINE					= 8
	CTL_RULE_REMOVE_BY_ID			= 9
	CTL_RULE__REMOVE_TARGET_BY_ID	= 10
	CTL_HASH_ENGINE					= 11
	CTL_HASH_ENFORCEMENT			= 12

)

func (a *Ctl) Init(r *engine.Rule, data string) string {
	a.Action, a.Value, a.Collection, a.ColKey = parseCtl(data)
	return ""
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

func (a *Ctl) GetType() int{
	return engine.ACTION_TYPE_NONDISRUPTIVE
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
