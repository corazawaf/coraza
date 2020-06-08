package actions

import(
	"strconv"
	"strings"
	_"fmt"
	"github.com/jptosso/coraza-waf/pkg/models"
)

/*
auditEngine
auditLogParts
debugLogLevel
forceRequestBodyVariable
requestBodyAccess
requestBodyLimit
requestBodyProcessor
responseBodyAccess
responseBodyLimit
ruleEngine
ruleRemoveById
ruleRemoveByMsg
ruleRemoveByTag
ruleRemoveTargetById
ruleRemoveTargetByMsg
ruleRemoveTargetByTag
hashEngine
hashEnforcement
*/

type Ctl struct {
	Action string
	Value string
	Collection string
	ColKey string
}

func (a *Ctl) Init(r *models.Rule, data string, errors []string) () {
	a.Action, a.Value, a.Collection, a.ColKey = parseCtl(data)
}

func (a *Ctl) Evaluate(r *models.Rule, tx *models.Transaction) () {
	//TODO change action to int and add proper consts
	switch a.Action {
	case "ruleRemoveTargetById":
		//Exception: disable rule value for collection:key
		id, _ := strconv.Atoi(a.Value)
		col := &models.Collection{a.Collection, a.ColKey}
		if tx.RemoveTargetFromId[id] == nil{
			tx.RemoveTargetFromId[id] = []*models.Collection{}
		}
		tx.RemoveTargetFromId[id] = append(tx.RemoveTargetFromId[id], col)
	case "ruleRemoveTargetByTag":
		col := &models.Collection{a.Collection, a.ColKey}
		if tx.RemoveTargetFromTag[a.Value] == nil{
			tx.RemoveTargetFromTag[a.Value] = []*models.Collection{}
		}
		tx.RemoveTargetFromTag[a.Value] = append(tx.RemoveTargetFromTag[a.Value], col)
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
