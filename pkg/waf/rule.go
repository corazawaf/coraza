package waf

import (
	"fmt"
	"strconv"
    "reflect"
    "github.com/jptosso/coraza-waf/pkg/models"
)


type Rule struct {
	models.Rule
	Chain *Rule `json:"chain"`
}

func (r *Rule) Init() {
	r.Phase = 1
	r.Tags = []string{}
	r.NegateVariables = map[string][]string{}
	r.Action = "pass"
}


func (r *Rule) Evaluate(tx *Transaction) []string{
	//Log.Debug(fmt.Sprintf("Evaluating transaction %s with rule ID %d", tx.Id, r.Id))
	matchedValues := []string{}
	if r.Capture{
		tx.Capture = true
	}

	for _, v := range r.Variables {
		matched := false
		values := []string{}


		if v.Context == "transaction"{
			values = tx.GetField(v.Collection, v.Key, r.NegateVariables)
		}else{
			//values = waf.GetField(v.Collection, v.Key)
			fmt.Println("NOT READY YET, or maybe yes, idk")
		}

		if v.Count{	
			l := len(values)
			arg := strconv.Itoa(l)
			//TODO is this the right way count works?
			if v.Key != "" && l > 0{
				arg = strconv.Itoa(len(values[0]))
			}
			if r.executeOperator(arg, tx) {
				for _, a := range r.Actions{
					if a.GetType() == "disruptive"{
						//we skip disruptive by now
						continue
					}
					a.Evaluate(&r.Rule, &tx.Transaction)
				}
				matchedValues = append(matchedValues, fmt.Sprintf("%s.%s=%s", v.Collection, v.Key, arg))
			}			
		}else{
			if len(values) == 0{
				if r.executeOperator("", tx) {
					for _, a := range r.Actions{
						if a.GetType() == "disruptive"{
							//we skip disruptive by now
							continue
						}						
						a.Evaluate(&r.Rule, &tx.Transaction)
					}
					matchedValues = append(matchedValues, fmt.Sprintf("%s.%s=%s", v.Collection, v.Key, ""))
				}	
				continue
			}
			for _, arg := range values {
				var args []string
				if r.MultiMatch{
					args = r.executeTransformationsMultimatch(arg)
				}else{
					args = []string{r.executeTransformations(arg)}
				}
				for _, carg := range args{
					if r.executeOperator(carg, tx) {
						matched = true
					}
					if matched{
						matched = true
						col := ""
						//TODO REVISAR CUALES SE EJECUTAN Y CUANDO:
						for _, a := range r.Actions{
							if a.GetType() == "disruptive"{
								//we skip disruptive by now
								continue
							}		
							a.Evaluate(&r.Rule, &tx.Transaction)
						}
						//TODO check this out
						if v.Collection == ""{
							col = v.Key
						}else{
							col = fmt.Sprintf("%s:%s", v.Collection, v.Key)
						}
						col = fmt.Sprintf("%s:%s", col, carg)
						matchedValues = append(matchedValues, col)
					}
				}
			}
		}
	}
	
	if len(matchedValues) == 0{
		//No match for variables
		return []string{}
	}

	tx.Capture = false //We have to set it in case of chains

	if r.ParentId == 0 && r.Chain != nil{
		//Log.Debug("Running chain rule...")
		msgs := []string{}
		nr := r.Chain
		for nr != nil{
			m := nr.Evaluate(tx)
			if len(m) == 0{
				//we fail the chain
				return []string{}
			}
			msgs = 	append(msgs, tx.MacroExpansion(nr.Msg))
			//TODO add matched values from the chain rule
			//matchedValues = append(matchedValues, )
			nr = nr.Chain
		}
		tx.MatchRule(r, msgs, matchedValues)
	}

	if r.ParentId == 0{
		tx.MatchRule(r, []string{tx.MacroExpansion(r.Msg)}, matchedValues)
		//we need to add disruptive actions in the end, otherwise they would be triggered without their chains.
		for _, a := range r.Actions{
			if a.GetType() == "disruptive"{
				a.Evaluate(&r.Rule, &tx.Transaction)
			}
		}
	}
	return matchedValues
}

func (r *Rule) executeOperator(data string, tx *Transaction) bool {
	//TODO: FRAGMENTO TEMPORAL!!!!
	if r.OperatorObj.Operator == nil{
		fmt.Println("RUNNING INVALID OPERATOR: " + r.Operator)
		return false
	}
	//FIN FRAGMENTO TEMPORAL!!!!
	
    result := r.OperatorObj.Operator.Evaluate(&tx.Transaction, data)

    if r.OperatorObj.Negation && result{
    	return false
    }
    if r.OperatorObj.Negation && !result{
    	return true
    }
	return result
}

func (r *Rule) executeTransformationsMultimatch(value string) []string{
	//Im not already sure if multimatch is cumulative or not... if not we should just make value constant
	res := []string{}
	for _, t := range r.Transformations {
	    rf := reflect.ValueOf(t.TfFunc)
	    rargs := make([]reflect.Value, 1)
	    rargs[0] = reflect.ValueOf(value)
	    call := rf.Call(rargs)
	    value = call[0].String()
	    res = append(res, value)
	}
	return res
}

func (r *Rule) executeTransformations(value string) string{

	for _, t := range r.Transformations {
	    rf := reflect.ValueOf(t.TfFunc)
	    rargs := make([]reflect.Value, 1)
	    rargs[0] = reflect.ValueOf(value)
	    call := rf.Call(rargs)
	    value = call[0].String()
	}

	return value
}

func (r *Rule) AddVariable(count bool, collection string, key string, context string) {
	rv := models.RuleVariable{count, collection, key, context}
	r.Variables = append(r.Variables, rv)
}

func (r *Rule) AddNegateVariable(collection string, key string){
	if r.NegateVariables[collection] == nil{
		r.NegateVariables[collection] = []string{key}
	}else{
		r.NegateVariables[collection] = append(r.NegateVariables[collection], key)
	}
}
