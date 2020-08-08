package engine

import(
	"fmt"
	"strconv"
	"reflect"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

type Action interface {
	Init(*Rule, string, []string)
	Evaluate(*Rule, *Transaction)
	GetType() string
}

type Operator interface {
	Init(string)
	Evaluate(*Transaction, string) bool
}

type RuleOp struct {
	Operator Operator
	Data string
	Negation bool
	//OpEval OperatorFunction
}

type RuleTransformation struct {
	Function string
	TfFunc interface {} `json:"-"`
}

type RuleVariable struct {
	Count bool
	Collection string
	Key string
	Context string
	Exceptions []string
}


type Rule struct {
	Id int `json:"id"`
	Phase int `json:"phase"`
	Vars string `json:"vars"`
	Variables []RuleVariable `json:"variables"`
	Operator string `json:"operator"`
	OperatorObj *RuleOp `json:"operator_obj"`
	Disruptive bool `json:"disruptive"`
	DisablesRules []int `json:"disabled_rules"`
	Transformations []RuleTransformation `json:"transformations"`
	HasChain bool `json:"has_chain"`
	ParentId int `json:"parent_id"`
	Actions []Action `json:"actions"`
	Action string `json:"action"`
	ActionParams string `json:"action_params"`
	Capture bool `json:"capture"`
	Msg string `json:"msg"`
	Rev string `json:"rev"`
	MultiMatch bool `json:"multimatch"`
	Severity string `json:"severity"`
	Skip bool `json:"skip"`
	SecMark string `json:"secmark"`
	Maturity string `json:"maturity"`
	Version string `json:"version"`
	Tags []string `json:"tags"`
	Log bool `json:"log"`
	Raw string `json:"raw"`
	ChildRule *Rule `json:"child_rule"`
	Chain *Rule `json:"chain"`
}

func (r *Rule) Init() {
	r.Phase = 1
	r.Tags = []string{}
	r.Action = "pass"
}


func (r *Rule) Evaluate(tx *Transaction) []string{
	//Log.Debug(fmt.Sprintf("Evaluating transaction %s with rule ID %d", tx.Id, r.Id))
	matchedValues := []string{}
	if r.Capture{
		tx.Capture = true
	}

	skiptargets := []*Collection{}
	for tag, cols := range tx.RemoveTargetFromTag{
		if utils.ArrayContains(r.Tags, tag){
			for _, col := range cols{
				skiptargets = append(skiptargets, col)
			}
		}
	}
	rbi := tx.RemoveTargetFromId[r.Id]
	if rbi != nil{
		fmt.Printf("Skipping some cols for rule id %s\n", tx.Id)
		for _, col := range rbi{			
			skiptargets = append(skiptargets, col)
		}
	}

	for _, v := range r.Variables {
		values := []string{}

		//TODO IMPORTANT: The match notification must be switched, we can't log empty keys!!

		if v.Context == "transaction"{
			values = tx.GetField(v.Collection, v.Key, v.Exceptions)
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
					a.Evaluate(r, tx)
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
						a.Evaluate(r, tx)
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
					if r.executeOperator(carg, tx){
						col := ""
						//TODO REVISAR CUALES SE EJECUTAN Y CUANDO:
						for _, a := range r.Actions{
							if a.GetType() == "disruptive"{
								//we skip disruptive by now
								continue
							}		
							a.Evaluate(r, tx)
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

	tx.Capture = false //TODO shall we remove this?

	if r.Chain != nil{
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
				a.Evaluate(r, tx)
			}
		}
	}
	return matchedValues
}

func (r *Rule) executeOperator(data string, tx *Transaction) bool {
    result := r.OperatorObj.Operator.Evaluate(tx, data)
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
	rv := RuleVariable{count, collection, key, context, []string{}}
	r.Variables = append(r.Variables, rv)
}

func (r *Rule) AddNegateVariable(collection string, key string){
	for i, vr := range r.Variables{
		if vr.Collection == collection{
			vr.Exceptions = append(vr.Exceptions, key)
			r.Variables[i] = vr
			return
		}
	}
}