package models

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
}


type Rule struct {
	Id int `json:"id"`
	Phase int `json:"phase"`
	Vars string `json:"vars"`
	Variables []RuleVariable `json:"variables"`
	NegateVariables map[string][]string `json:"negate_variables"`
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
}