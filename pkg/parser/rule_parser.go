package parser

import (
	"errors"
	actionsmod "github.com/jptosso/coraza-waf/pkg/actions"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/operators"
	"github.com/jptosso/coraza-waf/pkg/utils"
	pcre "github.com/jptosso/coraza-waf/pkg/utils/pcre"
	"strconv"
	"strings"
)

type RuleParser struct {
	rule      *engine.Rule
	configdir string
}

func (p *RuleParser) Init() {
	p.rule = engine.NewRule()
}

func (p *RuleParser) ParseVariables(vars string) error {
	//Splits the values by KEY, KEY:VALUE, &!KEY, KEY:/REGEX/, KEY1|KEY2
	//GROUP 1 is collection, group 3 is vlue, group 3 can be empty
	//TODO this is not an elegant way to parse variables but it works and it won't generate workload
	re := pcre.MustCompile(`(((?:&|!)?XML):?(.*?)(?:\||$))|((?:&|!)?[\w_]+):?([\w-_]+|\/.*?(?<!\\)\/)?`, 0)
	matcher := re.MatcherString(vars, 0)
	subject := []byte(vars)
	for matcher.Match(subject, 0) {
		vname := matcher.GroupString(4)
		vvalue := strings.ToLower(matcher.GroupString(5))
		if vname == "" {
			//This case is only for XML, sorry for the ugly code :(
			vname = matcher.GroupString(2)
			vvalue = strings.ToLower(matcher.GroupString(3))
		}
		index := matcher.Index()
		counter := false
		negation := false
		if vname[0] == '&' {
			vname = vname[1:]
			counter = true
		}
		if vname[0] == '!' {
			vname = vname[1:]
			negation = true
		}

		collection := strings.ToLower(vname)
		if negation {
			p.rule.AddNegateVariable(collection, vvalue)
		} else {
			p.rule.AddVariable(counter, collection, vvalue)
		}

		subject = subject[index[1]:]
		if len(subject) == 0 {
			break
		}
	}
	return nil
}

func (p *RuleParser) ParseOperator(operator string) error {
	if operator == "" {
		operator = "@rx "
	}
	if operator[0] != '@' && operator[0] != '!' {
		//default operator RX
		operator = "@rx " + operator
	}
	spl := strings.SplitN(operator, " ", 2)
	op := spl[0]
	p.rule.Operator = operator
	p.rule.OperatorObj = new(engine.RuleOp)

	if op[0] == '!' {
		p.rule.OperatorObj.Negation = true
		op = utils.TrimLeftChars(op, 1)
	}
	if op[0] == '@' {
		op = utils.TrimLeftChars(op, 1)
		if len(spl) == 2 {
			p.rule.OperatorObj.Data = spl[1]
		}
	}

	p.rule.OperatorObj.Operator = operators.OperatorsMap()[op]
	if p.rule.OperatorObj.Operator == nil {
		return errors.New("Invalid operator " + op)
	} else {
		//TODO add a special attribute to accept files
		fileops := []string{"ipMatchFromFile", "pmFromFile"}
		for _, fo := range fileops {
			if fo == op {
				p.rule.OperatorObj.Data = p.configdir + p.rule.OperatorObj.Data
			}
		}
		p.rule.OperatorObj.Operator.Init(p.rule.OperatorObj.Data)
	}
	return nil
}

func (p *RuleParser) ParseActions(actions string, defaults []*DefaultActions) error {
	act, _ := ParseActions(actions)
	//first we get the phase for default actions
	phase := act["phase"]
	pp := 1
	var err error
	if phase != nil || len(phase) > 0 {
		pp, err = PhaseToInt(phase[0])
		if err != nil {
			return err
		}
	}

	for _, acts := range defaults {
		cp := acts.Phase
		if cp != pp {
			//Not our phase bruh
			continue
		} else {
			act = MergeActions(acts.Actions, act)
			p.rule.DefaultDisruptiveAction = acts.DisruptiveAction
			break //TODO is it ok to break?
		}
	}

	for key, acts := range act {
		for _, value := range acts {
			action := actionsmod.ActionsMap()[key]
			if action == nil {
				//TODO some fixing here, this is a bug
				return errors.New("Invalid action " + key)
			} else {
				err := action.Init(p.rule, value)
				if err != "" {
					//p.log(err)
					continue
				}
				p.rule.Actions = append(p.rule.Actions, action)
			}
		}
	}

	return nil
}

func (p *RuleParser) GetRule() *engine.Rule {
	return p.rule
}

func NewRuleParser() *RuleParser {
	rp := &RuleParser{}
	rp.Init()
	return rp
}

func ParseActions(actions string) (map[string][]string, error) {
	//This regex splits actions by comma and assign key:values with supported escaped quotes
	//TODO needs fixing, sometimes we empty strings as key
	re := pcre.MustCompile(`(.*?)((?<!\\)(?!\B'[^']*),(?![^']*'\B)|$)`, 0)
	matcher := re.MatcherString(actions, 0)
	subject := []byte(actions)
	res := map[string][]string{}
	if len(actions) == 0 {
		return res, nil
	}
	for matcher.Match(subject, 0) {
		m := matcher.GroupString(1)
		index := matcher.Index()
		spl := strings.SplitN(m, ":", 2)
		value := ""
		key := strings.Trim(spl[0], " ")
		subject = subject[index[1]:]

		if len(spl) == 2 {
			value = strings.Trim(spl[1], " ")
		}
		if key == "" {
			continue
		}
		if res[key] == nil {
			res[key] = []string{value}
		} else {
			res[key] = append(res[key], value)
		}
		if len(subject) == 0 {
			break
		}
	}
	return res, nil
}

func PhaseToInt(phase string) (int, error) {
	if phase == "request" {
		return 1, nil
	} else if phase == "response" {
		return 4, nil
	} else if phase == "log" {
		return 5, nil
	}
	p, err := strconv.Atoi(phase)

	if err != nil || p < 1 || p > 5 {
		return 0, errors.New("Invalid phase " + phase)
	}
	// This should never happen (?)
	return p, nil
}

func MergeActions(origin map[string][]string, extra map[string][]string) map[string][]string {
	newdata := map[string][]string{}
	for _, m := range []map[string][]string{origin, extra} {
		for k, v := range m {
			if newdata[k] == nil {
				newdata[k] = v
			} else {
				for _, vv := range v {
					newdata[k] = append(newdata[k], vv)
				}
			}
		}
	}
	return newdata
}
