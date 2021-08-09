// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package seclang

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	engine "github.com/jptosso/coraza-waf"
	actionsmod "github.com/jptosso/coraza-waf/actions"
	"github.com/jptosso/coraza-waf/operators"
	"github.com/jptosso/coraza-waf/utils"
	regex "github.com/jptosso/coraza-waf/utils/regex"
)

type ruleAction struct {
	Key   string
	Value string
	Atype int
	F     engine.Action
}

type RuleParser struct {
	rule           *engine.Rule
	Configdir      string
	defaultActions map[int][]ruleAction
}

func (p *RuleParser) ParseVariables(vars string) error {
	//Splits the values by KEY, KEY:VALUE, &!KEY, KEY:/REGEX/, KEY1|KEY2
	//GROUP 1 is collection, group 3 is vlue, group 3 can be empty
	//TODO this is not an elegant way to parse variables but it works and it won't generate workload
	re := regex.MustCompile(`(((?:&|!)?XML):?(.*?)(?:\||$))|((?:&|!)?[\w_]+):?([\w\-._]+|'?\/.*?(?<!\\)\/'?)?`, 0)
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

		collection, err := engine.NameToVariable(vname)
		if err != nil {
			return err
		}
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
	p.rule.Operator = new(engine.RuleOperator)

	if op[0] == '!' {
		p.rule.Operator.Negation = true
		op = utils.TrimLeftChars(op, 1)
	}
	if op[0] == '@' {
		op = utils.TrimLeftChars(op, 1)
		if len(spl) == 2 {
			p.rule.Operator.Data = spl[1]
		}
	}
	if op == "unconditionalMatch" {
		p.rule.AlwaysMatch = true
	}

	p.rule.Operator.Operator = operators.OperatorsMap()[op]
	if p.rule.Operator.Operator == nil {
		return errors.New("Invalid operator " + op)
	} else {
		//TODO add a special attribute to accept files
		fileops := []string{"ipMatchFromFile", "pmFromFile"}
		for _, fo := range fileops {
			if fo == op {
				p.rule.Operator.Data = path.Join(p.Configdir, p.rule.Operator.Data)
				if _, err := os.Stat(p.rule.Operator.Data); errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("cannot find file %s", p.rule.Operator.Data)
				}
			}
		}
		err := p.rule.Operator.Operator.Init(p.rule.Operator.Data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *RuleParser) ParseDefaultActions(actions string) error {
	act, err := ParseActions(actions)
	if err != nil {
		return err
	}
	phase := 0
	defaultDisruptive := ""
	for _, action := range act {
		if action.Key == "phase" {
			phase, err = PhaseToInt(action.Value)
			if err != nil {
				return err
			}
			continue
		}
		if action.Atype == engine.ACTION_TYPE_DISRUPTIVE {
			defaultDisruptive = action.Key
		}
	}
	if phase == 0 {
		return errors.New("SecDefaultAction must contain a phase")
	}
	if defaultDisruptive == "" {
		return errors.New("SecDefaultAction must contain a disruptive action: " + actions)
	}
	p.defaultActions[phase] = act
	return nil
}

// ParseActions
func (p *RuleParser) ParseActions(actions string) error {
	act, _ := ParseActions(actions)
	//first we execute metadata rules
	for _, a := range act {
		if a.Atype == engine.ACTION_TYPE_METADATA {
			errs := a.F.Init(p.rule, a.Value)
			if errs != nil {
				return errs
			}
		}
	}

	phase := p.rule.Phase

	defaults := p.defaultActions[phase]
	if defaults != nil {
		act = MergeActions(act, defaults)
	}

	for _, action := range act {
		errs := action.F.Init(p.rule, action.Value)
		if errs != nil {
			return errs
		}
		p.rule.Actions = append(p.rule.Actions, action.F)
	}
	return nil
}

// Rule returns the compiled rule
func (p *RuleParser) Rule() *engine.Rule {
	return p.rule
}

// NewRuleParser Creates a new rule parser, each rule parser
// will contain a single rule that can be obtained using ruleparser.Rule()
func NewRuleParser() *RuleParser {
	rp := &RuleParser{
		rule:           engine.NewRule(),
		defaultActions: map[int][]ruleAction{},
	}
	return rp
}

// ParseActions will assign the function name, arguments and
// function (pkg.actions) for each action splitted by comma (,)
// Action arguments are allowed to wrap values between collons('')
func ParseActions(actions string) ([]ruleAction, error) {
	iskey := true
	ckey := ""
	cval := ""
	quoted := false
	res := []ruleAction{}
	for i, c := range actions {
		if iskey && c == ' ' {
			//skip whitespaces in key
			continue
		} else if !quoted && c == ',' {
			f := actionsmod.ActionsMap()[ckey]
			if f == nil {
				return nil, errors.New("Invalid action " + ckey)
			}
			res = append(res, ruleAction{
				Key:   ckey,
				Value: cval,
				F:     f,
				Atype: f.GetType(),
			})
			ckey = ""
			cval = ""
			iskey = true
		} else if iskey && c == ':' {
			iskey = false
		} else if !iskey && c == '\'' && actions[i-1] != '\\' {
			if quoted {
				quoted = false
				iskey = true
			} else {
				quoted = true
			}
		} else if !iskey {
			if c == ' ' && !quoted {
				//skip unquoted whitespaces
				continue
			}
			cval += string(c)
		} else if iskey {
			ckey += string(c)
		}
		if i+1 == len(actions) {
			f := actionsmod.ActionsMap()[ckey]
			if f == nil {
				return nil, fmt.Errorf("invalid action %s", ckey)
			}
			res = append(res, ruleAction{
				Key:   ckey,
				Value: cval,
				F:     f,
				Atype: f.GetType(),
			})
		}
	}
	return res, nil
}

// PhaseToInt transforms a phase string to it's integer
// value, modsecurity allows request(1), response(3), log(5),
// 1,2,3,4,5 values
func PhaseToInt(phase string) (int, error) {
	if phase == "request" {
		return 1, nil
	} else if phase == "response" {
		return 3, nil
	} else if phase == "log" {
		return 5, nil
	}
	p, err := strconv.Atoi(phase)

	if err != nil || p < 0 || p > 5 {
		return 0, errors.New("Invalid phase " + phase)
	}
	// This should never happen (?)
	return p, nil
}

/*
So here is my research:
SecDefaultAction must contain a phase and a disruptive action
They will only be merged if the match the same phase
If the rule disruptive action is block it will inherit the defaultaction disruptive actions
DefaultAction's disruptive action will be added to the rule only if there is no DA or DA is block
If we have:
SecDefaultAction "phase:2,deny,status:403,log"
Then we have a Rule:
SecAction "id:1, phase:2, block, nolog"
The rule ID 1 will inherit default actions and become
SecAction "id:1, phase:2, status:403, log, nolog, deny"
In the future I shall optimize that redundant log and nolog, it won't actually change anything but would look cooler
*/
func MergeActions(origin []ruleAction, defaults []ruleAction) []ruleAction {
	res := []ruleAction{}
	var da ruleAction //Disruptive action
	for _, action := range defaults {
		if action.Atype == engine.ACTION_TYPE_DISRUPTIVE {
			da = action
			continue
		}
		if action.Atype == engine.ACTION_TYPE_METADATA {
			continue
		}
		res = append(res, action)
	}
	hasDa := false
	for _, action := range origin {
		if action.Atype == engine.ACTION_TYPE_DISRUPTIVE {
			if action.Key != "block" {
				hasDa = true
				// We add the default rule DA in case this is no block
				res = append(res, action)
			}
		} else {
			res = append(res, action)
		}
	}
	if !hasDa {
		// We add the default disruptive action if there is no DA in rule or DA is block
		res = append(res, da)
	}

	return res
}
