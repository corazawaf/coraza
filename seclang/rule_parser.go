// Copyright 2022 Juan Pablo Tosso
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
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v2"
	actionsmod "github.com/corazawaf/coraza/v2/actions"
	operators "github.com/corazawaf/coraza/v2/operators"
	"github.com/corazawaf/coraza/v2/types"
	"github.com/corazawaf/coraza/v2/types/variables"
	utils "github.com/corazawaf/coraza/v2/utils/strings"
)

type ruleAction struct {
	Key   string
	Value string
	Atype types.RuleActionType
	F     coraza.RuleAction
}

// RuleParser is used to programatically create new rules using seclang formatted strings
type RuleParser struct {
	rule           *coraza.Rule
	defaultActions map[types.RulePhase][]ruleAction
	options        RuleOptions
}

// ParseVariables parses variables from a string and transforms it into
// variables, variable negations and variable counters.
// Multiple separated variables: VARIABLE1|VARIABLE2|VARIABLE3
// Variable count: &VARIABLE1
// Variable key negation: REQUEST_HEADERS|!REQUEST_HEADERS:user-agent
func (p *RuleParser) ParseVariables(vars string) error {

	// 0 = variable name
	// 1 = key
	// 2 = inside regex
	// 3 = inside xpath
	curr := 0
	isnegation := false
	iscount := false
	curvar := []byte{}
	curkey := []byte{}
	isescaped := false
	isquoted := false
	for i := 0; i < len(vars); i++ {
		c := vars[i]
		if (c == '|' && curr != 2) || i+1 >= len(vars) || (curr == 2 && c == '/' && !isescaped) {
			// if next variable or end
			// if regex we ignore |
			// we wont support pipe for xpath, maybe later
			if c != '|' {
				// we don't want to miss the last character
				if curr == 0 {
					curvar = append(curvar, c)
				} else if curr != 2 && c != '/' {
					// we don't want the last slash if it's a regex
					curkey = append(curkey, c)
				}
			}
			v, err := variables.Parse(string(curvar))
			if err != nil {
				return err
			}
			// fmt.Printf("(PREVIOUS %s) %s:%s (%t %t)\n", vars, curvar, curkey, iscount, isnegation)
			if isquoted {
				// if it is quoted we remove the last quote
				if len(vars) <= i+1 || vars[i+1] != '\'' {
					if vars[i] != '\'' {
						// TODO fix here
						return fmt.Errorf("unclosed quote: " + string(curkey))
					}
				}
				// we skip one additional character
				i += 2
				isquoted = false
			} else if curr == 2 {
				i++
			}

			key := string(curkey)
			if curr == 2 {
				// we are inside a regex
				key = fmt.Sprintf("/%s/", key)
			}
			if isnegation {
				err = p.rule.AddVariableNegation(v, key)
			} else {
				err = p.rule.AddVariable(v, key, iscount)
			}
			if err != nil {
				return err
			}
			curvar = []byte{}
			curkey = []byte{}
			iscount = false
			isnegation = false
			curr = 0
			continue
		}
		switch curr {
		case 0:
			switch c {
			case '!':
				isnegation = true
			case '&':
				iscount = true
			case ':':
				curr = 1
			default:
				curvar = append(curvar, c)
			}
		case 1:
			switch {
			case len(curkey) == 0 && (string(curvar) == "XML" || string(curvar) == "JSON"):
				// We are starting a XPATH
				curr = 3
				curkey = append(curkey, c)
			case c == '/':
				// We are starting a regex
				curr = 2
			case c == '\'':
				// we start a quoted regex
				// we go back to the loop to find /
				isquoted = true
			default:
				curkey = append(curkey, c)
			}
		case 2:
			// REGEX
			switch {
			case c == '/' && !isescaped:
				// unescaped / will stop the regex
				curr = 1
			case c == '\\':
				curkey = append(curkey, '\\')
				if isescaped {
					isescaped = false
				} else {
					isescaped = true
				}
			default:
				curkey = append(curkey, c)
			}
		case 3:
			// XPATH
			curkey = append(curkey, c)
		}
	}
	return nil
}

// ParseOperator parses a seclang formatted operator string
// A operator must begin with @ (like @rx), if no operator is specified, rx
// will be used. Everything after the operator will be used as operator argument
func (p *RuleParser) ParseOperator(operator string) error {
	// default operator @RX
	switch {
	case len(operator) == 0 || operator[0] != '@' && operator[0] != '!':
		operator = "@rx " + operator
	case len(operator) == 1 && operator == "!":
		operator = "!@rx"
	case len(operator) > 1 && operator[0] == '!' && operator[1] != '@':
		operator = "!@rx " + operator[1:]
	}

	spl := strings.SplitN(operator, " ", 2)
	op := strings.TrimSpace(spl[0])

	opdata := ""
	if len(spl) == 2 {
		opdata = strings.TrimSpace(spl[1])
	}
	if op[0] == '@' {
		// we trim @
		op = op[1:]
	} else if len(op) > 2 && op[0] == '!' && op[1] == '@' {
		// we trim !@
		op = op[2:]
	}

	opfn, err := operators.GetOperator(op)
	if err != nil {
		return err
	}
	data := []byte(opdata)
	// handling files by operators is hard because we must know the paths where we can
	// search, for example, the policy path or the binary path...
	// CRS stores the .data files in the same directory as the directives
	if strings.HasSuffix(op, "FromFile") {
		// TODO make enhancements here
		tpath := path.Join(p.options.Config.Get("parser_config_dir", "").(string), opdata)
		var err error
		content, err := os.ReadFile(tpath)
		if err != nil {
			return err
		}
		opdata = tpath
		data = content
	}
	err = opfn.Init(string(data))
	if err != nil {
		return err
	}
	p.rule.SetOperator(opfn, spl[0], opdata)
	return nil
}

// ParseDefaultActions parses a list of actions separated by a comma
// and assigns it to the specified phase.
// Default Actions MUST contain a phase
// Only one phase can be specified per WAF instance
// A disruptive action is required to be specified
// Each rule on the indicated phase will inherit the previously declared actions
// If the user overwrites the default actions, the default actions will be overwritten
func (p *RuleParser) ParseDefaultActions(actions string) error {
	act, err := parseActions(actions)
	if err != nil {
		return err
	}
	phase := types.RulePhase(0)
	defaultDisruptive := ""
	for _, action := range act {
		if action.Key == "phase" {
			phase, err = types.ParseRulePhase(action.Value)
			if err != nil {
				return err
			}
			continue
		}
		if action.Atype == types.ActionTypeDisruptive {
			defaultDisruptive = action.Key
		}
	}
	if phase == 0 {
		return errors.New("SecDefaultAction must contain a phase")
	}
	if defaultDisruptive == "" {
		return errors.New("SecDefaultAction must contain a disruptive action: " + actions)
	}
	p.defaultActions[types.RulePhase(phase)] = act
	return nil
}

// ParseActions parses a comma separated list of actions:arguments
// Arguments can be wrapper inside quotes
func (p *RuleParser) ParseActions(actions string) error {
	disabledActions := p.options.Config.Get("disabled_rule_actions", []string{}).([]string)
	act, err := parseActions(actions)
	if err != nil {
		return err
	}
	// check if forbidden action:
	for _, a := range act {
		if utils.InSlice(a.Key, disabledActions) {
			return fmt.Errorf("%s rule action is disabled", a.Key)
		}
	}
	// first we execute metadata rules
	for _, a := range act {
		if a.Atype == types.ActionTypeMetadata {
			errs := a.F.Init(p.rule, a.Value)
			if errs != nil {
				return errs
			}
		}
	}

	phase := p.rule.Phase

	defaults := p.defaultActions[phase]
	if defaults != nil {
		act = mergeActions(act, defaults)
	}

	for _, action := range act {
		// now we evaluate non-metadata actions
		if action.Atype == types.ActionTypeMetadata {
			continue
		}
		errs := action.F.Init(p.rule, action.Value)
		if errs != nil {
			return errs
		}
		if err := p.rule.AddAction(action.Key, action.F); err != nil {
			return err
		}
	}
	return nil
}

// Rule returns the compiled rule
func (p *RuleParser) Rule() *coraza.Rule {
	return p.rule
}

// RuleOptions contains the options used to compile a rule
type RuleOptions struct {
	WithOperator bool
	Waf          *coraza.Waf
	Config       types.Config
	Directive    string
	Data         string
}

// ParseRule parses a rule from a string
// The string must match the seclang format
// In case WithOperator is false, the rule will be parsed without operator
// This function is created for external plugin directives
func ParseRule(options RuleOptions) (*coraza.Rule, error) {
	var err error
	rp := &RuleParser{
		options:        options,
		rule:           coraza.NewRule(),
		defaultActions: map[types.RulePhase][]ruleAction{},
	}

	defaultActions := options.Config.Get("rule_default_actions", []string{}).([]string)
	disabledRuleOperators := options.Config.Get("disabled_rule_operators", []string{}).([]string)

	for _, da := range defaultActions {
		err = rp.ParseDefaultActions(da)
		if err != nil {
			return nil, err
		}
	}
	actions := ""
	if options.WithOperator {
		spl := strings.SplitN(options.Data, " ", 2)
		vars := spl[0]

		// regex: "(?:[^"\\]|\\.)*"
		r := regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
		matches := r.FindAllString(options.Data, -1)
		operator := utils.RemoveQuotes(matches[0])
		if utils.InSlice(operator, disabledRuleOperators) {
			return nil, fmt.Errorf("%s rule operator is disabled", operator)
		}
		err = rp.ParseVariables(vars)
		if err != nil {
			return nil, err
		}
		err = rp.ParseOperator(operator)
		if err != nil {
			return nil, err
		}
		if len(matches) > 1 {
			actions = utils.RemoveQuotes(matches[1])
			err = rp.ParseActions(actions)
			if err != nil {
				return nil, err
			}
		}
	} else {
		// quoted actions separated by comma (,)
		actions = utils.RemoveQuotes(options.Data)
		err = rp.ParseActions(actions)
		if err != nil {
			return nil, err
		}
	}
	rule := rp.Rule()
	rule.Raw = fmt.Sprintf("%s %s", options.Directive, options.Data)
	rule.File = options.Config.Get("parser_config_file", "").(string)
	rule.Line = options.Config.Get("parser_last_line", 0).(int)

	if parent := getLastRuleExpectingChain(options.Waf); parent != nil {
		rule.ParentID = parent.ID
		lastChain := parent
		for lastChain.Chain != nil {
			lastChain = lastChain.Chain
		}
		// TODO we must remove defaultactions from chains
		rule.Phase = 0
		lastChain.Chain = rule
		return nil, nil
	}
	return rp.rule, nil
}

func getLastRuleExpectingChain(w *coraza.Waf) *coraza.Rule {
	rules := w.Rules.GetRules()
	if len(rules) == 0 {
		return nil
	}
	lastRule := rules[len(rules)-1]
	parent := lastRule
	for parent.Chain != nil {
		parent = parent.Chain
	}
	// chain rules with ID -1 are not processed
	if parent.HasChain && parent.Chain == nil {
		return lastRule
	}
	return nil
}

// parseActions will assign the function name, arguments and
// function (pkg.actions) for each action split by comma (,)
// Action arguments are allowed to wrap values between colons('')
func parseActions(actions string) ([]ruleAction, error) {
	iskey := true
	ckey := ""
	cval := ""
	quoted := false
	res := []ruleAction{}
actionLoop:
	for i, c := range actions {
		switch {
		case iskey && c == ' ':
			// skip whitespaces in key
			continue actionLoop
		case !quoted && c == ',':
			f, err := actionsmod.GetAction(ckey)
			if err != nil {
				return nil, err
			}
			res = append(res, ruleAction{
				Key:   ckey,
				Value: cval,
				F:     f,
				Atype: f.Type(),
			})
			ckey = ""
			cval = ""
			iskey = true
		case iskey && c == ':':
			iskey = false
		case !iskey && c == '\'' && actions[i-1] != '\\':
			if quoted {
				quoted = false
				iskey = true
			} else {
				quoted = true
			}
		case !iskey:
			if c == ' ' && !quoted {
				// skip unquoted whitespaces
				continue actionLoop
			}
			cval += string(c)
		case iskey:
			ckey += string(c)
		}
		if i+1 == len(actions) {
			f, err := actionsmod.GetAction(ckey)
			if err != nil {
				return nil, err
			}
			res = append(res, ruleAction{
				Key:   ckey,
				Value: cval,
				F:     f,
				Atype: f.Type(),
			})
		}
	}
	return res, nil
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
func mergeActions(origin []ruleAction, defaults []ruleAction) []ruleAction {
	res := []ruleAction{}
	var da ruleAction // Disruptive action
	for _, action := range defaults {
		if action.Atype == types.ActionTypeDisruptive {
			da = action
			continue
		}
		if action.Atype == types.ActionTypeMetadata {
			continue
		}
		res = append(res, action)
	}
	hasDa := false
	for _, action := range origin {
		if action.Atype == types.ActionTypeDisruptive {
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
