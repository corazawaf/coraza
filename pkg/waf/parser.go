package waf

import(
	"github.com/jptosso/coraza-waf/pkg/utils"
	"github.com/jptosso/coraza-waf/pkg/waf/operators"
	actionsmod"github.com/jptosso/coraza-waf/pkg/waf/actions"
	"github.com/jptosso/coraza-waf/pkg/models"
	pcre"github.com/gijsbers/go-pcre"
	"os"
	"strings"
	"fmt"
	"bufio"
	"regexp"
	"errors"
	"path"
	"strconv"
)

type Parser struct {
	nextChain bool
	RuleEngine string
	waf *Waf
}

func (p *Parser) Init(waf *Waf) {
	p.waf = waf
}


func (p *Parser) FromFile(profilePath string) error{
	//Log.Debug("Opening profile " + profilePath)
    file, err := os.Open(profilePath)
    if err != nil {
        return err
    }
    defer file.Close()

    err = p.FromString(bufio.NewScanner(file))
    if err != nil{
    	return err
    }
    //TODO validar el error de scanner.Err()
	return nil
}

func (p *Parser) FromString(scanner *bufio.Scanner) error{
    var linebuffer = ""
    for scanner.Scan() {
        line := scanner.Text()
        linebuffer += strings.TrimSpace(line)
        //Check if line ends with \
        match, _ := regexp.MatchString(`\\(\s+)?$`, line)
        if !match {
        	err := p.Evaluate(linebuffer)
        	if err != nil{
        		return err
        	}
        	linebuffer = ""
        }else{
        	linebuffer = strings.TrimSuffix(linebuffer, "\\")
        }
    }
    return nil
}

func (p *Parser) Evaluate(data string) error{
	//Log.Debug("Evaluating line " + data)
	if data == "" || data[0] == '#'{
		return nil
	}
	//first we get the directive
	spl := strings.SplitN(data, " ", 2)
	if len(spl) != 2{
		return errors.New("Invalid syntaxis, expected [directive] [options] for: \n" + data)
	}
	directive := spl[0]
	opts := spl[1]

	//Log.Debug(fmt.Sprintf("Directive: %s, Options: %s", directive, opts))
	switch(directive){
	case "SecRuleEngine":
		p.waf.RuleEngine = (opts == "On")
	case "SecRequestBodyAccess":
		p.waf.RequestBodyAccess = (opts == "On")
	case "SecRequestBodyLimit":
		limit, err := strconv.ParseInt(opts, 10, 64)
		if err != nil{
			fmt.Println("Invalid SecRequestBodyLimit, setting 0")
			limit = 0
		}
		p.waf.RequestBodyLimit = limit
	case "SecResponseBodyAccess":
		p.waf.ResponseBodyAccess = (opts == "On")
	case "SecRule":
		p.ParseRule(opts)
	case "SecAction":
		p.ParseRule("RULE \"@unconditionalMatch\" " + opts)
	case "SecMarker":
		//we create a rule with the next id
		lastrule := p.waf.Rules[len(p.waf.Rules)-1]
		nid := 1
		if lastrule != nil{
			nid = lastrule.Id + 1
		}
		nr, _ := p.ParseRule(fmt.Sprintf("\"@unconditionalMatch\" \"id:%d, nolog, noauditlog, pass\"", nid))
		nr.SecMark = strings.Trim(opts, `"`)
	case "SecComponentSignature":

	default:
		return errors.New("Unsupported directive " + directive)
	}
	return nil
}

func (p *Parser) ParseRule(data string) (*Rule, error){
	var rule = new(Rule)
	rule.Init()

	spl := strings.SplitN(data, " ", 2)
    rule.Vars = utils.RemoveQuotes(spl[0])

    //regex: "(?:[^"\\]|\\.)*"
    r := regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
    matches := r.FindAllString(data, -1)
    operators := utils.RemoveQuotes(matches[0])
    actions := ""
	p.compileRuleVariables(rule, rule.Vars)
	p.compileRuleOperator(rule, operators)

	if len(matches) > 1{
    	actions = utils.RemoveQuotes(matches[1])
		p.compileRuleActions(rule, actions)
	}

	if p.nextChain{
		p.nextChain = false
		parent := p.waf.Rules[len(p.waf.Rules)-1]
		rule.ParentId = parent.Id
		lastchain := parent

		for lastchain.Chain != nil{
			lastchain = lastchain.Chain
		}

		lastchain.Chain = rule
	}else{
		p.waf.Rules = append(p.waf.Rules, rule)
	}
	if rule.HasChain{
		p.nextChain = true
	}
	return rule, nil
}

func (p *Parser) compileRuleVariables(r *Rule, vars string) {
	//TODO: in case on | inside regex, everything will break
	//escenario bug: ARGS:/^(id_|test_)/

	//escenario normal: ARGS:id
	spl := strings.Split(vars, "|")
	for _, x := range spl {
		negation := false
		count := false
		collection := ""
		key := ""		
		if  x[0] == '&'{
			count = true
			x = utils.TrimLeftChars(x, 1)
		}else if x[0] == '!'{
			negation = true
			x = utils.TrimLeftChars(x, 1)
		}		
		//[0] = ARGS [1] = id
		spl2 := strings.SplitN(x, ":", 2)
		collection = spl2[0]
		if len(spl2) == 2{
			key = strings.ToLower(spl2[1])
		}

		context := "transaction" //TODO WTF?
		collection = strings.ToLower(collection)
		//key = strings.ToLower(key)
		if negation{
			r.AddNegateVariable(collection, key)
		}else{
			r.AddVariable(count, collection, key, context) 
		}
	}
}


func (p *Parser) compileRuleOperator(r *Rule, operator string) {
	//Log.Debug(fmt.Sprintf("Loading operator: \"%s\"", operator))
	//TODO mejorar esto
	if operator[0] != '@' && operator[1] != '@'{
		//default operator RX
		operator = "@rx " + operator
	}
	spl := strings.SplitN(operator, " ", 2)
	op := spl[0]
	r.Operator = operator
	r.OperatorObj = new(models.RuleOp)
	//optimizar!
	if op[0] == '!' {
		//Log.Debug("Negated operator")
		r.OperatorObj.Negation = true
		op = utils.TrimLeftChars(op, 1)
	}
	if op[0] == '@' {
		op = utils.TrimLeftChars(op, 1)
		//Log.Debug("Loaded operator " + op)
		if len(spl) == 2 {
			r.OperatorObj.Data = spl[1]
		}
	}
	//TODO validar que existe
	r.OperatorObj.Operator = operators.OperatorsMap()[op]
	if op == "pmFromFile"{
		r.OperatorObj.Data = path.Join(p.waf.Datapath, r.OperatorObj.Data)
	}
	if r.OperatorObj.Operator == nil{
		fmt.Println("Invalid operator " + op )
	}else{
		r.OperatorObj.Operator.Init(r.OperatorObj.Data)
	}
}

//ugly code, please fix :C TODO
func (p *Parser) compileRuleActions(r *Rule, actions string) error{
	//Log.Debug(fmt.Sprintf("Loading actions: \"%s\"", actions))
	//REGEX: ((.*?)((?<!\\)(?!\B'[^']*),(?![^']*'\B)|$))
	//Este regex separa las acciones por coma e ignora backslashs y textos entre comillas
	//re := pcre.MustCompile(`(((.*?)((?<!\\)(?!\B'[^']*),(?![^']*'\B)|$)))`, 0)
	re := pcre.MustCompile(`(.*?)((?<!\\)(?!\B'[^']*),(?![^']*'\B)|$)`, 0)
	matcher := re.MatcherString(actions, 0)
	subject := []byte(actions)
    errorlist := []string{}
	for matcher.Match(subject, 0){
    	actionsmap := actionsmod.ActionsMap()
		m := matcher.GroupString(1)
		index := matcher.Index()
		spl := strings.SplitN(m, ":", 2)
		value := ""
		key := strings.Trim(spl[0], " ")
		if len(spl) == 2{
			value = spl[1]
		}
		if actionsmap[key] == nil{
			fmt.Printf("Error, invalid action: %s\n", key)
			//return fmt.Errorf("Invalid action %s", key)
		}else{
			action := actionsmap[key]
			action.Init(&r.Rule, value, errorlist)
			r.Actions = append(r.Actions, action)
		}
	    subject = subject[index[1]:]
	    if len(subject) == 0{
	    	break
	    }
	}	
	return nil
}