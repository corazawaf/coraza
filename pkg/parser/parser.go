package parser

import(
	"github.com/jptosso/coraza-waf/pkg/utils"
	"github.com/jptosso/coraza-waf/pkg/operators"
	actionsmod"github.com/jptosso/coraza-waf/pkg/actions"
	"github.com/jptosso/coraza-waf/pkg/engine"
	pcre"github.com/gijsbers/go-pcre"
	"os"
	"strings"
	"net/http"
	"fmt"
	"bufio"
	"time"
	"errors"
	"path"
	"strconv"
	"regexp"
)

type Parser struct {
	nextChain bool
	RuleEngine string
	waf *engine.Waf
}

func (p *Parser) Init(waf *engine.Waf) {
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
	//opts = strings.Trim(opts, `"`)
	switch(directive){
	//SecAuditEngine
	case "SecAuditLog":
		p.waf.AuditLogPath1 = opts
		break
	case "SecAuditLog2":
		p.waf.AuditLogPath2 = opts
		break
	case "SecAuditLogDirMode":
		p.waf.AuditLogDirMode, _ = strconv.Atoi(opts)
		break
	case "SecAuditLogFileMode":
		p.waf.AuditLogFileMode, _ = strconv.Atoi(opts)
		break
	case "SecAuditLogParts":
		p.waf.AuditLogParts = []int{}
		data := []rune(opts)
		for _,c := range data{
			ascii := int(c) //a = 97 // k = 107
			if c > 107 || c < 97{
				fmt.Println("Invalid Audit Log Part " + string(c))
				continue
			}
			p.waf.AuditLogParts = append(p.waf.AuditLogParts, ascii-97)
		}
		break
	case "SecAuditLogRelevantStatus":
		p.waf.AuditLogRelevantStatus = regexp.MustCompile(opts)
		break
	case "SecAuditLogStorageDir":
		p.waf.AuditLogStorageDir = opts
		//TODO validate access to directory
		break
	case "SecAuditLogType":
		switch opts{
		case "Concurrent":
			p.waf.AuditLogType = engine.AUDIT_LOG_CONCURRENT
			break
		case "HTTPS":
			p.waf.AuditLogType = engine.AUDIT_LOG_HTTPS
			break
		}
		break
	case "SecCollectionTimeout":
		p.waf.CollectionTimeout, _ = strconv.Atoi(opts)
		break
	case "SecConnEngine":
		switch opts{
		case "On":
			p.waf.ConnEngine = engine.CONN_ENGINE_ON
			break
		case "Off":
			p.waf.ConnEngine = engine.CONN_ENGINE_OFF
			break
		case "DetectOnly":
			p.waf.ConnEngine = engine.CONN_ENGINE_DETECTONLY
			break
		}
		break
	case "SecContentInjection":
		p.waf.ContentInjection = (opts == "On")
		break
	case "SecDebugLog":
		p.waf.DebugLog = opts
		break
	case "SecDefaultAction":
		p.waf.DefaultAction = opts
		break
	case "SecHashEngine":
		p.waf.HashEngine = (opts == "On")
		break
	case "SecHashKey":
		p.waf.HashKey = opts
		break
	case "SecHashParam":

		break
	case "SecHashMethodRx":

		break
	case "SecHashMethodPm":

		break
	case "SecGeoLookupDb":
		p.waf.InitGeoip(opts)
		break
	case "SecGsbLookupDb":

		break
	case "SecGuardianLog":

		break
	case "SecHttpBlKey":
		p.waf.HttpBlKey = opts
		break
	case "SecInterceptOnError":
		p.waf.InterceptOnError = (opts == "On")
		break
	case "SecPcreMatchLimit":
		p.waf.PcreMatchLimit, _ = strconv.Atoi(opts)
		break
	case "SecPcreMatchLimitRecursion":
		//TODO PCRE RECURSIONLIMIT is hardcoded inside the binary :( we have to figure out something
		fmt.Println("SecPcreMatchLimitRecursion TO BE IMPLEMENTED. I'm stil trying to figure it out :(")
		break
	case "SecConnReadStateLimit":
		p.waf.ConnReadStateLimit, _ = strconv.Atoi(opts)
		break
	case "SecSensorId":
		p.waf.SensorId = opts
		break
	case "SecConnWriteStateLimit":
		p.waf.ConnWriteStateLimit, _ = strconv.Atoi(opts)
		break
	case "SecRemoteRules":
		spl := strings.SplitN(opts, " ", 2)
		key := spl[0]
		url := spl[1]
		client := &http.Client{
			Timeout: time.Second * 30,
		}
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("ModSec-key", key)
		res, err := client.Do(req)
		if err != nil {
			if p.waf.AbortOnRemoteRulesFail{
				fmt.Println("Unable to fetch remote rules")
				os.Exit(255)
				return err
			}
			return err
		}
		defer res.Body.Close()
		b := bufio.NewScanner(res.Body)
		p.FromString(b)
		break
	case "SecRemoteRulesFailAction":
		p.waf.AbortOnRemoteRulesFail = (opts == "Abort")
		break
	case "SecRequestBodyInMemoryLimit":
		p.waf.RequestBodyInMemoryLimit, _ = strconv.ParseInt(opts, 10, 64)
		break
	case "SecRequestBodyLimitAction":
		p.waf.RejectOnRequestBodyLimit = (opts == "Reject")
		break
	case "SecResponseBodyLimit":
		p.waf.ResponseBodyLimit, _ = strconv.ParseInt(opts, 10, 64)
		break
	case "SecResponseBodyLimitAction":
		p.waf.RejectOnResponseBodyLimit = (opts == "Reject")
		break
	case "SecResponseBodyMimeType":
		p.waf.ResponseBodyMimeTypes = strings.Split(opts, " ")
		break
	case "SecResponseBodyMimeTypesClear":
		p.waf.ResponseBodyMimeTypes = []string{}
		break
	case "SecRuleInheritance":
		fmt.Println("SecRuleInheritance TO BE IMPLEMENTED.")
		break
	case "SecRulePerfTime":
		fmt.Println("SecRulePerfTime TO BE IMPLEMENTED.")
		break
	case "SecRuleRemoveById":
		id, _ := strconv.Atoi(opts)
		p.waf.DeleteRuleById(id)
		break
	case "SecRuleRemoveByMsg":
		for _, r := range p.waf.FindRulesByMsg(opts){
			p.waf.DeleteRuleById(r.Id)
		}
		break
	case "SecRuleRemoveByTag":
		for _, r := range p.waf.FindRulesByTag(opts){
			p.waf.DeleteRuleById(r.Id)
		}
		break
	case "SecRuleScript":
		fmt.Println("SecRuleScript TO BE IMPLEMENTED, USE ACTION EXEC.")
		break
	case "SecRuleUpdateActionById":
		//r := p.waf.FindRuleById(0)	
		fmt.Println("SecRuleUpdateActionById TO BE IMPLEMENTED.")
		break
	case "SecRuleUpdateTargetById":
		spl := strings.SplitN(opts, " ", 2)
		id, _ := strconv.Atoi(spl[0])
		p.waf.FindRuleById(id)
		fmt.Println("SecRuleUpdateTargetById TO BE IMPLEMENTED.")
		break
	case "SecRuleUpdateTargetByMsg":
		/*
		spl := strings.SplitN(opts, " ", 2)
		for _, r := range p.waf.FindRulesByMsg(spl[0]){
			
		}		
		*/
		fmt.Println("SecRuleUpdateTargetByMsg TO BE IMPLEMENTED.")
		break
	case "SecRuleUpdateTargetByTag":
		/*
		spl := strings.SplitN(opts, " ", 2)			
		for r := range p.waf.FindRulesByTag(spl[0]){

		}*/
		break
	case "SecServerSignature":
		p.waf.ServerSignature = opts
		break
	case "SecStreamOutBodyInspection":
		p.waf.StreamOutBodyInspection = (opts == "Abort")
		break
	case "SecTmpDir":
		p.waf.TmpDir = opts
		break
	case "SecUploadDir":
		p.waf.UploadDir = opts
		break
	case "SecUploadFileLimit":
		p.waf.UploadFileLimit, _ = strconv.Atoi(opts)
		break
	case "SecUploadFileMode":
		p.waf.UploadFileMode, _ = strconv.Atoi(opts)
		break
	case "SecUploadKeepFiles":
		break
	case "SecWebAppId":
		p.waf.WebAppId = opts
		break
	case "SecXmlExternalEntity":
		break
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
		nr.Phase = lastrule.Phase //TODO: Is this the right way? or maybe it should have a special phase that always runs
	case "SecComponentSignature":
		p.waf.ComponentSignature = opts
	default:
		return errors.New("Unsupported directive " + directive)
	}
	return nil
}

func (p *Parser) ParseRule(data string) (*engine.Rule, error){
	var rule = new(engine.Rule)
	rule.Init()
	rule.Raw = "SecRule " + data

	spl := strings.SplitN(data, " ", 2)
    rule.Vars = utils.RemoveQuotes(spl[0])

    //regex: "(?:[^"\\]|\\.)*"
    r := regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
    matches := r.FindAllString(data, -1)
    operators := utils.RemoveQuotes(matches[0])
    actions := ""
	p.compileRuleVariables(rule, rule.Vars)
	p.compileRuleOperator(rule, operators)

	//TODO ADD DEFAULT ACTIONS FROM SECDEFAULTACTIONS
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

func (p *Parser) compileRuleVariables(r *engine.Rule, vars string) {
	//Splits the values by KEY, KEY:VALUE, &!KEY, KEY:/REGEX/, KEY1|KEY2
	//GROUP 1 is collection, group 3 is vlue, group 3 can be empty
	re := pcre.MustCompile(`((?:&|!)?[\w_]+)((?::)(\w+|\/(.*?)(?<!\\)\/))?`, 0)
	matcher := re.MatcherString(vars, 0)
	subject := []byte(vars)	
	for matcher.Match(subject, 0){
		vname := matcher.GroupString(1)
		vvalue := matcher.GroupString(3)
		index := matcher.Index()
		counter := false
		negation := false

		if vname[0] == '&'{
			vname = vname[1:]
			counter = true
		}
		if vname[0] == '!'{
			vname = vname[1:]
			negation = true
		}
		/*
		if len(vvalue) > 0  && vvalue[0] == '/'{
			//we strip slahes (/)
			vvalue = vvalue[1:len(vvalue)-1]
		}
	    */
	    
		context := "transaction" //TODO WTF?
		collection := strings.ToLower(vname)
		//key = strings.ToLower(key)
		if negation{
			r.AddNegateVariable(collection, vvalue)
		}else{
			r.AddVariable(counter, collection, vvalue, context) 
		}

	    subject = subject[index[1]:]
	    if len(subject) == 0{
	    	break
	    }
	}
}


func (p *Parser) compileRuleOperator(r *engine.Rule, operator string) {
	if operator[0] != '@' && operator[1] != '@'{
		//default operator RX
		operator = "@rx " + operator
	}
	spl := strings.SplitN(operator, " ", 2)
	op := spl[0]
	r.Operator = operator
	r.OperatorObj = new(engine.RuleOp)
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

func (p *Parser) compileRuleActions(r *engine.Rule, actions string) error{
	//REGEX: ((.*?)((?<!\\)(?!\B'[^']*),(?![^']*'\B)|$))
	//This regex splits actions by comma and assign key:values with supported escaped quotes
	re := pcre.MustCompile(`(.*?)((?<!\\)(?!\B'[^']*),(?![^']*'\B)|$)`, 0)
	matcher := re.MatcherString(actions, 0)
	subject := []byte(actions)
    errorlist := []string{}
    actions = p.waf.DefaultAction + actions //we add the defaultactions
    actionsmap := actionsmod.ActionsMap()
	for matcher.Match(subject, 0){
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
			action.Init(r, value, errorlist)
			r.Actions = append(r.Actions, action)
		}
	    subject = subject[index[1]:]
	    if len(subject) == 0{
	    	break
	    }
	}	
	return nil
}