package parser

import(
	"github.com/jptosso/coraza-waf/pkg/utils"
	"github.com/jptosso/coraza-waf/pkg/operators"
	"github.com/jptosso/coraza-waf/pkg/engine"
	log"github.com/sirupsen/logrus"
	actionsmod"github.com/jptosso/coraza-waf/pkg/actions"
	pcre"github.com/gijsbers/go-pcre"
	"strings"
	"net/http"
	"io/ioutil"
	"fmt"
	"bufio"
	"time"
	"errors"
	"strconv"
	"regexp"
)

type Parser struct {
	nextChain bool
	RuleEngine string
	waf *engine.Waf

	nextSecMark string
	defaultActions string
	currentLine int
}

func (p *Parser) Init(waf *engine.Waf) {
	p.waf = waf
}

func (p *Parser) FromFile(profilePath string) error{
    file, err := utils.OpenFile(profilePath)
    if err != nil {
    	p.log("Cannot open profile path " + profilePath)
        return err
    }

    err = p.FromString(string(file))
    if err != nil{
    	log.Error("Cannot parse configurations")
    	return err
    }
    //TODO validar el error de scanner.Err()
	return nil
}

func (p *Parser) FromString(data string) error{
	scanner := bufio.NewScanner(strings.NewReader(data))
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
	if data == "" || data[0] == '#'{
		return nil
	}
	//first we get the directive
	spl := strings.SplitN(data, " ", 2)
	if len(spl) != 2{
		return p.log("Invalid syntaxis, expected [directive] [options]")
	}
	log.Debug("Parsing directive: " + data)
	directive := spl[0]
	opts := spl[1]

	if len(opts) >= 3 && opts[0] == '"' && opts[len(opts)-1] == '"'{
		opts = strings.Trim(opts, `"`)
	}
	switch(directive){
	case "SecAuditEngine":
		switch opts{
		case "On":
			p.waf.AuditEngine = engine.AUDIT_LOG_ENABLED
		case "Off":
			p.waf.AuditEngine = engine.AUDIT_LOG_DISABLED
		case "RelevantOnly":
			p.waf.AuditEngine = engine.AUDIT_LOG_RELEVANT
		}
	case "SecAuditLog":
		p.waf.AuditLogPath = opts
		break
	case "SecAuditLogDirMode":
		p.waf.AuditLogDirMode, _ = strconv.Atoi(opts)
		break
	case "SecAuditLogFileMode":
		p.waf.AuditLogFileMode, _ = strconv.Atoi(opts)
		break
	case "SecAuditLogParts":
		p.waf.AuditLogParts = []int{}
		for _, c := range opts{
			var val int
			switch c{
				case 'A':
					val = engine.AUDIT_LOG_PART_HEADER
					break
				case 'B':
					val = engine.AUDIT_LOG_PART_REQUEST_HEADERS
					break
				case 'C':
					val = engine.AUDIT_LOG_PART_REQUEST_BODY
					break
				case 'D':
					val = engine.AUDIT_LOG_PART_RESERVED_1
					break
				case 'E':
					val = engine.AUDIT_LOG_PART_INT_RESPONSE_BODY
					break
				case 'F':
					val = engine.AUDIT_LOG_PART_FIN_RESPONSE_BODY
					break
				case 'G':
					val = engine.AUDIT_LOG_PART_FIN_RESPONSE_HEADERS
					break
				case 'H':
					val = engine.AUDIT_LOG_PART_RESPONSE_BODY
					break
				case 'I':
					val = engine.AUDIT_LOG_PART_AUDIT_LOG_TRAIL
					break
				case 'J':
					val = engine.AUDIT_LOG_PART_FILES_MULTIPART
					break
				case 'K':
					val = engine.AUDIT_LOG_PART_ALL_MATCHED_RULES
					break
				case 'Z':
					val = engine.AUDIT_LOG_PART_FINAL_BOUNDARY
					break
				default:
					return p.log("Invalid log part " + string(c))
			}
			//TODO validate repeated parts
			p.waf.AuditLogParts = append(p.waf.AuditLogParts, val)
		}
		break
	case "SecAuditLogRelevantStatus":
		p.waf.AuditLogRelevantStatus = pcre.MustCompile(opts, 0)
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
		//p.waf.CollectionTimeout, _ = strconv.Atoi(opts)
		break
	case "SecConnEngine":
		/*
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
		*/
	case "SecContentInjection":
		//p.waf.ContentInjection = (opts == "On")
		break
	case "SecDefaultAction":
		p.defaultActions = opts
		break
	case "SecHashEngine":
		// p.waf.HashEngine = (opts == "On")
		break
	case "SecHashKey":
		//p.waf.HashKey = opts
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
		//p.waf.HttpBlKey = opts
		break
	case "SecInterceptOnError":
		//p.waf.InterceptOnError = (opts == "On")
		break
	case "SecPcreMatchLimit":
		// p.waf.PcreMatchLimit, _ = strconv.Atoi(opts)
		break
	case "SecPcreMatchLimitRecursion":
		//TODO PCRE RECURSIONLIMIT is hardcoded inside the binary :( we have to figure out something
		fmt.Println("SecPcreMatchLimitRecursion TO BE IMPLEMENTED. I'm stil trying to figure it out :(")
		break
	case "SecConnReadStateLimit":
		// p.waf.ConnReadStateLimit, _ = strconv.Atoi(opts)
		break
	case "SecSensorId":
		// p.waf.SensorId = opts
		break
	case "SecConnWriteStateLimit":
		// p.waf.ConnWriteStateLimit, _ = strconv.Atoi(opts)
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
				return p.log("Unable to fetch remote rules")
			}
			return err
		}
		defer res.Body.Close()
		b, _ := ioutil.ReadAll(res.Body)
		p.FromString(string(b))
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
		p.waf.Rules.DeleteById(id)
		break
	case "SecRuleRemoveByMsg":
		for _, r := range p.waf.Rules.FindByMsg(opts){
			p.waf.Rules.DeleteById(r.Id)
		}
		break
	case "SecRuleRemoveByTag":
		for _, r := range p.waf.Rules.FindByTag(opts){
			p.waf.Rules.DeleteById(r.Id)
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
		p.waf.Rules.FindById(id)
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
		//p.waf.StreamOutBodyInspection = (opts == "Abort")
		break
	case "SecTmpDir":
		p.waf.TmpDir = opts
		break
	case "SecUploadDir":
		//p.waf.UploadDir = opts
		break
	case "SecUploadFileLimit":
		//p.waf.UploadFileLimit, _ = strconv.Atoi(opts)
		break
	case "SecUploadFileMode":
		//p.waf.UploadFileMode, _ = strconv.Atoi(opts)
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
		rule, err := p.ParseRule(opts)
		if err != nil{
			return err
		}
		p.waf.Rules.Add(rule)
	case "SecAction":
		p.ParseRule("RULE \"@unconditionalMatch\" " + opts)
	case "SecMarker":
		p.nextSecMark = opts
	case "SecComponentSignature":
		p.waf.ComponentSignature = opts
	case "SecErrorPage":
		if len(opts) < 2{
			return p.log("Invalid SecErrorPage value")
		}
		if opts == "debug"{
			p.waf.ErrorPageMethod = engine.ERROR_PAGE_DEBUG
		}else if opts[0] == '|'{
			file := opts[1:]
			p.waf.ErrorPageMethod = engine.ERROR_PAGE_SCRIPT
			p.waf.ErrorPageFile = file
		}else if opts[0] == '/'{
			file, err := utils.OpenFile(opts)
			if err != nil{
				p.log("Cannot open SecErrorPage, keeping default value.")
				break
			}
			p.waf.ErrorPageMethod = engine.ERROR_PAGE_FILE
			p.waf.ErrorPageFile = string(file)
		}else{
			p.waf.ErrorPageMethod = engine.ERROR_PAGE_INLINE
			p.waf.ErrorPageFile = opts
		}
	default:
		return p.log("Unsupported directive: " + directive)
	}
	return nil
}

func (p *Parser) ParseRule(data string) (*engine.Rule, error){
	var err error
	var rule = new(engine.Rule)
	rule.Init()
	rule.Raw = "SecRule " + data

	spl := strings.SplitN(data, " ", 2)
    rule.Vars = utils.RemoveQuotes(spl[0])

    //regex: "(?:[^"\\]|\\.)*"
    r := regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
    matches := r.FindAllString(data, -1)
    actions := ""
    operators := utils.RemoveQuotes(matches[0])
	err = p.compileRuleVariables(rule, rule.Vars)
	if err != nil{
		return nil, err
	}
	err = p.compileRuleOperator(rule, operators)
	if err != nil{
		return nil, err
	}	
	if len(matches) > 1{
    	actions = utils.RemoveQuotes(matches[1])
    	err = p.compileRuleActions(rule, actions) 
		if err != nil{
			return nil, err
		}
	}

	if p.nextChain{
		p.nextChain = false
		rules := p.waf.Rules.GetRules()
		parent := rules[len(rules)-1]
		rule.ParentId = parent.Id
		lastchain := parent

		for lastchain.Chain != nil{
			lastchain = lastchain.Chain
		}

		lastchain.Chain = rule
	}
	if rule.HasChain{
		p.nextChain = true
	}
	rule.SecMark = p.nextSecMark
	return rule, nil
}

func (p *Parser) compileRuleVariables(r *engine.Rule, vars string) error{
	//Splits the values by KEY, KEY:VALUE, &!KEY, KEY:/REGEX/, KEY1|KEY2
	//GROUP 1 is collection, group 3 is vlue, group 3 can be empty
	//TODO this is not an elegant way to parse variables but it works and it won't generate workload
	re := pcre.MustCompile(`(((?:&|!)?XML):?(.*?)(?:\||$))|((?:&|!)?[\w_]+):?([\w-_]+|\/.*?(?<!\\)\/)?`, 0)
	matcher := re.MatcherString(vars, 0)
	subject := []byte(vars)	
	for matcher.Match(subject, 0){
		vname := matcher.GroupString(4)
		vvalue := strings.ToLower(matcher.GroupString(5))
		if vname == ""{
			//This case is only for XML, sorry for the ugly code :(
			vname = matcher.GroupString(2)
			vvalue = strings.ToLower(matcher.GroupString(3))
		}
		index := matcher.Index()
		counter := false
		negation := false
		log.Error(vname)
		if vname[0] == '&'{
			vname = vname[1:]
			counter = true
		}
		if vname[0] == '!'{
			vname = vname[1:]
			negation = true
		}
	    
		collection := strings.ToLower(vname)
		if negation{
			r.AddNegateVariable(collection, vvalue)
		}else{
			r.AddVariable(counter, collection, vvalue) 
		}

	    subject = subject[index[1]:]
	    if len(subject) == 0{
	    	break
	    }
	}
	return nil
}


func (p *Parser) compileRuleOperator(r *engine.Rule, operator string) error{
	if operator == "" {
		operator = "@rx "
	}
	if operator[0] != '@' && operator[0] != '!'{
		//default operator RX
		operator = "@rx " + operator
	}
	spl := strings.SplitN(operator, " ", 2)
	op := spl[0]
	r.Operator = operator
	r.OperatorObj = new(engine.RuleOp)
	
	if op[0] == '!' {
		r.OperatorObj.Negation = true
		op = utils.TrimLeftChars(op, 1)
	}
	if op[0] == '@' {
		op = utils.TrimLeftChars(op, 1)
		if len(spl) == 2 {
			r.OperatorObj.Data = spl[1]
		}
	}

	r.OperatorObj.Operator = operators.OperatorsMap()[op]
	if r.OperatorObj.Operator == nil{
		return p.log("Invalid operator " + op)
	}else{
		r.OperatorObj.Operator.Init(r.OperatorObj.Data)
	}
	return nil
}

func (p *Parser) compileRuleActions(r *engine.Rule, actions string) error{
	//REGEX: ((.*?)((?<!\\)(?!\B'[^']*),(?![^']*'\B)|$))
	//This regex splits actions by comma and assign key:values with supported escaped quotes
	//TODO needs fixing, sometimes we empty strings as key
	re := pcre.MustCompile(`(.*?)((?<!\\)(?!\B'[^']*),(?![^']*'\B)|$)`, 0)
	matcher := re.MatcherString(actions, 0)
	subject := []byte(actions)
    if len(p.defaultActions) > 0{
    	actions = fmt.Sprintf("%s, %s", p.defaultActions, actions)
    }

    actionsmap := actionsmod.ActionsMap()
	for matcher.Match(subject, 0){
		m := matcher.GroupString(1)
		index := matcher.Index()
		spl := strings.SplitN(m, ":", 2)
		value := ""
		key := strings.Trim(spl[0], " ")
		if len(spl) == 2{
			value = strings.Trim(spl[1], " ")
		}
		if actionsmap[key] == nil{
			//TODO some fixing here, this is a bug
			p.log("Invalid action " + key)
		}else{
			action := actionsmap[key]
			err := action.Init(r, value)
			if err != ""{
				p.log(err)
				// TODO we should return an error later
				return nil
			}
			r.Actions = append(r.Actions, action)
		}
	    subject = subject[index[1]:]
	    if len(subject) == 0{
	    	break
	    }
	}	

	return nil
}

func (p *Parser) log(msg string) error{
	msg = fmt.Sprintf("[Parser] [Line %d] %s", p.currentLine, msg)
	log.Error(msg)
	return errors.New(msg)
}