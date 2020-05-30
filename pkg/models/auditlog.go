package models
import(
	"encoding/json"
)

type AuditTransaction struct {
	TransactionId string `json:"transaction_id"`
	Time string `json:"time"`
	RemotePort int `json:"remote_port"`
	LocalAddress string `json:"local_address"`
	LocalPort int `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
}

type AuditRequest struct {
	Headers map[string][]string `json:"headers"`
	RequestLine string `json:"request_line"`
	Body string `json:"body"`
}

type AuditResponse struct{
	Protocol string `json:"protocol"`
	Status int `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body string `json:"body"`
}

type AuditAction struct{
	Message string `json:"message"`
	Phase int `json:"phase"`
	Intercepted bool `json:"intercepted"`
}

type AuditMatchedRuleActionset struct {
	Id int `json:"id"`
	IsChained bool `json:"is_chained"`
	ChainStarter bool `json:"chain_starter"`
	tags []string `json:"tags"`
	Phase int `json:"phase"`
}

type AuditMatchedRuleConfig struct {
	LineNum int `json:"line_num"`
	Filename string `json:"filename"`
}

type AuditMatchedRuleOperator struct {
	Operator string `json:"operator"`
	OperatorParam string `json:"operator_param"`
	Target string `json:"target"`
	Negated bool `json:"negated"`
}

type AuditMatchedRule struct {
	Actionset *AuditMatchedRuleActionset `json:"actionset"`
	Config *AuditMatchedRuleConfig `json:"config"`
	IsMatched bool `json:"is_matched"`
	Unparsed string `json:"unparsed"`
	Operator *AuditMatchedRuleOperator `json:"operator"`
}

type AuditMatchedRules struct {
	Rules []*AuditMatchedRule `json:"rules"`
}

type AuditData struct{
	EngineMode string `json:"engine_mode"`
	Server string `json:"server"`
	Stopwatch map[string]string `json:"stopwatch"`
	Producer string `json:"producer"`
	Action *AuditAction `json:"action"`
}

type AuditLog struct{
	Transaction *AuditTransaction `json:"transaction"`
	Request *AuditRequest `json:"request"`
	Response *AuditResponse `json:"response"`
	AuditData *AuditData `json:"audit_data"`
	MatchedRules *AuditMatchedRules `json:"matched_rules"`
}

func (al *AuditLog) Parse(tx *Transaction){
	al.Transaction = &AuditTransaction{
		TransactionId: tx.Id,
		Time: "",
		RemotePort: 0,
		LocalAddress: "",
		LocalPort: 0,
		RemoteAddress: tx.Collections["remote_addr"].GetFirstString(),
	}
	al.Request = &AuditRequest{
		Headers: tx.Collections["request_headers"].Data,
		RequestLine: tx.Collections["request_line"].GetFirstString(),
		Body: tx.Collections["request_body"].GetFirstString(),
	}
	al.Response = &AuditResponse{
		//Protocol: tx.Collections["protocol"].GetFirstString(),
		//Status: tx.Collections["status"].GetFirstInt(),
		Headers: tx.Collections["response_headers"].Data,
		Body: tx.Collections["response_body"].GetFirstString(),
	}	

	al.AuditData = &AuditData{
		EngineMode: "ENABLED",
		Server: "",
		Stopwatch: nil, 
		Producer: "Coraza Web Application Firewall",
		Action: &AuditAction{
			Message: "",
			Phase: 0,
			Intercepted: false,
		},
	}
	al.MatchedRules = &AuditMatchedRules{
		Rules: []*AuditMatchedRule{},
	}

	for _, mr := range tx.MatchedRules{
		r := mr.Rule
		al.MatchedRules.Rules = append(al.MatchedRules.Rules, &AuditMatchedRule{
			Actionset: &AuditMatchedRuleActionset{
				Id: r.Id,
				IsChained: (r.Id == 0),
				ChainStarter: (r.Id != 0), //TODO check
				tags: r.Tags,
				Phase: r.Phase,
			},
			Config: &AuditMatchedRuleConfig{
				LineNum: 0,
				Filename: "",
			},
			IsMatched: false,
			Unparsed: r.Raw,
			Operator: &AuditMatchedRuleOperator{
				Operator: "",
				OperatorParam: "",
				Target: "",
				Negated: false,
			},
		})	
	}
}

func (al *AuditLog) ToJson() []byte{
	js, _ := json.Marshal(al)
	return js
}