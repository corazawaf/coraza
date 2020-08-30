package engine
import(
	"encoding/json"
)

type AuditLog struct{
	Transaction *AuditTransaction `json:"transaction"`
	Messages []*AuditMessage `json:"messages"`
}

type AuditTransaction struct{
	Timestamp string `json:"timestamp"`
	Id string `json:"id"`
	ClientIp string `json:"client_ip"`
	ClientPort int `json:"client_port"`
	HostIp string `json:"host_ip"`
	HostPort int `json:"host_port"`
	ServerId string `json:"server_id"`
	Request *AuditTransactionRequest `json:"request"`
	Response *AuditTransactionResponse `json:"response"`
	Producer *AuditTransactionProducer `json:"producer"`
}

type AuditTransactionResponse struct{
	Status int
	Headers map[string][]string
	Body string
}

type AuditTransactionProducer struct{
	Connector string `json:"connector"`
	Version string `json:"version"`
	Server string `json:"server"`
	RuleEngine bool `json:"rule_engine"`
	Stopwatch string `json:"stopwatch"`
}

type AuditTransactionRequest struct{
	Protocol string `json:"protocol"`
	Uri string `json:"uri"`
	HttpVersion string `json:"http_version"`
	Headers map[string][]string `json:"headers"`
	Body string `json:"body"`
	Files []*AuditTransactionRequestFiles `json:"files"`
}

type AuditTransactionRequestFiles struct{
	Name string `json:"name"`
	Size int64  `json:"size"`
	Mime string `json:"mime"`
}

type AuditMessage struct{
	Actionset string `json:"actionset"`
	Message string `json:"message"`
	Data *AuditMessageData `json:"data"`
}

type AuditMessageData struct{
	File string `json:"file"`
	Line int `json:"line"`
	Id int `json:"id"`
	Rev string `json:"rev"`
	Msg string `json:"msg"`
	Data string `json:"data"`
	Severity int `json:"severity"`
	Ver string `json:"ver"`
	Maturity int `json:"maturity"`
	Accuracy int `json:"accuracy"`
	Tags []string `json:"tags"`
}

func (al *AuditLog) Init(tx *Transaction){
	parts := tx.AuditLogParts
	al.Messages = []*AuditMessage{}
	al.Transaction = &AuditTransaction{
		Timestamp: tx.GetTimestamp(),
		Id: tx.Id,
		ClientIp: tx.Collections["remote_addr"].GetFirstString(),
		ClientPort: tx.Collections["remote_port"].GetFirstInt(),
		HostIp: "",
		HostPort: 0,
		ServerId: "",
		Request: &AuditTransactionRequest{
			Protocol: tx.Collections["request_method"].GetFirstString(),
			Uri: tx.Collections["request_uri"].GetFirstString(),
			HttpVersion: tx.Collections["request_protocol"].GetFirstString(),
			//Body and headers are audit parts
		},
		Response: &AuditTransactionResponse{
			Status: tx.Collections["response_status"].GetFirstInt(),
			//body and headers are audit parts
		},
	}

	for _, p := range parts{
		switch p{
		case 'B':
			al.Transaction.Request.Headers = tx.Collections["request_headers"].Data
			break
		case 'C':
			al.Transaction.Request.Body = tx.Collections["request_body"].GetFirstString()		
			break
		case 'F':
			al.Transaction.Response.Headers = tx.Collections["response_headers"].Data
			break
		case 'G':
			al.Transaction.Response.Body = tx.Collections["response_body"].GetFirstString()
			break
		case 'H':
			servera := tx.Collections["response_headers"].Get("server")
			server := ""
			if len(server) > 0{
				server = servera[0]
			}
			al.Transaction.Producer = &AuditTransactionProducer{
				Connector: "unknown",
				Version: "unknown",
				Server: server,
				RuleEngine: tx.RuleEngine,
				Stopwatch: tx.GetStopWatch(),
			}
			break			
		case 'I':
			// not implemented
			// TODO
			break
		case 'J':
			//upload data
			// TODO
			break
		case 'K':
			for _, mr := range tx.MatchedRules{
				r := mr.Rule
				al.Messages = append(al.Messages, &AuditMessage{
					Actionset: "",
					Message: "",
					Data: &AuditMessageData{
						File: "",
						Line: 0,
						Id: r.Id,
						Rev: r.Rev,
						Msg: r.Msg,
						Data: "",
						//Severity: r.Severity,
						//Ver: r.Ver,
						//Maturity: r.Maturity,
						//Accuracy: r.Accuracy,
						Tags: r.Tags,
					},
				})	
			}			
			break
		}
	}
}

func (al *AuditLog) ToJson() []byte{
	js, _ := json.Marshal(al)
	return js
}