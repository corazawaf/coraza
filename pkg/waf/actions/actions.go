package actions
import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

func ActionsMap() map[string]models.Action {
	return map[string]models.Action{
		// #### Flow Actions #### 
		//Sets variables for the transaction and rule
		"chain": &Chain{},
		//"skip": &Skip{},
		"skipAfter": &SkipAfter{},

		// #### Metadata Actions #### 
		//These variables goes to the rule object
		//"accuracy": &Accurracy{},
		"id": &Id{},
		"maturity": &Maturity{},
		"msg": &Msg{},
		"phase": &Phase{},
		"rev": &Rev{},
		"severity": &Severity{},
		"tag": &Tag{},
		"ver": &Ver{},

		// #### Data actions #### 
		//These variables goes to the transaction
		"status": &Status{},
		//"xmlns": &Xmlns{},

		// #### Non Disruptive Actions ####
		//Can update transaction but cannot affect the flow nor disrupt the request
		"append": &Append{},
		"auditlog": &Auditlog{},
		"capture": &Capture{},
		"ctl": &Ctl{},
		//"exec": &Exec{},
		"expirevar": &Expirevar{},
		//"deprecateVar": &DeprecateVar{},
		"initcol": &InitCol{},
		"log": &Log{},
		"logdata": &Logdata{},
		"multiMatch": &MultiMatch{},
		"noauditlog": &Noauditlog{},
		"nolog": &Nolog{},
		//"prepend": &Prepend{},
		//"sanitiseArg": &SanitiseArg{},
		//"sanitiseMatched": &SanitiseMatched{},
		//"sanitiseMatchedBytes": &SanitiseMatchedBytes{},
		//"sanitiseRequestHeader": &SanitiseRequestHeader{},
		//"sanitiseResponseHeader": &SanitiseResponseHeader{},
		//"setuid": &Setuid{},
		//"setrsc": &Setrsc{},
		//"setsid": &Setsid{},
		//"setenv": &Setenv{},
		"setvar": &Setvar{},
		"t": &T{},

		// #### Disruptive Actions #### 
		// can manage the whole request and response process, doesnt run if SecRuleEngine is off or DetectionOnly is on
		"allow": &Allow{},
		"block": &Block{},
		"deny": &Deny{},
		"drop": &Drop{},
		"pass": &Pass{},
		//"pause": &Pause{},
		//"proxy": &Proxy{},
		//"redirect": &Redirect{},
	}
}