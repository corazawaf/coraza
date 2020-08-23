package actions
import(
	"testing"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

func TestCtl(t *testing.T){
	waf := &engine.Waf{}
	waf.Init()
	tx := waf.NewTransaction()
	r := &engine.Rule{}
	r.Init()	
	ctl := Ctl{}

	ctl.Init(r, "requestBodyProcessor=XML")
	ctl.Evaluate(r, tx)
	// Not implemented yet

	ctl.Init(r, "ruleRemoveTargetById=981260;ARGS:user")
	ctl.Evaluate(r, tx)

	if tx.RuleRemoveTargetById[981260] == nil{
		t.Error("Failed to create ruleRemoveTargetById")
	}else{
		if tx.RuleRemoveTargetById[981260][0].Name != "args"{
			t.Error("Failed to create ruleRemoveTargetById, invalid Collection")
		}
		if tx.RuleRemoveTargetById[981260][0].Key != "user"{
			t.Error("Failed to create ruleRemoveTargetById, invalid Key")
		}		
	}

	ctl.Init(r, "auditEngine=off")
	ctl.Evaluate(r, tx)

	if tx.AuditEngine != engine.AUDIT_LOG_DISABLED{
		t.Error("Failed to disable audit log")
	}
}