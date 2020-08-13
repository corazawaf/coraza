package engine

import (
	"testing"
	"encoding/json"
	"os"
	"io/ioutil"
)


func TestCLogFileCreation(t *testing.T){
	waf := &Waf{}
	waf.AuditLogStorageDir = "/tmp/audit/"
	waf.AuditLogPath = "/tmp/audit/audit.log"
	waf.Init()
	waf.InitLogger()
	tx := waf.NewTransaction()
	waf.Logger.WriteAudit(tx)
	fpath, fname := tx.GetAuditPath()
	if _, err := os.Stat(fpath); os.IsNotExist(err) {
		t.Error("Directory was not created: " + fpath)
	}
	file, err := ioutil.ReadFile(fpath + fname)
	if err != nil{
		t.Error("Audit file was not created")
		return
	}
	al := &AuditLog{}
	err = json.Unmarshal([]byte(file), al)
	if err != nil{
		t.Error("Invalid JSON audit file")
	}
	if al.Transaction.TransactionId != tx.Id{
		t.Error("Invalid ID for JSON audit file")
	}
}
