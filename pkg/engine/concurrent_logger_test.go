// Copyright 2020 Juan Pablo Tosso
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

package engine

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
)

func TestCLogFileCreation(t *testing.T) {
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
	if err != nil {
		t.Error("Audit file was not created")
		return
	}
	al := &AuditLog{}
	err = json.Unmarshal([]byte(file), al)
	if err != nil {
		t.Error("Invalid JSON audit file")
	}
	if al.Transaction.Id != tx.Id {
		t.Error("Invalid ID for JSON audit file")
	}
}
