// Copyright 2021 Juan Pablo Tosso
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

package loggers

import (
	"bufio"
	"os"
	"path"
	"strings"
	"testing"

	utils "github.com/jptosso/coraza-waf/v2/utils/strings"
)

func TestSerialLogger_Write(t *testing.T) {
	tmp := path.Join("/tmp", utils.SafeRandom(10)+"-audit.log")
	defer os.Remove(tmp)
	logger, err := NewAuditLogger()
	if err != nil {
		t.Error(err)
	}
	logger.file = tmp
	err = logger.SetWriter("serial")
	if err != nil {
		t.Error(err)
	}
	al := AuditLog{
		Transaction: AuditTransaction{
			ID: "test123",
		},
		Messages: []AuditMessage{
			{
				Data: AuditMessageData{
					ID:  100,
					Raw: "SecAction \"id:100\"",
				},
			},
		},
	}
	if err := logger.Write(al); err != nil {
		t.Error("failed to write to serial logger")
	}

	f, err := os.OpenFile(tmp, os.O_RDONLY, 0666)
	if err != nil {
		t.Error(f)
	}
	// copy io.Reader to string
	scanner := bufio.NewScanner(f)
	var data string
	for scanner.Scan() {
		data += scanner.Text()
	}
	if !strings.Contains(data, "test123") {
		t.Errorf("failed to parse log tx id from serial log: %q on file %q", data, tmp)
	}
	if !strings.Contains(data, "id:100") {
		t.Errorf("failed to parse log rule id: %q on file %q", data, tmp)
	}
}
