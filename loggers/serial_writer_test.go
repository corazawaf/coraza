//go:build !tinygo
// +build !tinygo

// Copyright 2022 Juan Pablo Tosso
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
	"os"
	"path"
	"strings"
	"testing"

	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
)

func TestSerialLogger_Write(t *testing.T) {
	tmp := path.Join("/tmp", utils.SafeRandom(10)+"-audit.log")
	defer os.Remove(tmp)
	writer := &serialWriter{}
	config := types.Config{
		"auditlog_file":      tmp,
		"auditlog_formatter": jsonFormatter,
	}
	if err := writer.Init(config); err != nil {
		t.Error(err)
	}
	al := &AuditLog{
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
	if err := writer.Write(al); err != nil {
		t.Error("failed to write to serial logger")
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Error("failed to read serial logger file", err)
	}
	if !strings.Contains(string(data), "test123") {
		t.Errorf("failed to parse log tx id from serial log: \n%q on file %q", string(data), tmp)
	}
	if !strings.Contains(string(data), "id:100") {
		t.Errorf("failed to parse log rule id: \n%q on file %q", string(data), tmp)
	}
}
