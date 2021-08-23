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
	"strings"
	"testing"
)

func TestSerialLogger_Write(t *testing.T) {
	l := &SerialLogger{}
	tmp := "/tmp/something.log"
	args := map[string]string{
		"file": tmp,
	}
	err := l.New(args)
	if err != nil {
		t.Error(err)
	}
	al := &AuditLog{
		Transaction: &AuditTransaction{
			Id: "test123",
		},
		Messages: []*AuditMessage{
			{
				Data: &AuditMessageData{
					Id: 123,
				},
			},
		},
	}
	l.Write(al)
	file, err := os.Open(tmp)
	if err != nil {
		t.Error(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	last := ""
	for scanner.Scan() {
		last = scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		t.Error(err)
	}
	if !strings.Contains(last, "test123") {
		t.Error("failed to parse log tx id: ")
	}
	if !strings.Contains(last, "[id \"123\"]") {
		t.Error("failed to parse log rule id: " + last)
	}
}
