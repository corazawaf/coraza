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
	"strconv"

	"github.com/pcktdmp/cef/cefevent"
)

type formatter = func(al *AuditLog) (string, error)

func cefFormatter(al *AuditLog) (string, error) {
	f := make(map[string]string)
	f["src"] = al.Transaction.ClientIp
	f["timestamp"] = al.Transaction.Timestamp
	f["status"] = strconv.Itoa(al.Transaction.Response.Status)
	// TODO add more fields

	event := cefevent.CefEvent{
		Version:            0,
		DeviceVendor:       "Coraza Technologies",
		DeviceProduct:      "Coraza WAF",
		DeviceVersion:      "1.0",
		DeviceEventClassId: "AUDIT",
		Name:               "...",
		Severity:           "...",
		Extensions:         f,
	}

	cef, _ := event.Generate()
	return cef, nil
}
