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
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/pcktdmp/cef/cefevent"
)

type formatter = func(al *AuditLog) (string, error)

func jsonFormatter(al *AuditLog) (string, error) {
	jsdata, err := json.Marshal(al)
	if err != nil {
		return "", err
	}
	return string(jsdata), nil
}

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

func ftwFormatter(al *AuditLog) (string, error) {
	timestamp := al.Transaction.Timestamp
	address := al.Transaction.ClientIp
	rules := ""
	phase := 5
	msgs := ""
	severity := ""
	uri := ""
	status := 0
	if al.Transaction.Request != nil {
		uri = al.Transaction.Request.Uri
	}
	if al.Transaction.Response != nil {
		status = al.Transaction.Response.Status
	}
	logdata := ""

	id := al.Transaction.Id
	err := fmt.Sprintf("Access denied with code %d (phase %d)", status, phase)
	for _, r := range al.Messages {
		rules += fmt.Sprintf("[id \"%d\"] ", r.Data.Id)
		msgs += fmt.Sprintf("[msg \"%s\"]", r.Data.Msg)
	}
	data := fmt.Sprintf("[%s] [error] [client %s] Coraza: %s. %s %s %s [severity \"%s\"] [uri \"%s\"] [unique_id \"%s\"]",
		timestamp, address, err, logdata, rules, msgs, severity, uri, id)
	return data, nil
}

func modsecFormatter(al *AuditLog) (string, error) {
	boundary := ""
	parts := map[byte]string{}
	// [27/Jul/2016:05:46:16 +0200] V5guiH8AAQEAADTeJ2wAAAAK 192.168.3.1 50084 192.168.3.111 80
	parts['A'] = fmt.Sprintf("[%s] %s %s %d %s %d", al.Transaction.Timestamp, al.Transaction.Id,
		al.Transaction.ClientIp, al.Transaction.ClientPort, al.Transaction.HostIp, al.Transaction.HostPort)
	//Host: example.com
	//User-Agent: Mozilla/5.0
	//Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
	//Accept-Language: en-US,en;q=0.5
	//Accept-Encoding: gzip, deflate
	//Referer: http://example.com/index.html
	//Connection: keep-alive
	//Content-Type: application/x-www-form-urlencoded
	//Content-Length: 6
	parts['B'] = ""
	if al.Transaction.Request != nil {
		for k, vv := range al.Transaction.Request.Headers {
			for _, v := range vv {
				parts['B'] += fmt.Sprintf("%s: %s\n", k, v)
			}
		}
		//b=test
		parts['C'] = al.Transaction.Request.Body
	}
	if al.Transaction.Response != nil {
		parts['E'] = al.Transaction.Response.Body
		parts['F'] = ""
		for k, vv := range al.Transaction.Response.Headers {
			for _, v := range vv {
				parts['F'] += fmt.Sprintf("%s: %s\n", k, v)
			}
		}
	}
	//Stopwatch: 1470025005945403 1715 (- - -)
	//Stopwatch2: 1470025005945403 1715; combined=26, p1=0, p2=0, p3=0, p4=0, p5=26, ↩
	//sr=0, sw=0, l=0, gc=0
	//Response-Body-Transformed: Dechunked
	//Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/).
	//Server: Apache
	//Engine-Mode: "ENABLED"
	parts['H'] = "" //TODO
	parts['K'] = ""
	for _, r := range al.Messages {
		parts['K'] = fmt.Sprintf("%d\n", r.Data.Id) //TODO add Raw rule to logs
	}
	parts['Z'] = ""
	data := ""
	for _, c := range []byte("ABCEFHKZ") {
		data += fmt.Sprintf("--%s-%c--\n%s\n", boundary, c, parts[c])
	}
	return data, nil
}

func getFormatter(f string) (formatter, error) {
	switch f {
	case "cef":
		return cefFormatter, nil
	case "ftw":
		return ftwFormatter, nil
	case "modsec":
		return modsecFormatter, nil
	case "json":
		return jsonFormatter, nil
	}
	return nil, fmt.Errorf("invalid formatter %s", f)
}

var (
	_ formatter = cefFormatter
	_ formatter = ftwFormatter
)
