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

package testing

import (
	b64 "encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"

	engine "github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types/variables"
)

// Start will begin the test stage
func (stage *ProfileTestStage) Start(waf *engine.Waf) error {
	log := ""

	tx := waf.NewTransaction()
	if stage.Stage.Input.EncodedRequest != "" {
		sDec, _ := b64.StdEncoding.DecodeString(stage.Stage.Input.EncodedRequest)
		stage.Stage.Input.RawRequest = string(sDec)
	}
	if stage.Stage.Input.RawRequest != "" {
		_, err := tx.ParseRequestReader(strings.NewReader(stage.Stage.Input.RawRequest))
		if err != nil {
			return errors.New("failed to parse Raw Request")
		}
	}
	//Apply tx data
	for k, v := range stage.Stage.Input.Headers {
		tx.AddRequestHeader(k, v)
	}
	method := "GET"
	if stage.Stage.Input.Method != "" {
		method = stage.Stage.Input.Method
	}

	//Request Line
	httpv := "HTTP/1.1"
	if stage.Stage.Input.Version != "" {
		httpv = stage.Stage.Input.Version
	}

	if stage.Stage.Input.Uri != "" {
		tx.ProcessUri(stage.Stage.Input.Uri, method, httpv)
	}

	//We can skip processConnection
	tx.ProcessRequestHeaders()

	// POST DATA
	if stage.Stage.Input.Data != "" {
		_, _ = tx.RequestBodyBuffer.Write([]byte(parseInputData(stage.Stage.Input.Data)))
		_, _ = tx.ProcessRequestBody()
		// we ignore the error
	}
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	// for testing
	tx.AddResponseHeader("content-type", "text/html")
	_, _ = tx.ProcessResponseBody() // we are ignoring result and error
	tx.ProcessLogging()

	tr := []int{}
	for _, mr := range tx.MatchedRules {
		log += fmt.Sprintf(" [id \"%d\"]", mr.Rule.Id)
		tr = append(tr, mr.Rule.Id)
	}
	//now we evaluate tests
	if stage.Stage.Output.LogContains != "" {
		if !strings.Contains(log, stage.Stage.Output.LogContains) {
			return fmt.Errorf("log does not contain %s", stage.Stage.Output.LogContains)
		}
	}
	if stage.Stage.Output.NoLogContains != "" {
		if strings.Contains(log, stage.Stage.Output.NoLogContains) {
			return fmt.Errorf("log does contain %s", stage.Stage.Output.NoLogContains)
		}
	}
	if len(stage.Stage.Output.TriggeredRules) > 0 {
		for _, trr := range stage.Stage.Output.TriggeredRules {
			triggered := false
			for _, t := range tr {
				if t == trr {
					triggered = true
				}
			}
			if !triggered {
				if stage.Debug {
					dumptransaction(tx)
				}
				return fmt.Errorf("%d was not triggered", trr)
			}
		}
	}
	if len(stage.Stage.Output.NonTriggeredRules) > 0 {
		for _, trr := range stage.Stage.Output.NonTriggeredRules {
			for _, t := range tr {
				if t == trr {
					return fmt.Errorf("%d waf triggered", trr)
				}
			}
		}
	}

	return nil
}

func parseInputData(input interface{}) string {
	data := ""
	v := reflect.ValueOf(input)
	switch v.Kind() {
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			data += fmt.Sprintf("%s\r\n", v.Index(i))
		}
		data += "\r\n"
	case reflect.String:
		data = input.(string)
	}
	return data
}

func dumptransaction(tx *engine.Transaction) {
	fmt.Println("======DEBUG======")
	for v := byte(1); v < 100; v++ {
		vr := variables.RuleVariable(v)
		if vr.Name() == "UNKNOWN" {
			break
		}
		fmt.Printf("%s:\n", vr.Name())
		data := tx.GetCollection(vr).Data()
		for k, d := range data {
			fmt.Printf("-->%s: %s\n", k, strings.Join(d, ","))
		}
	}
}
