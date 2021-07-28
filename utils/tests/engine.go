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

package utils

import (
	b64 "encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"

	engine "github.com/jptosso/coraza-waf/v1"
	"github.com/jptosso/coraza-waf/v1/seclang"
	"github.com/jptosso/coraza-waf/v1/utils"
	"gopkg.in/yaml.v2"
	//"time"
)

func ParseProfile(path string) (*testProfile, error) {
	data, err := utils.OpenFile(path)
	if err != nil {
		return nil, errors.New("Cannot open file " + path)
	}
	profile := testProfile{}
	err = yaml.Unmarshal(data, &profile)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

// This function is related to testStage
func (stage *testStage) Start(waf *engine.Waf, rules string) error {
	if rules != "" {
		waf = engine.NewWaf()
		p, _ := seclang.NewParser(waf)
		p.FromString(rules)
	}
	tx := waf.NewTransaction()
	if stage.Stage.Input.EncodedRequest != "" {
		sDec, _ := b64.StdEncoding.DecodeString(stage.Stage.Input.EncodedRequest)
		stage.Stage.Input.RawRequest = string(sDec)
	}
	if stage.Stage.Input.RawRequest != "" {
		_, err := tx.ParseRequestString(stage.Stage.Input.RawRequest)
		if err != nil {
			return errors.New("failed to parse Raw Request")
		}
	}
	//Apply tx data
	if len(stage.Stage.Input.Headers) > 0 {
		for k, v := range stage.Stage.Input.Headers {
			tx.AddRequestHeader(k, v)
		}
	}
	method := "GET"
	if stage.Stage.Input.Method != "" {
		method = stage.Stage.Input.Method
	}
	tx.GetCollection(engine.VARIABLE_REQUEST_METHOD).Add("", method)

	//Request Line
	httpv := "HTTP/1.1"
	if stage.Stage.Input.Version != "" {
		httpv = stage.Stage.Input.Version
	}
	tx.GetCollection(engine.VARIABLE_REQUEST_PROTOCOL).Add("", httpv)

	path := "/"
	if stage.Stage.Input.Uri != "" {
		path = stage.Stage.Input.Uri
		parseUrl(path, tx)
	}
	tx.GetCollection(engine.VARIABLE_REQUEST_LINE).Add("", fmt.Sprintf("%s %s %s", method, stage.Stage.Input.Uri, httpv))

	//We can skip processConnection and ProcessUri
	tx.ProcessRequestHeaders()

	// POST DATA
	if stage.Stage.Input.Data != "" {
		tx.RequestBodyBuffer.Write([]byte(parseInputData(stage.Stage.Input.Data)))
		tx.ProcessRequestBody()
		// we ignore the error
	}
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	tx.ProcessLogging()

	log := ""
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
			if !utils.ArrayContainsInt(tr, trr) {
				return fmt.Errorf("rule %d was not triggered", trr)
			}
		}
	}
	if len(stage.Stage.Output.NonTriggeredRules) > 0 {
		for _, trr := range stage.Stage.Output.NonTriggeredRules {
			if utils.ArrayContainsInt(tr, trr) {
				return fmt.Errorf("rule %d was triggered", trr)
			}
		}
	}
	if stage.Stage.Output.Status != nil {
		// Status is not supported because it depends on apache behaviour
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

func parseUrl(uri string, tx *engine.Transaction) {
	tx.GetCollection(engine.VARIABLE_REQUEST_URI_RAW).Add("", uri)
	tx.GetCollection(engine.VARIABLE_REQUEST_URI).Add("", uri)
	args := ""
	path := "/"
	if strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://") {
		spl := strings.SplitN(uri, "://", 2)
		uri = spl[1]
	}
	if len(uri) == 0 {
		return
	}
	if uri[0] != '/' {
		spl := strings.SplitN(uri, "/", 2)
		if len(spl) == 2 {
			args = spl[1]
			uri = spl[1]
		}
	}
	spl := strings.SplitN(uri, "?", 2)
	if len(spl) == 2 {
		path = spl[0]
		args = spl[1]
	}
	tx.GetCollection(engine.VARIABLE_REQUEST_FILENAME).Add("", path)
	tx.GetCollection(engine.VARIABLE_REQUEST_BASENAME).Add("", path)
	tx.GetCollection(engine.VARIABLE_QUERY_STRING).Add("", args)
	values := utils.ParseQuery(args, "&")
	for k, vs := range values {
		for _, v := range vs {
			tx.AddArgument("GET", k, v)
		}
	}
}

type testProfile struct {
	Meta  testMeta   `yaml:"meta"`
	Tests []testTest `yaml:"tests"`
	Rules string     `yaml:"rules"`
	Pass  bool
}

type testMeta struct {
	Author      string `yaml:"author"`
	Description string `yaml:"description"`
	Enabled     bool   `yaml:"enabled"`
	Name        string `yaml:"name"`
}

type testTest struct {
	Title       string      `yaml:"test_title"`
	Description string      `yaml:"desc"`
	Stages      []testStage `yaml:"stages"`
}

type testStage struct {
	Stage testStageInner `yaml:"stage"`
	Pass  bool
}

type testStageInner struct {
	Input  testInput  `yaml:"input"`
	Output testOutput `yaml:"output"`
}

type testInput struct {
	DestAddr       string            `yaml:"dest_addr"`
	Port           int               `yaml:"port"`
	Method         string            `yaml:"method"`
	Uri            string            `yaml:"uri"`
	Version        string            `yaml:"version"`
	Data           interface{}       `yaml:"data"` //Accepts array or string
	Headers        map[string]string `yaml:"headers"`
	RawRequest     string            `yaml:"raw_request"`
	EncodedRequest string            `yaml:"encoded_request"`
}

type testOutput struct {
	LogContains       string      `yaml:"log_contains"`
	NoLogContains     string      `yaml:"no_log_contains"`
	ExpectError       bool        `yaml:"expect_error"`
	TriggeredRules    []int       `yaml:"triggered_rules"`
	NonTriggeredRules []int       `yaml:"non_triggered_rules"`
	Status            interface{} `yaml:"status"`
}
