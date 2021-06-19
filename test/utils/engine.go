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
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/seclang"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"gopkg.in/yaml.v2"
	"io"
	"net/url"
	"reflect"
	"strings"
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
		p := &seclang.Parser{}
		p.Init(waf)
		p.FromString(rules)
	}
	tx := waf.NewTransaction()
	if stage.Stage.Input.EncodedRequest != "" {
		sDec, _ := b64.StdEncoding.DecodeString(stage.Stage.Input.EncodedRequest)
		stage.Stage.Input.RawRequest = string(sDec)
	}
	if stage.Stage.Input.RawRequest != "" {
		err := tx.ParseRequestString(stage.Stage.Input.RawRequest)
		if err != nil {
			return errors.New("Failed to parse Raw Request")
		}
	}
	//Apply tx data
	if len(stage.Stage.Input.Headers) > 0 {
		for k, v := range stage.Stage.Input.Headers {
			tx.AddRequestHeader(k, v)
			kt := strings.ToLower(k)
			if kt == "cookie" {
				tx.AddCookies(v)
			}
		}
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

	path := "/"
	if stage.Stage.Input.Uri != "" {
		path = stage.Stage.Input.Uri
		parseUrl(path, tx)
		spl := strings.SplitN(path, "/", 2)
		if len(spl) == 2 {
			path = "/" + spl[1]
		} else {
			path = "/" + spl[0]
		}
	}
	tx.SetRequestLine(method, httpv, path)
	// This is a fix for some tests overwrites...
	tx.GetCollection("request_line").Add("", fmt.Sprintf("%s %s %s", method, stage.Stage.Input.Uri, httpv))

	//PHASE 1
	tx.ExecutePhase(1)

	// POST DATA
	if stage.Stage.Input.Data != "" {
		r := io.Reader(strings.NewReader(parseInputData(stage.Stage.Input.Data)))
		tx.SetRequestBody(&r)
		// we ignore the error
	}

	for i := 2; i <= 5; i++ {
		if tx.ExecutePhase(i) {
			break
		}
	}
	log := ""
	tr := []int{}
	for _, mr := range tx.MatchedRules {
		log += fmt.Sprintf(" [id \"%d\"]", mr.Rule.Id)
		tr = append(tr, mr.Rule.Id)
	}
	//now we evaluate tests
	if stage.Stage.Output.LogContains != "" {
		if !strings.Contains(log, stage.Stage.Output.LogContains) {
			return errors.New(fmt.Sprintf("Log does not contain %s", stage.Stage.Output.LogContains))
		}
	}
	if stage.Stage.Output.NoLogContains != "" {
		if strings.Contains(log, stage.Stage.Output.NoLogContains) {
			return errors.New(fmt.Sprintf("Log does contain %s", stage.Stage.Output.NoLogContains))
		}
	}
	if len(stage.Stage.Output.TriggeredRules) > 0 {
		for _, trr := range stage.Stage.Output.TriggeredRules {
			if !utils.ArrayContainsInt(tr, trr) {
				return errors.New(fmt.Sprintf("Rule %d was not triggered", trr))
			}
		}
	}
	if len(stage.Stage.Output.NonTriggeredRules) > 0 {
		for _, trr := range stage.Stage.Output.NonTriggeredRules {
			if utils.ArrayContainsInt(tr, trr) {
				return errors.New(fmt.Sprintf("Rule %d was triggered", trr))
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
	u, err := url.Parse(uri)
	if err == nil {
		tx.SetUrl(u)
		tx.AddGetArgsFromUrl(u)
		return
	}
	tx.GetCollection("request_uri_raw").Add("", uri)
	tx.GetCollection("request_uri").Add("", uri)
	schema := "http"
	args := ""
	hostname := "127.0.0.1"
	path := "/"
	if strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://") {
		spl := strings.SplitN(uri, "://", 2)
		schema = spl[0]
		uri = spl[1]
	}
	if len(uri) == 0 {
		return
	}
	if uri[0] != '/' {
		spl := strings.SplitN(uri, "/", 2)
		if len(spl) == 2 {
			hostname = spl[0]
			args = spl[1]
			uri = spl[1]
		}
	}
	spl := strings.SplitN(uri, "?", 2)
	if len(spl) == 2 {
		path = spl[0]
		args = spl[1]
	}
	// TODO
	schema = schema + hostname
	tx.GetCollection("request_filename").Add("", path)
	tx.GetCollection("request_basename").Add("", path)
	tx.GetCollection("query_string").Add("", args)
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
	LogContains       string `yaml:"log_contains"`
	NoLogContains     string `yaml:"no_log_contains"`
	ExpectError       bool   `yaml:"expect_error"`
	TriggeredRules    []int  `yaml:"triggered_rules"`
	NonTriggeredRules []int  `yaml:"non_triggered_rules"`
	Status            []int  `yaml:"status"`
}
