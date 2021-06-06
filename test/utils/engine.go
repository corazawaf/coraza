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
	"github.com/jptosso/coraza-waf/pkg/parser"
	"github.com/jptosso/coraza-waf/pkg/utils"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
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
		p := &parser.Parser{}
		p.Init(waf)
		p.FromString(rules)
	}
	tx := waf.NewTransaction()
	ct := ""
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
			} else if kt == "content-type" {
				ct = v
			}
		}
	}
	method := "GET"
	if stage.Stage.Input.Method != "" {
		method = stage.Stage.Input.Method
		tx.SetRequestMethod(method)
	}

	//Request Line
	httpv := "HTTP/1.1"
	if stage.Stage.Input.Version != "" {
		httpv = stage.Stage.Input.Version
	}

	path := "/"
	if stage.Stage.Input.Uri != "" {
		u, err := url.Parse(stage.Stage.Input.Uri)
		if err != nil {
			log.Debug("Invalid URL: " + stage.Stage.Input.Uri)
		} else {
			tx.SetUrl(u)
			tx.AddGetArgsFromUrl(u)
			path = stage.Stage.Input.Uri //or unescaped?
		}

	}
	tx.SetRequestLine(method, httpv, path)

	//PHASE 1
	tx.ExecutePhase(1)

	// POST DATA
	if stage.Stage.Input.Data != "" {
		err := tx.SetRequestBody([]byte(parseInputData(stage.Stage.Input.Data)), ct)
		if err != nil {
			return err
		}
	}

	for i := 2; i <= 5; i++ {
		if tx.ExecutePhase(i) {
			break
		}
	}
	log := ""
	tr := []int{}
	for _, mr := range tx.MatchedRules {
		log += fmt.Sprintf(" [id \"%d\"]", mr.Id)
		tr = append(tr, mr.Id)
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
}
