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

package testing

import (
	"os"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/seclang"
)

// Profile represents a test profile
// It contains metadata and instructions for a test
// It requires more documentation
//tinyjson:json
type Profile struct {
	Rules string `json:"rules,omitempty"`
	Pass  bool
	Meta  struct {
		Author      string `json:"author,omitempty"`
		Description string `json:"description,omitempty"`
		Enabled     bool   `json:"enabled,omitempty"`
		Name        string `json:"name,omitempty"`
	} `json:"meta,omitempty"`
	TinyGoDisable bool `json:"tinygo_disable,omitempty"`
	Tests         []struct {
		Title       string `json:"test_title,omitempty"`
		Description string `json:"desc,omitempty"`
		Stages      []struct {
			Stage struct {
				Input struct {
					DestAddr       string            `json:"dest_addr,omitempty"`
					Port           int               `json:"port,omitempty"`
					Method         string            `json:"method,omitempty"`
					URI            string            `json:"uri,omitempty"`
					Version        string            `json:"version,omitempty"`
					Data           string            `json:"data,omitempty"`
					Headers        map[string]string `json:"headers,omitempty"`
					RawRequest     []byte            `json:"raw_request,omitempty"`
					EncodedRequest string            `json:"encoded_request,omitempty"`
					StopMagic      bool              `json:"stop_magic,omitempty"`
				} `json:"input,omitempty"`
				Output expectedOutput `json:"output,omitempty"`
			} `json:"stage,omitempty"`
		} `json:"stages,omitempty"`
	} `json:"tests,omitempty"`
}

//tinyjson:json
type expectedOutput struct {
	Headers           map[string]string     `json:"headers,omitempty"`
	Data              string                `json:"data,omitempty"`
	LogContains       string                `json:"log_contains,omitempty"`
	NoLogContains     string                `json:"no_log_contains,omitempty"`
	ExpectError       bool                  `json:"expect_error,omitempty"`
	TriggeredRules    []int                 `json:"triggered_rules,omitempty"`
	NonTriggeredRules []int                 `json:"non_triggered_rules,omitempty"`
	Status            interface{}           `json:"status,omitempty"`
	Interruption      *expectedInterruption `json:"interruption,omitempty"`
}

//tinyjson:json
type expectedInterruption struct {
	RuleID int    `json:"rule_id,omitempty"`
	Action string `json:"action,omitempty"`
	Status int    `json:"status,omitempty"`
	Data   string `json:"data,omitempty"`
}

// TestList returns a list of tests created for a profile
func (p *Profile) TestList(waf *coraza.Waf) ([]*Test, error) {
	var tests []*Test
	for _, t := range p.Tests {
		name := t.Title
		for _, tt := range t.Stages {
			stage := tt.Stage
			w := waf
			if w == nil || p.Rules != "" {
				w = coraza.NewWaf()
				parser, _ := seclang.NewParser(w)
				parser.SetCurrentDir("../testdata/")
				if err := parser.FromString(p.Rules); err != nil {
					return nil, err
				}
			}
			test := NewTest(name, w)
			test.ExpectedOutput = stage.Output
			// test.RequestAddress =
			// test.RequestPort =
			if stage.Input.URI != "" {
				test.RequestURI = stage.Input.URI
			}
			if stage.Input.Method != "" {
				test.RequestMethod = stage.Input.Method
			}
			if stage.Input.Version != "" {
				test.RequestProtocol = stage.Input.Version
			}
			if stage.Input.Headers != nil {
				test.RequestHeaders = stage.Input.Headers
			}
			if stage.Output.Headers != nil {
				test.ResponseHeaders = stage.Output.Headers
			}
			// test.ResponseHeaders = stage.Output.Headers
			test.ResponseCode = 200
			test.ResponseProtocol = "HTTP/1.1"
			test.ServerAddress = stage.Input.DestAddr
			test.ServerPort = stage.Input.Port
			if stage.Input.StopMagic {
				test.DisableMagic()
			}
			if err := test.SetEncodedRequest(stage.Input.EncodedRequest); err != nil {
				return nil, err
			}
			if err := test.SetRawRequest(stage.Input.RawRequest); err != nil {
				return nil, err
			}
			if err := test.SetRequestBody(stage.Input.Data); err != nil {
				return nil, err
			}
			if err := test.SetResponseBody(stage.Output.Data); err != nil {
				return nil, err
			}
			tests = append(tests, test)
		}
	}
	return tests, nil
}

// NewProfile creates a new profile from a file
func NewProfile(path string) (*Profile, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	profile := new(Profile)
	err = profile.UnmarshalJSON(f)
	return profile, err
}
