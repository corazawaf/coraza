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
	"gopkg.in/yaml.v2"
)

// Profile represents a test profile
// It contains metadata and instructions for a test
// It requires more documentation
type Profile struct {
	Rules string `yaml:"rules,omitempty"`
	Pass  bool
	Meta  struct {
		Author      string `yaml:"author,omitempty"`
		Description string `yaml:"description,omitempty"`
		Enabled     bool   `yaml:"enabled,omitempty"`
		Name        string `yaml:"name,omitempty"`
	} `yaml:"meta,omitempty"`
	Tests []struct {
		Title       string `yaml:"test_title,omitempty"`
		Description string `yaml:"desc,omitempty"`
		Stages      []struct {
			Stage struct {
				Input struct {
					DestAddr       string            `yaml:"dest_addr,omitempty"`
					Port           int               `yaml:"port,omitempty"`
					Method         string            `yaml:"method,omitempty"`
					URI            string            `yaml:"uri,omitempty"`
					Version        string            `yaml:"version,omitempty"`
					Data           interface{}       `yaml:"data,omitempty"` // Accepts array or string
					Headers        map[string]string `yaml:"headers,omitempty"`
					RawRequest     []byte            `yaml:"raw_request,omitempty"`
					EncodedRequest string            `yaml:"encoded_request,omitempty"`
					StopMagic      bool              `yaml:"stop_magic,omitempty"`
				} `yaml:"input,omitempty"`
				Output expectedOutput `yaml:"output,omitempty"`
			} `yaml:"stage,omitempty"`
		} `yaml:"stages,omitempty"`
	} `yaml:"tests,omitempty"`
}

type expectedOutput struct {
	Headers           map[string]string     `yaml:"headers,omitempty"`
	Data              interface{}           `yaml:"data,omitempty"` // Accepts array or string
	LogContains       string                `yaml:"log_contains,omitempty"`
	NoLogContains     string                `yaml:"no_log_contains,omitempty"`
	ExpectError       bool                  `yaml:"expect_error,omitempty"`
	TriggeredRules    []int                 `yaml:"triggered_rules,omitempty"`
	NonTriggeredRules []int                 `yaml:"non_triggered_rules,omitempty"`
	Status            interface{}           `yaml:"status,omitempty"`
	Interruption      *expectedInterruption `yaml:"interruption,omitempty"`
}

type expectedInterruption struct {
	RuleID int    `yaml:"rule_id,omitempty"`
	Action string `yaml:"action,omitempty"`
	Status int    `yaml:"status,omitempty"`
	Data   string `yaml:"data,omitempty"`
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
	err = yaml.Unmarshal(f, profile)
	return profile, err
}
