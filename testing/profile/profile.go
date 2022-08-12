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

package profile

// Meta contains the test metadata
type Meta struct {
	Author      string `yaml:"author,omitempty"`
	Description string `yaml:"description,omitempty"`
	Enabled     bool   `yaml:"enabled,omitempty"`
	Name        string `yaml:"name,omitempty"`
}

// StageInput contains the input data for tests
type StageInput struct {
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
}

// Stage is a yaml container for the stage key
// it contains ProfileSubStages
type Stage struct {
	Stage SubStage `yaml:"stage,omitempty"`
}

// SubStage contains the input data and expected output
// for tests
type SubStage struct {
	Input  StageInput     `yaml:"input,omitempty"`
	Output ExpectedOutput `yaml:"output,omitempty"`
}

// Test contains the title and test stages
type Test struct {
	Title       string  `yaml:"test_title,omitempty"`
	Description string  `yaml:"desc,omitempty"`
	Stages      []Stage `yaml:"stages,omitempty"`
}

// Profile represents a test profile
// It contains metadata and instructions for a test
// It requires more documentation
type Profile struct {
	Rules string `yaml:"rules,omitempty"`
	Pass  bool   `yaml:"pass,omitempty"`
	Meta  Meta   `yaml:"meta,omitempty"`
	Tests []Test `yaml:"tests,omitempty"`
}

// ExpectedOutput contains the expected output results for a test
type ExpectedOutput struct {
	Headers           map[string]string     `yaml:"headers,omitempty"`
	Data              interface{}           `yaml:"data,omitempty"` // Accepts array or string
	LogContains       string                `yaml:"log_contains,omitempty"`
	NoLogContains     string                `yaml:"no_log_contains,omitempty"`
	ExpectError       bool                  `yaml:"expect_error,omitempty"`
	TriggeredRules    []int                 `yaml:"triggered_rules,omitempty"`
	NonTriggeredRules []int                 `yaml:"non_triggered_rules,omitempty"`
	Status            interface{}           `yaml:"status,omitempty"`
	Interruption      *ExpectedInterruption `yaml:"interruption,omitempty"`
}

// ExpectedInterruption contains the expected interruption results for a test
type ExpectedInterruption struct {
	RuleID int    `yaml:"rule_id,omitempty"`
	Action string `yaml:"action,omitempty"`
	Status int    `yaml:"status,omitempty"`
	Data   string `yaml:"data,omitempty"`
}

// Profiles is a map of registered profiles used by test runners
var Profiles = map[string]Profile{}

// RegisterProfile registers a profile for running from tests
func RegisterProfile(p Profile) Profile {
	Profiles[p.Meta.Name] = p
	return p
}
