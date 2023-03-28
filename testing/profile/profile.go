// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package profile

// Meta contains the test metadata
type Meta struct {
	Author      string `yaml:"author,omitempty"`
	Description string `yaml:"description,omitempty"`
	Name        string `yaml:"name,omitempty"`
	Enabled     bool   `yaml:"enabled,omitempty"`
}

// StageInput contains the input data for tests
type StageInput struct {
	Headers        map[string]string `yaml:"headers,omitempty"`
	DestAddr       string            `yaml:"dest_addr,omitempty"`
	Method         string            `yaml:"method,omitempty"`
	URI            string            `yaml:"uri,omitempty"`
	Version        string            `yaml:"version,omitempty"`
	Data           string            `yaml:"data,omitempty"` // Accepts array or string
	EncodedRequest string            `yaml:"encoded_request,omitempty"`
	RawRequest     []byte            `yaml:"raw_request,omitempty"`
	Port           int               `yaml:"port,omitempty"`
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
	Output ExpectedOutput `yaml:"output,omitempty"`
	Input  StageInput     `yaml:"input,omitempty"`
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
	Meta  Meta   `yaml:"meta,omitempty"`
	Rules string `yaml:"rules,omitempty"`
	Tests []Test `yaml:"tests,omitempty"`
	Pass  bool   `yaml:"pass,omitempty"`
}

// ExpectedOutput contains the expected output results for a test
type ExpectedOutput struct {
	Data              interface{}           `yaml:"data,omitempty"` // Accepts array or string
	Status            interface{}           `yaml:"status,omitempty"`
	Headers           map[string]string     `yaml:"headers,omitempty"`
	Interruption      *ExpectedInterruption `yaml:"interruption,omitempty"`
	LogContains       string                `yaml:"log_contains,omitempty"`
	NoLogContains     string                `yaml:"no_log_contains,omitempty"`
	TriggeredRules    []int                 `yaml:"triggered_rules,omitempty"`
	NonTriggeredRules []int                 `yaml:"non_triggered_rules,omitempty"`
	ExpectError       bool                  `yaml:"expect_error,omitempty"`
}

// ExpectedInterruption contains the expected interruption results for a test
type ExpectedInterruption struct {
	Action string `yaml:"action,omitempty"`
	Data   string `yaml:"data,omitempty"`
	RuleID int    `yaml:"rule_id,omitempty"`
	Status int    `yaml:"status,omitempty"`
}

// Profiles is a map of registered profiles used by test runners
var Profiles = map[string]Profile{}

// RegisterProfile registers a profile for running from tests
func RegisterProfile(p Profile) Profile {
	Profiles[p.Meta.Name] = p
	return p
}
