// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

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
	Data           string            `yaml:"data,omitempty"` // Accepts array or string
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

	// Rules overrides Profile.Rules for this test only. It exists so that a
	// behaviour needing its own ruleset does not require a whole new profile
	// file: group the cases by the behaviour under test, not by the ruleset.
	// When empty, Profile.Rules is used.
	Rules string `yaml:"rules,omitempty"`
}

// Profile represents a test profile
// It contains metadata and instructions for a test
// It requires more documentation
type Profile struct {
	// Rules is the default ruleset for every test in the profile.
	// Individual tests may override it with Test.Rules.
	Rules string `yaml:"rules,omitempty"`
	// Deprecated: Pass is not evaluated by the runner. Express the expectation
	// in ExpectedOutput instead.
	Pass  bool   `yaml:"pass,omitempty"`
	Meta  Meta   `yaml:"meta,omitempty"`
	Tests []Test `yaml:"tests,omitempty"`
}

// ExpectedOutput contains the expected output results for a test
type ExpectedOutput struct {
	Headers       map[string]string `yaml:"headers,omitempty"`
	Data          any               `yaml:"data,omitempty"` // Accepts array or string
	LogContains   string            `yaml:"log_contains,omitempty"`
	NoLogContains string            `yaml:"no_log_contains,omitempty"`
	// ExpectError asserts that running the phases returns an error.
	ExpectError       bool  `yaml:"expect_error,omitempty"`
	TriggeredRules    []int `yaml:"triggered_rules,omitempty"`
	NonTriggeredRules []int `yaml:"non_triggered_rules,omitempty"`

	// TriggeredRulesCount asserts how many times each rule id was matched.
	// Use it for duplicate-logging regressions: a rule id present in
	// TriggeredRules only asserts "at least once".
	TriggeredRulesCount map[int]int `yaml:"triggered_rules_count,omitempty"`

	// LogContainsCount asserts how many error log lines contain each substring.
	// Use it to pin down repeated tags, messages or logdata.
	LogContainsCount map[string]int `yaml:"log_contains_count,omitempty"`

	// Variables asserts the value of transaction variables after phase 5.
	// Keys are seclang variable selectors, e.g. "TX:score" or "REQUEST_URI".
	// Use it instead of hand-driving a transaction to check setvar results.
	Variables map[string]string `yaml:"variables,omitempty"`

	// AuditLog asserts on the audit log produced by the transaction.
	AuditLog *ExpectedAuditLog `yaml:"audit_log,omitempty"`

	// Deprecated: Status is not evaluated. Assert Interruption.Status instead.
	Status       any                   `yaml:"status,omitempty"`
	Interruption *ExpectedInterruption `yaml:"interruption,omitempty"`
}

// ExpectedAuditLog contains the expected audit log results for a test.
// It exists so audit log behaviour is asserted from the same declarative case
// as the rule behaviour that produced it, instead of from a separate hand
// written transaction test.
type ExpectedAuditLog struct {
	// Parts asserts the exact set of audit log parts, e.g. "ABCFHZ".
	Parts string `yaml:"parts,omitempty"`
	// MessageCount asserts the number of messages in part H.
	// It is a pointer so that 0 can be asserted explicitly.
	MessageCount *int `yaml:"message_count,omitempty"`
	// MessagesContain asserts every listed substring appears in some message.
	MessagesContain []string `yaml:"messages_contain,omitempty"`
	// NoMessagesContain asserts no message contains any listed substring.
	NoMessagesContain []string `yaml:"no_messages_contain,omitempty"`
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

// RegisterProfile registers a profile for running from tests.
//
// Profiles are keyed by Meta.Name, so a duplicate name would silently replace
// an already registered profile and drop its cases from every run. Panicking
// here surfaces the mistake at package initialisation instead.
func RegisterProfile(p Profile) Profile {
	if p.Meta.Name == "" {
		panic("profile: Meta.Name is required")
	}
	if _, ok := Profiles[p.Meta.Name]; ok {
		panic("profile: duplicate profile name " + p.Meta.Name)
	}
	Profiles[p.Meta.Name] = p
	return p
}
