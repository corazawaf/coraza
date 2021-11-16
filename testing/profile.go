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
	"os"

	"gopkg.in/yaml.v2"
)

type Profile struct {
	Meta  ProfileMeta   `yaml:"meta"`
	Tests []ProfileTest `yaml:"tests"`
	Rules string        `yaml:"rules"`
	Pass  bool
}

type ProfileMeta struct {
	Author      string `yaml:"author"`
	Description string `yaml:"description"`
	Enabled     bool   `yaml:"enabled"`
	Name        string `yaml:"name"`
}

type ProfileTest struct {
	Title       string             `yaml:"test_title"`
	Description string             `yaml:"desc"`
	Stages      []ProfileTestStage `yaml:"stages"`
}

type ProfileTestStage struct {
	Stage ProfileTestStageInner `yaml:"stage"`
	Pass  bool                  `yaml:"pass"`
	Debug bool                  `yaml:"debug"`
}

type ProfileTestStageInner struct {
	Input  ProfileTestStageInnerInput  `yaml:"input"`
	Output ProfileTestStageInnerOutput `yaml:"output"`
}

type ProfileTestStageInnerInput struct {
	DestAddr       string            `yaml:"dest_addr"`
	Port           int               `yaml:"port"`
	Method         string            `yaml:"method"`
	Uri            string            `yaml:"uri"`
	Version        string            `yaml:"version"`
	Data           interface{}       `yaml:"data"` //Accepts array or string
	Headers        map[string]string `yaml:"headers"`
	RawRequest     string            `yaml:"raw_request"`
	EncodedRequest string            `yaml:"encoded_request"`
	StopMagic      bool              `yaml:"stop_magic"`
}

type ProfileTestStageInnerOutput struct {
	LogContains       string      `yaml:"log_contains"`
	NoLogContains     string      `yaml:"no_log_contains"`
	ExpectError       bool        `yaml:"expect_error"`
	TriggeredRules    []int       `yaml:"triggered_rules"`
	NonTriggeredRules []int       `yaml:"non_triggered_rules"`
	Status            interface{} `yaml:"status"`
}

//NewProfile creates a new profile from a file
func NewProfile(path string) (*Profile, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	profile := new(Profile)
	err = yaml.Unmarshal(f, profile)
	return profile, err
}
