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
	Pass  bool
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
