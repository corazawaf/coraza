package utils

import(
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

type callback func(string, bool)

type TestSuite struct{
	profiles []*testProfile
	waf *engine.Waf
}

func (ts *TestSuite) Init(cfg string){
	ts.profiles = []*testProfile{}
	ts.waf = engine.NewWaf()
	parser := &parser.Parser{}
	parser.Init(ts.waf)
	parser.FromFile(cfg)
}

func (ts *TestSuite) AddProfile(path string) error {
	data, err := utils.OpenFile(path)
	if err != nil {
		return errors.New("Cannot open file " + path)
	}
	profile := testProfile{}
	err = yaml.Unmarshal(data, &profile)
	if err != nil {
		return err
	}
	ts.profiles = append(ts.profiles, &profile)
	return nil
}

func (ts *TestSuite) Start(cb callback) error {
	//TODO add routines
	for _, p := range ts.profiles {
		res, _ := ts.runTest(p)
		cb(p.Meta.Name, res)
	}
	return nil
}

func (ts *TestSuite) GetProfiles() []*testProfile {
	return ts.profiles
}

func (ts *TestSuite) runTest(profile *testProfile) (bool, error) {
	passed := 0
	waf := ts.waf
	if profile.Rules != ""{
		log.Debug("Loading rules from string")
		waf = engine.NewWaf()
		p := &parser.Parser{}
		p.Init(waf)
		p.FromString(profile.Rules)
	}
	for _, test := range profile.Tests {
		//tn := time.Now().UnixNano()
		pass := true
		for _, stage := range test.Stages {
			tx := waf.NewTransaction()
			if stage.Stage.Input.EncodedRequest != "" {
				sDec, _ := b64.StdEncoding.DecodeString(stage.Stage.Input.EncodedRequest)
				stage.Stage.Input.RawRequest = string(sDec)
			}
			if stage.Stage.Input.RawRequest != "" {
				err := tx.ParseRequestString(stage.Stage.Input.RawRequest)
				if err != nil {
					return false, err
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
				parseInputData(stage.Stage.Input.Data, tx)
			}

			for i := 2; i <= 5; i++ {
				tx.ExecutePhase(i)
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
					pass = false
				}
			}
			if stage.Stage.Output.NoLogContains != "" {
				if strings.Contains(log, stage.Stage.Output.NoLogContains) {
					pass = false
				}
			}
			if len(stage.Stage.Output.TriggeredRules) > 0 {
				for _, trr := range stage.Stage.Output.TriggeredRules{
					if !utils.ArrayContainsInt(tr, trr){
						pass = false
						break
					}
				}
			}
			if len(stage.Stage.Output.NonTriggeredRules) > 0 {
				for _, trr := range stage.Stage.Output.NonTriggeredRules{
					if utils.ArrayContainsInt(tr, trr){
						pass = false
						break
					}
				}
			}			
		}
		if pass {
			passed++
		}
	}
	return len(profile.Tests) == passed, nil
}

func parseInputData(input interface{}, tx *engine.Transaction){
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
	rh := tx.GetCollection("request_headers")
	ct := rh.GetSimple("content-type")
	ctt := ""
	if len(ct) == 1 {
		ctt = ct[0]
	}
	tx.ParseRequestBodyBinary(ctt, data)
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
	LogContains   string `yaml:"log_contains"`
	NoLogContains string `yaml:"no_log_contains"`
	ExpectError   bool   `yaml:"expect_error"`
	TriggeredRules []int `yaml:"triggered_rules"`
	NonTriggeredRules []int `yaml:"non_triggered_rules"`
}
