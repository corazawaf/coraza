// Copyright 2020 Juan Pablo Tosso
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

// This tool is designed to imitate the OWASP CRS WAF testing framework ftw and can be used to automate WAF testing for DevSecOps.
// Coraza WAF Testsuite does not require a web server as it is used as a standalone library, providing better feedback and faster.
// This tool only works with Coraza WAF.
package main

import (
    "flag"
    "fmt"
    "strings"
    "errors"
    "time"
    "os"
    "regexp"
    "bufio"
    "io/ioutil"
    "reflect"
    "mime"
    "mime/multipart"
    "strconv"
    "path/filepath"
    "net/url"
    "net/http"
    b64 "encoding/base64"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"gopkg.in/yaml.v2"
)

var debug = false
var failonly = false
func main() {
	mode := flag.String("mode", "test", "Testing mode: benchmark|test")
	path := flag.String("path", "./", "Path to find yaml files")
	rules := flag.String("rules", "/tmp/rules.conf", "Path to rule files for testing.")
	fo := flag.Bool("fo", false, "Filter by fails only.")
	//proxy := flag.String("p", "", "Tests will be proxied to this url, example: https://10.10.10.10:443")
	//duration := flag.Int("d", 500, "Max tests duration in seconds.")
	//iterations := flag.Int("i", 1, "Max test iterations.")
	//concurrency := flag.Int("c", 1, "How many concurrent routines.")
	dodebug := flag.Bool("d", false, "Show debug information.")
	flag.Parse()
	debug = *dodebug
	failonly = *fo

	fmt.Println("Starting Coraza WAF testsuite...")

	if *mode == "test"{
		waf := &engine.Waf{}
		waf.Init()
		parser := &parser.Parser{}
		parser.Init(waf)
		err := parser.FromFile(*rules)
		if err != nil{
			fmt.Println("Error parsing configurations")
			fmt.Println(err)
			return
		}		
		fmt.Printf("Loaded %d rules\n", waf.Rules.Count())
		err = evaluateTests(*path, waf)
		if err != nil{
			fmt.Println(err)
			return
		}
	}else if *mode == "benchmark"{
		fmt.Println("Not supported yet.")
	}
}

func getYamlFromDir(directory string) ([]string, error){
	files := []string{}
	err := filepath.Walk(directory,
	    func(path string, info os.FileInfo, err error) error {
	    if err != nil {
	        return err
	    }
	    if strings.HasSuffix(path, ".yaml"){
	    	files = append(files, path)
	    }
	    return nil
	})
	if err != nil {
	    return files, err
	}
	return files, nil
}

func evaluateTests(path string, waf *engine.Waf) error{
	files, err := getYamlFromDir(path)
	if err != nil{
		return err
	}
	profiles := []testProfile{}
	for _, f := range files{
		data, err := utils.OpenFile(f)
		if err != nil{
			return errors.New("Cannot open file " + f)
		}
		p, err := parseTest(data)
		if err != nil{
			if debug{
				fmt.Println(err)
			}
			return errors.New("Error parsing test " + f)
		}
		profiles = append(profiles, p)
	}
	fmt.Printf("%d tests loaded.\n", len(profiles))
	oks := 0
	for _, p := range profiles{
		res, _, err := runTest(waf, p)
		if err != nil{
			return err
		}
		if res{
			oks++
		}
	}
	fmt.Printf("Passed %d/%d\n", oks, len(profiles))
	return nil
}

func parseTest(data []byte) (testProfile, error){
        profile := testProfile{}
        err := yaml.Unmarshal(data, &profile)
        if err != nil{
        	return profile, err
        }
        return profile, nil
}

func benchmarkreport(){
	fmt.Println("Results:")
	fmt.Println("Started at: ")
	fmt.Println("Ended at: (N minutes)")
	fmt.Println("Rules tested: ")
	fmt.Println("Test iterations: ")
	fmt.Println("====== RULES AVERAGE PERFORMANCE ======")
	fmt.Println("12345: 4us")
}

//Returns result, time elapsed and error
func runTest(waf *engine.Waf, profile testProfile) (bool, int, error){
	passed := 0
	for _, test := range profile.Tests{
		tn := time.Now().UnixNano()
		pass := true
		for _, stage := range test.Stages{
			tx := waf.NewTransaction()
			if stage.Stage.Input.EncodedRequest != ""{
				sDec, _ := b64.StdEncoding.DecodeString(stage.Stage.Input.EncodedRequest)
				stage.Stage.Input.RawRequest = string(sDec)
			}
			if stage.Stage.Input.RawRequest != ""{
				req, err := requestFromString(stage.Stage.Input.RawRequest)
				if err != nil{
					fmt.Println("Error parsing HTTP request:")
					fmt.Println(err)
					return false, 0, err
				}
				requestToTx(req, tx)
			}
			//Apply tx data
			if len(stage.Stage.Input.Headers) > 0{
				for k, v := range stage.Stage.Input.Headers{
					tx.AddRequestHeader(k, v)
				}
			}			
			method := "GET"
			if stage.Stage.Input.Method != ""{
				method = stage.Stage.Input.Method
				tx.SetRequestMethod(method)
			}

			//Request Line
			httpv := "HTTP/1.1"
			if stage.Stage.Input.Version != ""{
				httpv = stage.Stage.Input.Version
			}

			path := "/"
			if stage.Stage.Input.Uri != ""{
				u, err := url.Parse(stage.Stage.Input.Uri)
				if err != nil {
					if debug{
						fmt.Println("Invalid URL: " + stage.Stage.Input.Uri)
						fmt.Println(err)
					}
				}else{
					tx.SetUrl(u)
					tx.AddGetArgsFromUrl(u)
					path = stage.Stage.Input.Uri//or unescaped?	
				}
				
			}
			tx.SetRequestLine(method, httpv, path)

			//PHASE 1
			tx.ExecutePhase(1)

			// POST DATA
			if stage.Stage.Input.Data != ""{
				data := ""
				v := reflect.ValueOf(stage.Stage.Input.Data)
				switch v.Kind() {
				case reflect.Slice:
			        for i := 0; i < v.Len(); i++ {
			            data += fmt.Sprintf("%s\r\n", v.Index(i))
			        }
			        data += "\r\n"
				case reflect.String:
					data = stage.Stage.Input.Data.(string)
				}
				rh := tx.GetCollection("request_headers")
				ct := rh.GetSimple("content-type")
				ctt := ""
				if len(ct) == 1{
					ctt = ct[0]
				}
				mediaType, params, _ := mime.ParseMediaType(ctt)
				if method == "GET" || method == "HEAD" || method == "OPTIONS" {
					length := strconv.Itoa(len(data))
					if len(rh.GetSimple("content-length")) == 0{
						rh.Set("content-length", []string{length})
					}
					// Just for testing
					tx.GetCollection("request_body").Set("", []string{data})
				}else if strings.HasPrefix(mediaType, "multipart/") {
					parseMultipart(data, params["boundary"], tx)
				}else {
					tx.SetRequestBody(data, int64(len(data)), mediaType)
					u, err := url.ParseQuery(data)
					if err == nil{
						tx.SetArgsPost(u)
					}
				}
			}

			for i := 2; i <= 5; i++{
				tx.ExecutePhase(i)
			}
			log := ""
			for _, mr := range tx.MatchedRules{
				log += fmt.Sprintf(" [id \"%d\"]", mr.Id)
			}
			//now we evaluate tests
			if stage.Stage.Output.LogContains != ""{
				if !strings.Contains(log, stage.Stage.Output.LogContains){
					pass = false
				}
			}
			if stage.Stage.Output.NoLogContains != ""{
				if strings.Contains(log, stage.Stage.Output.NoLogContains){
					pass = false
				}
			}
		}
		result := "\033[31mFailed"
		if pass{
			result = "\033[32mPassed"
			passed++
			if failonly{
				continue
			}
		}
		fmt.Printf("%s: %s\033[0m (%dus)\n", test.Title, result, time.Now().UnixNano()-tn)
	}
	return len(profile.Tests) == passed, 0, nil
}

func requestFromString(data string) (*http.Request, error) {
    req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(data)))
    return req, err
}

func requestToTx(req *http.Request, tx *engine.Transaction){
    re := regexp.MustCompile(`^\[(.*?)\]:(\d+)$`)
    matches := re.FindAllStringSubmatch(req.RemoteAddr, -1)
    address := ""
    port := 0
    //no more validations as we don't take weird ip addresses
    if len(matches) > 0 {
        address = string(matches[0][1])
        port, _ = strconv.Atoi(string(matches[0][2]))
    }
    tx.SetRequestHeaders(req.Header)
    tx.SetArgsGet(req.URL.Query())
    tx.SetUrl(req.URL)
    tx.SetRemoteAddress(address, port)
    tx.SetRequestCookies(req.Cookies())
    tx.SetRequestLine(req.Method, req.Proto, req.RequestURI)
}

func parseMultipart(body string, boundary string, tx *engine.Transaction) error{
	if debug{
		fmt.Println("Parsing multipart")
	}
	mr := multipart.NewReader(strings.NewReader(body), boundary)
	files := map[string][]*multipart.FileHeader{}
	args := map[string][]string{}
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		data, err := ioutil.ReadAll(p)
		if err != nil {
			return err
		}
		key := p.FormName()
		file := p.FileName()
		mpf := &multipart.FileHeader{
			Filename: file, 
			Header: p.Header, 
			Size: int64(len(data)),
		}
		if files[key] == nil{
			files[key] = []*multipart.FileHeader{mpf}
		}else{
			files[key] = append(files[key], mpf)
		}
		if args[key] == nil{
			args[key] = []string{string(data)}
		}else{
			args[key] = append(args[key], string(data))
		}
	}
    tx.SetFiles(files)
    tx.SetArgsPost(args)
    return nil
}

type testProfile struct{
	Meta testMeta        `yaml:"meta"`
	Tests []testTest     `yaml:"tests"`
}

type testMeta struct{
	Author string        `yaml:"author"`
	Description string   `yaml:"description"`
	Enabled bool         `yaml:"enabled"`
	Name string          `yaml:"name"`
}

type testTest struct{
	Title string         `yaml:"test_title"`
	Description string   `yaml:"desc"`
	Stages []testStage   `yaml:"stages"`
}

type testStage struct{
	Stage testStageInner `yaml:"stage"`
}

type testStageInner struct{
	Input testInput      `yaml:"input"`
	Output testOutput    `yaml:"output"`	
}

type testInput struct{
	DestAddr string      `yaml:"dest_addr"`
	Port int             `yaml:"port"`
	Method string        `yaml:"method"`
	Uri string           `yaml:"uri"`
	Version string       `yaml:"version"`
	Data interface{}        `yaml:"data"` //Accepts array or string
	Headers map[string]string    `yaml:"headers"`
	RawRequest string `yaml:"raw_request"`
	EncodedRequest string `yaml:"encoded_request"`
}

type testOutput struct{
	LogContains string   `yaml:"log_contains"`
	NoLogContains string `yaml:"no_log_contains"`
	ExpectError bool     `yaml:"expect_error"`
}