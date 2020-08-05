/*
This tool is designed to imitate the OWASP CRS WAF testing framework ftw and can be used to automate WAF testing for DevSecOps.
Coraza WAF Testsuite does not require a web server as it is used as a standalone library, providing better feedback and faster.
This tool only works with Coraza WAF.
*/
package main

import (
    "flag"
    "fmt"
    "strings"
    "errors"
    "os"
    "path/filepath"
    "net/url"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"gopkg.in/yaml.v2"
)

var debug = false

func main() {
	mode := flag.String("mode", "test", "Testing mode: benchmark|test")
	path := flag.String("path", "./", "Path to find yaml files")
	rules := flag.String("rules", "/tmp/rules.conf", "Path to rule files for testing.")
	//proxy := flag.String("p", "", "Tests will be proxied to this url, example: https://10.10.10.10:443")
	//duration := flag.Int("d", 500, "Max tests duration in seconds.")
	//iterations := flag.Int("i", 1, "Max test iterations.")
	//concurrency := flag.Int("c", 1, "How many concurrent routines.")
	dodebug := flag.Bool("d", false, "Show debug information.")
	flag.Parse()
	debug = *dodebug

	if *mode == "test"{
		waf := &engine.Waf{}
		waf.Init()
		parser := &parser.Parser{}
		parser.Init(waf)
		err := parser.FromFile(*rules)
		if err != nil{
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
		pass := true
		for _, stage := range test.Stages{
			tx := waf.NewTransaction()
			//Apply tx data
			if len(stage.Stage.Input.Headers) > 0{
				for k, v := range stage.Stage.Input.Headers{
					tx.AddRequestHeader(k, v)
				}
			}

			if stage.Stage.Input.Method != ""{
				tx.SetRequestMethod(stage.Stage.Input.Method)
			}

			if stage.Stage.Input.Uri != ""{
				u, err := url.Parse(stage.Stage.Input.Uri)
				if err != nil {
					if debug{
						fmt.Println("Invalid URL: " + stage.Stage.Input.Uri)
						fmt.Println(err)
					}
				}else{
					tx.SetUrl(u)
					tx.AddArgsFromUrl(u)
				}				
			}

			for i := 1; i <= 5; i++{
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
			if debug{
				fmt.Println("LOG:", log)
			}
		}
		result := "\033[31mFailed"
		if pass{
			result = "\033[32mPassed"
			passed++
		}
		fmt.Printf("%s: %s\033[0m (0us)\n", test.Title, result)
	}
	return len(profile.Tests) == passed, 0, nil
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
}

type testOutput struct{
	LogContains string   `yaml:"log_contains"`
	NoLogContains string `yaml:"no_log_contains"`
	ExpectError bool     `yaml:"expect_error"`
}