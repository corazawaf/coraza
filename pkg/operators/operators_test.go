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

package operators
import(
	"testing"
	"encoding/json"
	"os"
	"strconv"
	"fmt"
	"strings"
	"path/filepath"
	"io/ioutil"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Test struct {
	Input string `json:"input"`
	Param string `json:"param"`
	Name string `json:"name"`
	Ret int `json:"ret"`
	Type string `json:"type"`
}

//https://github.com/SpiderLabs/secrules-language-tests/
func TestTransformations(t *testing.T) {
	root := "../../test/data/operators/"
	files := [][]byte{}
    filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
    	if strings.HasSuffix(path, ".json"){
    		data, _ := ioutil.ReadFile(path)
        	files = append(files, data)
    	}
        return nil
    })
    waf := engine.Waf{}
    waf.Init()
	for _, f := range files {

		cases := []*Test{}
		err := json.Unmarshal(f, &cases)
		if err != nil{
			t.Error("Cannot parse test case")
		}
		for _, data := range cases {
			//UNMARSHALL does not transform \u0000 to binary
			data.Input = strings.ReplaceAll(data.Input,  `\u0000`, "\u0000")
			data.Param = strings.ReplaceAll(data.Param,  `\u0000`, "\u0000")
			
			if strings.Contains(data.Input, `\x`) {
				data.Input, _ = strconv.Unquote(`"`+data.Input+`"`)
			}
			if strings.Contains(data.Param, `\x`) {
				data.Param, _ = strconv.Unquote(`"`+data.Param+`"`)
			}
			op := OperatorsMap()[data.Name]
			if op == nil{
				continue
			}
			if data.Name == "pmFromFile"{
				data.Param = root + "op/" + data.Param
			}
			op.Init(data.Param)
			res := op.Evaluate(waf.NewTransaction(), data.Input)
			if (res && data.Ret != 1) || (!res && data.Ret == 1){
				t.Error(fmt.Sprintf("Invalid operator result for %s(%s, %s) expected %d", data.Name, data.Input, data.Param, data.Ret))
			}
		}
	}

}