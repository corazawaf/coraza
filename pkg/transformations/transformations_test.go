package transformations
import(
	"testing"
	"encoding/json"
	"os"
	"reflect"
	"fmt"
	"strconv"
	"strings"
	"path/filepath"
	"io/ioutil"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

type Test struct {
	Input string `json:"input"`
	Output string `json:"output"`
	Name string `json:"name"`
	Ret int `json:"ret"`
	Type string `json:"type"`
}

//https://github.com/SpiderLabs/secrules-language-tests/
func TestTransformations(t *testing.T) {
	utils.InitUnicodeMapping()
	root := "../../test/data/transformations/"
	files := [][]byte{}
    filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
    	if strings.HasSuffix(path, ".json"){
    		data, _ := ioutil.ReadFile(path)
        	files = append(files, data)
    	}
        return nil
    })
	for _, f := range files {

		cases := []*Test{}
		err := json.Unmarshal(f, &cases)
		if err != nil{
			t.Error("Cannot parse test case")
		}
		for _, data := range cases {
			//UNMARSHALL does not transform \u0000 to binary
			data.Input = strings.ReplaceAll(data.Input,  `\u0000`, "\u0000")
			data.Output = strings.ReplaceAll(data.Output,  `\u0000`, "\u0000")
			
			if strings.Contains(data.Input, `\x`) {
				data.Input, _ = strconv.Unquote(`"`+data.Input+`"`)
			}
			if strings.Contains(data.Output, `\x`) {
				data.Output, _ = strconv.Unquote(`"`+data.Output+`"`)
			}
			trans := TransformationsMap()[data.Name]
			if trans == nil{
				//t.Error("Invalid transformation test for " + data.Name)
				continue
			}
			out := executeTransformation(trans, data.Input)
			if out != data.Output{
				t.Error(fmt.Sprintf("Invalid transformation result for %s with input %s, got %s and expected %s\n", data.Name, data.Input, out, data.Output))
				t.Error([]byte(data.Output))
				t.Error([]byte(out))
			}
		}
	}

}

func executeTransformation(t interface{}, value string) string{
    rf := reflect.ValueOf(t)
    rargs := make([]reflect.Value, 1)
    rargs[0] = reflect.ValueOf(value)
    call := rf.Call(rargs)
    value = call[0].String()
    return value
}