package transformations
import(
	"testing"
	"encoding/json"
	"os"
	"strings"
	"path/filepath"
	"io/ioutil"
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
	root := "./test/data/slt/transformations/"
	files := [][]byte{}
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
    	if strings.HasSuffix(path, ".json"){
    		data, err := ioutil.ReadFile(path)
        	files = append(files, data)
    	}
        return nil
    })
	for _, f := range files {

		cases := []*Test{}
		err := json.Unmarshal(f, &cases)
		if err != nil{
			t.Error("Cannot parse test case " )
		}
		for _, data := range cases {
			trans := TransformationsMap()[data.Name]
			if trans == nil{
				t.Error("Invalid transformation test for " + data.Name)
				continue
			}
			out := trans(data.Input)
			if out != data.Output{
				t.Error(fmt.Sprintf("Invalid transaction result for %s with input %s\n", data.Name, data.Input))
			}
		}
	}

}