package bodyprocessors

import (
	"fmt"
	"io"
	"net/http"

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

type multipartBodyProcessor struct {
	collections *collectionsMap
}

func (ue *multipartBodyProcessor) Read(reader io.Reader, mime string, storagePath string) error {
	req, _ := http.NewRequest("GET", "/", reader)
	req.Header.Set("Content-Type", mime)
	err := req.ParseMultipartForm(1000000000)
	defer req.Body.Close()
	if err != nil {
		return err
	}
	totalSize := int64(0)
	fn := map[string][]string{
		"": {},
	}
	fl := map[string][]string{
		"": {},
	}
	fs := map[string][]string{
		"": {},
	}
	for field, fheaders := range req.MultipartForm.File {
		// TODO add them to temporal storage
		// or maybe not, according to http.MultipartForm, it does exactly that
		// the main issue is how do I get this path?
		fn[""] = append(fn[""], field)
		for _, header := range fheaders {
			fl[""] = append(fl[""], header.Filename)
			totalSize += header.Size
			fs[""] = append(fs[""], fmt.Sprintf("%d", header.Size))
		}
	}
	m := map[string][]string{}
	for k, vs := range req.MultipartForm.Value {
		m[k] = vs
	}
	fcs := map[string][]string{
		"": {fmt.Sprintf("%d", totalSize)},
	}
	ue.collections = &collectionsMap{
		variables.FilesNames:        fn,
		variables.Files:             fl,
		variables.FilesSizes:        fs,
		variables.FilesCombinedSize: fcs,
		variables.ArgsPost:          m,
		variables.Args:              m,
	}

	return nil
}

func (js *multipartBodyProcessor) Collections() collectionsMap {
	return *js.collections
}

func (js *multipartBodyProcessor) Find(expr string) (map[string][]string, error) {
	return nil, nil
}

func (js *multipartBodyProcessor) VariableHook() variables.RuleVariable {
	return variables.Json
}

var (
	_ BodyProcessor = &multipartBodyProcessor{}
)
