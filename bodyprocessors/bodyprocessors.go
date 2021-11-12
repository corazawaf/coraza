package bodyprocessors

import (
	"fmt"
	"io"

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

type collectionsMap map[variables.RuleVariable]map[string][]string

type BodyProcessor interface {
	Read(reader io.Reader, mime string, storagePath string) error
	Collections() collectionsMap
	Find(string) (map[string][]string, error)
	VariableHook() variables.RuleVariable
}

type bodyProcessorWrapper = func() BodyProcessor

var processors = map[string]bodyProcessorWrapper{}

func RegisterBodyProcessor(name string, fn func() BodyProcessor) {
	processors[name] = fn
}

func GetBodyProcessor(name string) (BodyProcessor, error) {
	if fn, ok := processors[name]; ok {
		return fn(), nil
	}
	return nil, fmt.Errorf("invalid bodyprocessor %q", name)
}

func init() {
	RegisterBodyProcessor("json", func() BodyProcessor {
		return &jsonBodyProcessor{}
	})
	RegisterBodyProcessor("urlencoded", func() BodyProcessor {
		return &urlencodedBodyProcessor{}
	})
	RegisterBodyProcessor("multipart", func() BodyProcessor {
		return &multipartBodyProcessor{}
	})
}
