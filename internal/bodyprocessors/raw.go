package bodyprocessors

import (
	"io"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
)

type rawBodyProcessor struct {
}

func (*rawBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	b := buf.String()

	v.RequestBody().(*collections.Single).Set(b)
	v.RequestBodyLength().(*collections.Single).Set(strconv.Itoa(len(b)))
	return nil
}

func (*rawBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

var (
	_ plugintypes.BodyProcessor = &rawBodyProcessor{}
)

func init() {
	RegisterBodyProcessor("raw", func() plugintypes.BodyProcessor {
		return &rawBodyProcessor{}
	})
}
