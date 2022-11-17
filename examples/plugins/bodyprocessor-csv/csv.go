package plugin

import (
	"encoding/csv"
	"fmt"
	"io"

	"github.com/corazawaf/coraza/v3/bodyprocessors"
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/rules"
)

type csvBodyProcessor struct{}

func (p *csvBodyProcessor) ProcessRequest(reader io.Reader, variables rules.TransactionVariables, options bodyprocessors.Options) error {
	return p.bodyToVariables(reader, variables.ArgsPost())
}

func (p *csvBodyProcessor) ProcessResponse(reader io.Reader, variables rules.TransactionVariables, options bodyprocessors.Options) error {
	return nil
}

// We assign all values to each key name, for example:
// id, name
// 1, foo
// 2, bar
// Will create the variables:
// VARIABLE.CSV.0.id = 1
// VARIABLE.CSV.0.name = foo
// VARIABLE.CSV.1.id = 2
// VARIABLE.CSV.1.name = bar
func (p *csvBodyProcessor) bodyToVariables(reader io.Reader, variable *collection.Map) error {
	r := csv.NewReader(reader)
	matrix, err := r.ReadAll()
	if err != nil {
		return err
	}
	if len(matrix) == 0 {
		return nil
	}
	for i, row := range matrix {
		for j, value := range row {
			variable.SetIndex(fmt.Sprintf("VARIABLE.CSV.%d.%s", i, matrix[0][j]), 0, value)
		}
	}
	return nil
}

var _ bodyprocessors.BodyProcessor = (*csvBodyProcessor)(nil)

func init() {
	bodyprocessors.Register("csv", func() bodyprocessors.BodyProcessor {
		return &csvBodyProcessor{}
	})
}
