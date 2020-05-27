package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
	"strings"
)

type SkipAfter struct {
	data string
}

//NOT IMPLEMENTED
func (a *SkipAfter) Init(r *models.Rule, data string, errors []string) () {
	a.data = strings.Trim(data, `"`)
}

func (a *SkipAfter) Evaluate(r *models.Rule, tx *models.Transaction) () {
	tx.SkipAfter = a.data
}

func (a *SkipAfter) GetType() string{
	return ""
}
