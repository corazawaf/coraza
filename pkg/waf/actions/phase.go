package actions

import(
	"strconv"
	"github.com/jptosso/coraza/pkg/models"
)

type Phase struct {}

func (a *Phase) Init(r *models.Rule, data string, errors []string) () {
	i, _ := strconv.Atoi(data)
	r.Phase = int(i)
}

func (a *Phase) Evaluate(r *models.Rule, tx *models.Transaction) () {
	
}

func (a *Phase) GetType() string{
	return "metadata"
}
