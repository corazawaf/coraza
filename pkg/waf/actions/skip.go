package actions

import(
	"github.com/jptosso/coraza/pkg/models"
	"strconv"
)

//NOT IMPLEMENTED
type Skip struct {
	data int
}

func (a *Skip) Init(r *models.Rule, data string, errors []string) () {
	i, err := strconv.Atoi(data)
	if err != nil{

	}
	a.data = i
}

func (a *Skip) Evaluate(r *models.Rule, tx *models.Transaction) () {
	tx.Skip = a.data
}

func (a *Skip) GetType() string{
	return ""
}
