package actions

import(
	"strconv"
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Id struct {
}

func (a *Id) Init(r *models.Rule, data string, errors []string) () {
	i, err := strconv.Atoi(data)
	if err != nil{
		errors = append(errors, "Invalid rule ID " + data)
	}
	r.Id = int(i)
}

func (a *Id) Evaluate(r *models.Rule, tx *models.Transaction) () {

}

func (a *Id) GetType() string{
	return "metadata"
}
