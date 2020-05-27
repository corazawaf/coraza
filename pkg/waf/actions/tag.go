package actions

import(
	"github.com/jptosso/coraza/pkg/models"
)

type Tag struct {
}

func (a *Tag) Init(r *models.Rule, data string, errors []string) () {
	r.Tags = append(r.Tags, data[1:len(data)-1])
}

func (a *Tag) Evaluate(r *models.Rule, tx *models.Transaction) () {

}

func (a *Tag) GetType() string{
	return "metadata"
}
