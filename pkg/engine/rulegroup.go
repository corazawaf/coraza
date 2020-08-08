package engine
import(
	"errors"
	"fmt"
	"sort"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

type RuleGroup struct{
	rules []*Rule
}

func (rg *RuleGroup) Init(){
	rg.rules = []*Rule{}
}

// Adds a rule to the collection
// Will return an error if the ID is already used
func (rg *RuleGroup) Add(rule *Rule) error{
	if rg.FindById(rule.Id) != nil{
		return errors.New(fmt.Sprintf("There is a another rule with ID %d", rule.Id))
	}
	rg.rules = append(rg.rules, rule)
	return nil
}

func (rg *RuleGroup) GetRules() []*Rule{
	return rg.rules
}

func (rg *RuleGroup) Sort() {
	sort.Slice(rg.rules, func(i, j int) bool {
	  return rg.rules[i].Id < rg.rules[j].Id
	})
}

func (rg *RuleGroup) FindById(id int) *Rule{
	for _, r := range rg.rules{
		if r.Id == id{
			return r
		}
	}
	return nil
}

func (rg *RuleGroup) DeleteById(id int){
	for i, r := range rg.rules{
		if r.Id == id{
			copy(rg.rules[i:], rg.rules[i+1:])
			rg.rules[len(rg.rules)-1] = nil
			rg.rules = rg.rules[:len(rg.rules)-1]
		}
	}
}

func (rg *RuleGroup) FindByMsg(msg string) []*Rule{
	rules := []*Rule{}
	for _, r := range rg.rules{
		if r.Msg == msg{
			rules = append(rules, r)
		}
	}
	return rules
}

func (rg *RuleGroup) FindByTag(tag string) []*Rule{
	rules := []*Rule{}
	for _, r := range rg.rules{
		if utils.StringInSlice(tag, r.Tags) {
			rules = append(rules, r)
		}
	}
	return rules
}

func (rg *RuleGroup) Count() int{
	return len(rg.rules)
}