package coraza

import (
	"fmt"
	"strings"

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

type macroToken struct {
	text     string
	variable *variables.RuleVariable
	key      string
}
type Macro struct {
	original string
	tokens   []macroToken
}

func (m *Macro) Expand(tx *Transaction) string {
	res := strings.Builder{}
	for _, token := range m.tokens {
		// now we place the in the index
		if token.variable != nil {
			col := tx.GetCollection(*token.variable)
			if col == nil {
				return m.original
			}
			// we get the key from the collection
			// Get does not support regex
			data := col.Get(token.key)
			if len(data) == 0 {
				res.WriteString(token.text)
				continue
			}
			res.WriteString(data[0])
		} else {
			res.WriteString(token.text)
		}
	}
	return res.String()
}

// Example input: %{var.foo} and %{var.bar}
// expected result:
// macroToken{text: "%{var.foo}", variable: &variables.Var, key: "foo"},
// macroToken{text: " and ", variable: nil, key: ""}
// macroToken{text: "%{var.bar}", variable: &variables.Var, key: "bar"}
func (m *Macro) Compile(input string) error {
	data := []rune(input)
	currentToken := ""
	m.original = input
	isMacro := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c == '%' && (i <= len(data) && data[i+1] == '{') {
			// we have a macro
			if len(currentToken) > 0 {
				// we add the text token
				m.tokens = append(m.tokens, macroToken{
					text:     currentToken,
					variable: nil,
					key:      "",
				})
			}
			currentToken = ""
			isMacro = true
			i++
			continue
		}
		if isMacro {
			if c == '}' {
				// we close a macro
				isMacro = false
				spl := strings.SplitN(currentToken, ".", 2)
				key := ""
				if len(spl) == 2 {
					key = spl[1]
				} else if len(spl) == 0 {
					return fmt.Errorf("invalid macro %s", currentToken)
				}
				v, err := variables.Parse(spl[0])
				if err != nil {
					return fmt.Errorf("invalid variable %s", spl[0])
				}
				// we add the variable token
				m.tokens = append(m.tokens, macroToken{
					text:     currentToken,
					variable: &v,
					key:      strings.ToLower(key),
				})
				currentToken = ""
				continue
			}
			currentToken += string(c)
			continue
		}
		// we have a normal character
		currentToken += string(c)
	}
	// if there is something left
	if len(currentToken) > 0 {
		m.tokens = append(m.tokens, macroToken{
			text:     currentToken,
			variable: nil,
			key:      "",
		})
	}
	return nil
}

func (m *Macro) String() string {
	return m.original
}

func NewMacro(data string) (*Macro, error) {
	macro := &Macro{
		tokens: []macroToken{},
	}
	if err := macro.Compile(data); err != nil {
		return nil, err
	}
	return macro, nil
}
