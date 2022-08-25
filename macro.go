// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type macroToken struct {
	text     string
	variable *variables.RuleVariable
	key      string
}

// Macro is used to create tokenized strings that can be
// "expanded" at high speed and concurrent-safe.
// A Macro contains tokens for strings and expansions
// For example: some string %{tx.var} some string
// The previous example would create 3 tokens:
// String token: some string
// Variable token: Variable: TX, key: var
// String token: some string
type Macro struct {
	original string
	tokens   []macroToken
}

// Expand the pre-compiled macro expression into a string
func (m *Macro) Expand(tx *Transaction) string {
	res := strings.Builder{}
	for _, token := range m.tokens {
		// now we place the in the index
		if token.variable != nil {
			switch col := tx.Collections[*token.variable].(type) {
			case *collection.Map:
				if c := col.Get(token.key); len(c) > 0 {
					res.WriteString(c[0])
				} else {
					res.WriteString(token.text)
				}
			case *collection.Simple:
				res.WriteString(col.String())
			case *collection.Proxy:
				if c := col.Get(token.key); len(c) > 0 {
					res.WriteString(c[0])
				} else {
					res.WriteString(token.text)
				}
			case *collection.TranslationProxy:
				if c := col.Get(0); len(c) > 0 {
					res.WriteString(c)
				} else {
					res.WriteString(token.text)
				}
			}
		} else {
			res.WriteString(token.text)
		}
	}
	return res.String()
}

// Compile is used to parse the input and generate the corresponding token
// Example input: %{var.foo} and %{var.bar}
// expected result:
// [0] macroToken{text: "%{var.foo}", variable: &variables.Var, key: "foo"},
// [1] macroToken{text: " and ", variable: nil, key: ""}
// [2] macroToken{text: "%{var.bar}", variable: &variables.Var, key: "bar"}
func (m *Macro) Compile(input string) error {
	currentToken := strings.Builder{}
	m.original = input
	isMacro := false
	for i := 0; i < len(input); i++ {
		c := input[i]
		if c == '%' && (i <= len(input) && input[i+1] == '{') {
			// we have a macro
			if currentToken.Len() > 0 {
				// we add the text token
				m.tokens = append(m.tokens, macroToken{
					text:     currentToken.String(),
					variable: nil,
					key:      "",
				})
			}
			currentToken.Reset()
			isMacro = true
			i++
			continue
		}
		if isMacro {
			if c == '}' {
				// we close a macro
				isMacro = false
				spl := strings.SplitN(currentToken.String(), ".", 2)
				key := ""
				if len(spl) == 2 {
					key = spl[1]
				} else if len(spl) == 0 {
					return fmt.Errorf("invalid macro %s", currentToken.String())
				}
				v, err := variables.Parse(spl[0])
				if err != nil {
					return fmt.Errorf("invalid variable %s", spl[0])
				}
				// we add the variable token
				m.tokens = append(m.tokens, macroToken{
					text:     currentToken.String(),
					variable: &v,
					key:      strings.ToLower(key),
				})
				currentToken.Reset()
				continue
			}
			currentToken.WriteByte(c)
			continue
		}
		// we have a normal character
		currentToken.WriteByte(c)
	}
	// if there is something left
	if currentToken.Len() > 0 {
		m.tokens = append(m.tokens, macroToken{
			text:     currentToken.String(),
			variable: nil,
			key:      "",
		})
	}
	return nil
}

// String returns the original string
func (m *Macro) String() string {
	return m.original
}

// IsExpandable return true if there are macro expanadable tokens
func (m *Macro) IsExpandable() bool {
	return len(m.tokens) > 1
}

// NewMacro creates a new macro
func NewMacro(data string) (*Macro, error) {
	macro := &Macro{
		tokens: []macroToken{},
	}
	if err := macro.Compile(data); err != nil {
		return nil, err
	}
	return macro, nil
}
