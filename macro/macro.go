// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package macro

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type Macro interface {
	Expand(tx rules.TransactionState) string
	String() string
}

func NewMacro(data string) (Macro, error) {
	macro := &macro{
		tokens: []macroToken{},
	}
	if err := macro.compile(data); err != nil {
		return nil, err
	}
	return macro, nil
}

type macroToken struct {
	text     string
	variable *variables.RuleVariable
	key      string
}

// macro is used to create tokenized strings that can be
// "expanded" at high speed and concurrent-safe.
// A macro contains tokens for strings and expansions
// For example: some string %{tx.var} some string
// The previous example would create 3 tokens:
// String token: some string
// Variable token: Variable: TX, key: var
// String token: some string
type macro struct {
	original string
	tokens   []macroToken
}

// Expand the pre-compiled macro expression into a string
func (m *macro) Expand(tx rules.TransactionState) string {
	if len(m.tokens) == 1 {
		return expandToken(tx, m.tokens[0])
	}
	res := strings.Builder{}
	for _, token := range m.tokens {
		res.WriteString(expandToken(tx, token))
	}
	return res.String()
}

func expandToken(tx rules.TransactionState, token macroToken) string {
	if token.variable == nil {
		return token.text
	}
	switch col := tx.Collection(*token.variable).(type) {
	case *collection.Map:
		if c := col.Get(token.key); len(c) > 0 {
			return c[0]
		}
	case *collection.Simple:
		return col.String()
	case *collection.Proxy:
		if c := col.Get(token.key); len(c) > 0 {
			return c[0]
		}
	case *collection.TranslationProxy:
		if c := col.Get(0); len(c) > 0 {
			return c
		}
	}

	return token.text
}

// compile is used to parse the input and generate the corresponding token
// Example input: %{var.foo} and %{var.bar}
// expected result:
// [0] macroToken{text: "%{var.foo}", variable: &variables.Var, key: "foo"},
// [1] macroToken{text: " and ", variable: nil, key: ""}
// [2] macroToken{text: "%{var.bar}", variable: &variables.Var, key: "bar"}
func (m *macro) compile(input string) error {
	currentToken := strings.Builder{}
	m.original = input
	ismacro := false
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
			ismacro = true
			i++
			continue
		}
		if ismacro {
			if c == '}' {
				// we close a macro
				ismacro = false
				varName, key, _ := strings.Cut(currentToken.String(), ".")
				v, err := variables.Parse(varName)
				if err != nil {
					return fmt.Errorf("invalid variable %s", varName)
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
func (m *macro) String() string {
	return m.original
}

// IsExpandable return true if there are macro expanadable tokens
func (m *macro) IsExpandable() bool {
	return len(m.tokens) > 1
}
