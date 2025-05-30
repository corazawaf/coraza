// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	_ "embed"
	"go/ast"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"os"
	"regexp"
	"strings"
	"text/template"
)

//go:embed variablesmap.go.tmpl
var variablesMapTmpl string

type VariablesMap struct {
	Key           string
	Value         string
	CanBeSelected bool
}

func main() {
	tmpl, err := template.New("variablesmap").Parse(variablesMapTmpl)
	if err != nil {
		log.Fatal(err)
	}

	fset := token.NewFileSet()

	src, err := os.ReadFile("./variables.go")
	if err != nil {
		log.Fatal(err)
	}

	f, err := parser.ParseFile(fset, "variables.go", src, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}

	conf := types.Config{Importer: importer.Default()}
	info := &types.Info{
		Defs: make(map[*ast.Ident]types.Object),
	}
	_, err = conf.Check("variables.go", fset, []*ast.File{f}, info)
	if err != nil {
		log.Fatal(err) // type error
	}

	var directives []VariablesMap
	ast.Inspect(f, func(n ast.Node) bool {
		switch decl := n.(type) {
		case *ast.GenDecl:
			if decl.Tok != token.CONST {
				return true
			}
			for _, s := range decl.Specs {
				v := s.(*ast.ValueSpec) // safe because decl.Tok == token.CONST
				for _, name := range v.Names {
					c := info.ObjectOf(name).(*types.Const)
					if !strings.HasSuffix(c.Type().String(), "RuleVariable") {
						continue
					}

					value := ToUpperSnakeCase(name.String())
					if name.String() == "FilesTmpNames" {
						value = "FILES_TMPNAMES"
					}

					canBeSelected := false
					if v.Comment != nil {
						for _, c := range v.Comment.List {
							if strings.Contains(c.Text, "CanBeSelected") {
								canBeSelected = true
							}
						}
					}

					directives = append(directives, VariablesMap{
						Key:           name.String(),
						Value:         value,
						CanBeSelected: canBeSelected,
					})
				}
			}
		default:

		}

		return true
	})

	dmc := bytes.Buffer{}
	err = tmpl.Execute(&dmc, directives)
	if err != nil {
		log.Fatal(err)
	}

	fdmc, err := format.Source(dmc.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	dm, err := os.Create("./variablesmap.gen.go")
	if err != nil {
		log.Fatal(err)
	}

	_, err = dm.Write(fdmc)
	if err != nil {
		log.Fatal(err)
	}

	err = dm.Close()
	if err != nil {
		log.Fatal(err)
	}
}

var (
	matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
	matchAllCap   = regexp.MustCompile("([a-z0-9])([A-Z])")
)

func ToUpperSnakeCase(str string) string {
	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")
	return strings.ToUpper(snake)
}
