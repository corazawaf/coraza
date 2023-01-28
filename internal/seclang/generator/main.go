// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	_ "embed"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"html/template"
	"log"
	"os"
	"strings"
)

//go:embed directivesmap.go.tmpl
var directivesMapTmpl string

type DirectivesMap struct {
	Key    string
	FnName string
}

func main() {
	tmpl, err := template.New("directivesmap").Parse(directivesMapTmpl)
	if err != nil {
		log.Fatal(err)
	}

	fset := token.NewFileSet()

	src, err := os.ReadFile("./directives.go")
	if err != nil {
		log.Fatal(err)
	}

	f, err := parser.ParseFile(fset, "directives.go", src, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}

	dm, err := os.Create("./directivesmap.gen.go")
	if err != nil {
		log.Fatal(err)
	}

	directives := []DirectivesMap{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch fn := n.(type) {
		// catching all function declarations
		case *ast.FuncDecl:
			fnName := fn.Name.String()
			if !strings.HasPrefix(fnName, "directive") {
				return true
			}

			directiveName := fnName[9:]

			if directiveName == "Include" || directiveName == "Unsupported" {
				return true
			}

			directives = append(directives, DirectivesMap{
				Key:    strings.ToLower(directiveName),
				FnName: fnName,
			})
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

	_, err = dm.Write(fdmc)
	if err != nil {
		log.Fatal(err)
	}

	err = dm.Close()
	if err != nil {
		log.Fatal(err)
	}
}
