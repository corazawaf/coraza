package main

import (
	"bytes"
	_ "embed"
	"go/format"
	"html/template"
	"log"
	"os"
	"strings"
)

//go:embed logger.go.tmpl
var loggersTmpl string

var loggersMap = []struct {
	Name     string
	LogLevel int
}{
	{
		Name:     "Error",
		LogLevel: 1,
	},
	{
		Name:     "Warn",
		LogLevel: 2,
	},
	{
		Name:     "Info",
		LogLevel: 3,
	},
	{
		Name:     "Debug",
		LogLevel: 4,
	},
	{
		Name:     "Trace",
		LogLevel: 5,
	},
}

var funcMap = template.FuncMap{
	"ToUpper": strings.ToUpper,
	"FirstLetter": func(s string) string {
		if len(s) > 0 {
			return strings.ToLower(string(s[0]))
		}
		return ""
	},
}

func main() {
	tmpl, err := template.New("loggers").Funcs(funcMap).Parse(loggersTmpl)
	if err != nil {
		log.Fatal(err)
	}

	l, err := os.Create("./internal/logger/loggers.gen.go")
	if err != nil {
		log.Fatal(err)
	}

	dmc := bytes.Buffer{}
	err = tmpl.Execute(&dmc, loggersMap)
	if err != nil {
		log.Fatal(err)
	}

	fdmc, err := format.Source(dmc.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	_, err = l.Write(fdmc)
	if err != nil {
		log.Fatal(err)
	}

	err = l.Close()
	if err != nil {
		log.Fatal(err)
	}
}
