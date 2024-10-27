package main

import (
	"embed"

	"github.com/corazawaf/coraza/v3/experimental/seclang"
	"github.com/davecgh/go-spew/spew"
)

//go:embed rules/*.conf
var rulesDir embed.FS

func main() {
	p := seclang.NewParser(seclang.NewParserConfig().WithRoot(rulesDir))
	err := p.FromFile("rules/incorrect.conf")
	spew.Dump(err)
}
