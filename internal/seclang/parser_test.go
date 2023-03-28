// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"bufio"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	coraza "github.com/corazawaf/coraza/v3/internal/corazawaf"
)

//go:embed testdata
var testdata embed.FS

func TestInterruption(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	if err := p.FromString(`SecAction "id:1,deny,log,phase:1"`); err != nil {
		t.Errorf("Could not create from string: %s", err.Error())
	}
	tx := waf.NewTransaction()
	if tx.ProcessRequestHeaders() == nil {
		t.Error("Transaction not interrupted")
	}
}

func TestDirectivesCaseInsensitive(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	err := p.FromString("seCwEbAppid 15")
	if err != nil {
		t.Error(err)
	}
}

func TestInvalidDirective(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	err := p.FromString("Unknown Rule")
	if err == nil {
		t.Error("expected error")
	}

	err = p.FromString("SecEngineRule")
	if err == nil {
		t.Error("expected error")
	}
}

func TestCommentsWithBackticks(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	tCases := map[string]string{
		"two backticks in comment": "# This comment has a trailing backtick `here`" + `
		SecAction "id:1,deny,log,phase:1"
		`,
		"one backtick in comment": "# The rule 942510 is related to 942110 which catches a single ' or `",
	}
	for name, s := range tCases {
		t.Run(name, func(t *testing.T) {
			err := p.FromString(s)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestErrorWithBackticks(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	err := p.FromString("SecDataset test `")
	if err == nil {
		t.Error(err)
	}
}

func TestLoadConfigurationFile(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	err := p.FromFile("../../coraza.conf-recommended")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	err = p.FromFile("../doesnotexist.conf")
	if err == nil {
		t.Error("expected not found error")
	}

	err = p.FromFile("./testdata/glob/*.conf")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestHardcodedIncludeDirective(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	if err := p.FromString("Include ../../coraza.conf-recommended"); err != nil {
		t.Error(err)
	}
	if waf.Rules.Count() == 0 {
		t.Error("No rules loaded using include directive")
	}
	if err := p.FromString("Include unknown"); err == nil {
		t.Error("Include directive should fail")
	}
}

func TestHardcodedSubIncludeDirective(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	if err := p.FromString("Include ./testdata/includes/parent.conf"); err != nil {
		t.Error(err)
	}
	if waf.Rules.Count() != 4 {
		t.Error("Expected 4 rules loaded using include directive. Found: ", waf.Rules.Count())
	}
}

func TestHardcodedSubIncludeDirectiveAbsolutePath(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	currentDir, _ := filepath.Abs("./")
	ruleFile := filepath.Join(currentDir, "./testdata/includes/parent.conf")
	if err := p.FromString("Include " + ruleFile); err != nil {
		t.Error(err)
	}
	if waf.Rules.Count() != 4 {
		t.Error("Expected 4 rules loaded using include directive. Found: ", waf.Rules.Count())
	}
}

func TestHardcodedIncludeDirectiveDDOS(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	tmpFile, err := os.Create(filepath.Join(t.TempDir(), "rand.conf"))
	if err != nil {
		t.Fatal(err)
	}
	data := fmt.Sprintf("Include %s\n", tmpFile.Name())
	// write data to tmpFile
	w := bufio.NewWriter(tmpFile)
	if _, err := w.WriteString(data); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	tmpFile.Close()
	if err := p.FromFile(tmpFile.Name()); err == nil {
		t.Error("Include directive should fail in case of recursion")
	}
}

func TestHardcodedIncludeDirectiveDDOS2(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	tmpFile, err := os.Create(filepath.Join(t.TempDir(), "rand1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	tmpFile2, err := os.Create(filepath.Join(t.TempDir(), "rand2.conf"))
	if err != nil {
		t.Fatal(err)
	}

	w := bufio.NewWriter(tmpFile)
	for i := 0; i < maxIncludeRecursion+1; i++ {
		data := fmt.Sprintf("Include %s\n", tmpFile2.Name())
		if _, err := w.WriteString(data); err != nil {
			t.Fatal(err)
		}
	}
	w.Flush()
	tmpFile.Close()
	if err := p.FromFile(tmpFile.Name()); err == nil {
		t.Error("Include directive should fail in case of a lot of recursion")
	}
}

func TestChains(t *testing.T) {
	/*
		waf := coraza.NewWAF()
		p, _ := NewParser(waf)
		if err := p.FromString(`
		SecAction "id:1,deny,log,phase:1,chain"
		SecRule ARGS "chain"
		SecRule REQUEST_HEADERS ""
		`); err != nil {
			t.Error("Could not create from string")
		}
		rules := waf.Rules.GetRules()
		if len(rules) != 1 || rules[0].Chain == nil {
			t.Errorf("Chain not created %v", rules[0])
			return
		}
			if rules[0].Chain.Chain == nil {
				t.Error("Chain over chain not created")
			}*/
}

func TestEmbedFS(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	root, err := fs.Sub(testdata, "testdata")
	if err != nil {
		t.Error(err)
	}
	p.SetRoot(root)
	if err := p.FromString("Include includes/parent.conf"); err != nil {
		t.Error(err)
	}
	if waf.Rules.Count() != 4 {
		t.Error("Expected 4 rules loaded using include directive. Found: ", waf.Rules.Count())
	}
}

//go:embed testdata/parserbenchmark.conf
var parsingRule string

func BenchmarkParseFromString(b *testing.B) {
	waf := coraza.NewWAF()
	parser := NewParser(waf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parser.FromString(parsingRule)
	}
}
