// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/corazawaf/coraza/v3"
	engine "github.com/corazawaf/coraza/v3"
)

func TestInterruption(t *testing.T) {
	waf := engine.NewWaf()
	p, _ := NewParser(waf)
	if err := p.FromString(`SecAction "id:1,deny,log,phase:1"`); err != nil {
		t.Error("Could not create from string")
	}
	tx := waf.NewTransaction(context.Background())
	if tx.ProcessRequestHeaders() == nil {
		t.Error("Transaction not interrupted")
	}
}

func TestDirectivesCaseInsensitive(t *testing.T) {
	waf := engine.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromString("seCwEbAppid 15")
	if err != nil {
		t.Error(err)
	}
}

func TestDefaultConfigurationFile(t *testing.T) {
	waf := engine.NewWaf()
	p, _ := NewParser(waf)
	err := p.FromFile("../coraza.conf-recommended")
	if err != nil {
		t.Error(err)
	}
}

func TestHardcodedIncludeDirective(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	if err := p.FromString("Include ../coraza.conf-recommended"); err != nil {
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
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	if err := p.FromString("Include ./testdata/includes/parent.conf"); err != nil {
		t.Error(err)
	}
	if waf.Rules.Count() != 3 {
		t.Error("Expected 3 rules loaded using include directive. Found: ", waf.Rules.Count())
	}
}

func TestHardcodedSubIncludeDirectiveAbsolutePath(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
	currentDir, _ := filepath.Abs("./")
	ruleFile := filepath.Join(currentDir, "./testdata/includes/parent.conf")
	if err := p.FromString("Include " + ruleFile); err != nil {
		t.Error(err)
	}
	if waf.Rules.Count() != 3 {
		t.Error("Expected 3 rules loaded using include directive. Found: ", waf.Rules.Count())
	}
}

func TestHardcodedIncludeDirectiveDDOS(t *testing.T) {
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
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
	waf := coraza.NewWaf()
	p, _ := NewParser(waf)
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
		waf := engine.NewWaf()
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
