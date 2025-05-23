// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jcchavezs/mergefs"
	"github.com/jcchavezs/mergefs/io"

	coreruleset "github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3/debuglog"
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

func TestAllowedMetadataTags(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	if err := p.FromString(`
		SecRule ARGS "@rx 123" "id:1,block,log,msg:"Match",tag:'metadatafilter/numeric',phase:2"
		SecRule ARGS "@rx abc" "id:2,block,log,msg:"Match",tag:'metadatafilter/numeric',phase:2"
		SecRule ARGS "@rx a5" "id:3,block,log,msg:"Match",tag:'metadatafilter/boolean',phase:2"
		SecRule ARGS "@rx true" "id:4,block,log,msg:"Match",tag:'metadatafilter/boolean,alphanumeric',phase:2"
		SecRule ARGS "@rx b222" "id:5,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a5" "id:6,block,log,msg:"Match",tag:'metadatafilter/alphanumeric',phase:2"
		SecRule ARGS "@rx a5" "id:7,block,log,msg:"Match",phase:2"
		
	`); err != nil {
		t.Errorf("Could not create from string: %s", err.Error())
	}
	tx := waf.NewTransaction()
	tx.SetMetadataInspection(true)
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.AddPostRequestArgument("p6", "$(a123+b222)")
	tx.AddPostRequestArgument("p7", "b222")
	tx.ProcessURI("http://localhost/test.php?m1=123test&m2=abc123&m3=true&m4=a5&m5=a-b", "GET", "1.1")
	tx.ProcessRequestHeaders()
	interrupt, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if interrupt != nil {
		t.Error("Transaction interrupted")
	}
	matchedRules := tx.MatchedRules()
	if len(matchedRules) != 4 {
		t.Errorf("Expected 4 matched rule, got %d", len(matchedRules))
	}
}

func TestDisabledMetadataTagsInspection(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	if err := p.FromString(`
		SecRule ARGS "@rx 123" "id:1,block,log,msg:"Match",tag:'metadatafilter/numeric',phase:2"
		SecRule ARGS "@rx abc" "id:2,block,log,msg:"Match",tag:'metadatafilter/numeric',phase:2"
		SecRule ARGS "@rx a5" "id:3,block,log,msg:"Match",tag:'metadatafilter/boolean',phase:2"
		SecRule ARGS "@rx true" "id:4,block,log,msg:"Match",tag:'metadatafilter/boolean,alphanumeric',phase:2"
		SecRule ARGS "@rx b222" "id:5,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a5" "id:6,block,log,msg:"Match",tag:'metadatafilter/alphanumeric',phase:2"
		SecRule ARGS "@rx a5" "id:7,block,log,msg:"Match",phase:2"
	`); err != nil {
		t.Errorf("Could not create from string: %s", err.Error())
	}
	tx := waf.NewTransaction()
	tx.SetMetadataInspection(true)
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.AddPostRequestArgument("p6", "$(a123+b222)")
	tx.AddPostRequestArgument("p7", "b222")
	tx.ProcessURI("http://localhost/test.php?m1=123&m2=abc123&m3=true&m4=a5&m5=a-b", "GET", "1.1")
	tx.ProcessRequestHeaders()
	interrupt, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if interrupt != nil {
		t.Error("Transaction interrupted")
	}
	matchedRules := tx.MatchedRules()
	sort.Slice(matchedRules, func(i, j int) bool {
		return matchedRules[i].Rule().ID() < matchedRules[j].Rule().ID()
	})
	if len(matchedRules) != 5 {
		t.Errorf("Expected 4 matched rule, got %d", len(matchedRules))
	}
	if matchedRules[0].Rule().ID() != 1 {
		t.Errorf("Expected matched rule ID 1, got %d", matchedRules[0].Rule().ID())
	}
	if matchedRules[1].Rule().ID() != 4 {
		t.Errorf("Expected matched rule ID 4, got %d", matchedRules[1].Rule().ID())
	}
	if matchedRules[2].Rule().ID() != 5 {
		t.Errorf("Expected matched rule ID 5, got %d", matchedRules[2].Rule().ID())
	}
	if matchedRules[3].Rule().ID() != 6 {
		t.Errorf("Expected matched rule ID 6, got %d", matchedRules[3].Rule().ID())
	}
	if matchedRules[4].Rule().ID() != 7 {
		t.Errorf("Expected matched rule ID 7, got %d", matchedRules[4].Rule().ID())
	}
}

func TestAllowedMetadataTagsInspectionEnabled(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	_ = p.FromString(`
		SecRuleEngine On
		SecRequestBodyAccess On
		SecResponseBodyMimeType text/plain text/html text/xml application/json
		# Enable JSON request body parser.
		SecRule REQUEST_HEADERS:Content-Type "^application/json" \
		"id:'200002',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
		SecRule ARGS "@rx a{100}.*a" "id:50,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*b" "id:51,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*c" "id:52,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*d" "id:54,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*e" "id:60,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*e" "id:61,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*f" "id:62,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*g" "id:63,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
	`)
	body := make(map[string]string)
	for i := 0; i < 100; i++ {
		body[fmt.Sprintf("p%d", i)] = strings.Repeat("a", 1000) + "bcdefghijklmnopqrstuvwxyz"
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction()
	tx.SetMetadataInspection(true)
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.ProcessURI("http://localhost/test.php", "GET", "1.1")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody(jsonBody); err != nil {
		t.Error(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Error(err)
	}
	tx.AddResponseHeader("Content-Type", "application/json")
	tx.ProcessResponseHeaders(200, "OK")
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Error(err)
	}
	tx.ProcessLogging()
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
	matchedRules := tx.MatchedRules()
	if len(matchedRules) != 1 {
		t.Errorf("Expected 1 matched rule, got %d", len(matchedRules))
	}
	tx.Close()
}

func BenchmarkAllowedMetadataTagsInspectionEnabled(b *testing.B) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	_ = p.FromString(`
		SecRuleEngine On
		SecRequestBodyAccess On
		SecResponseBodyMimeType text/plain text/html text/xml application/json
		# Enable JSON request body parser.
		SecRule REQUEST_HEADERS:Content-Type "^application/json" \
		"id:'200002',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
		SecRule ARGS "@rx a{100}.*a" "id:50,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*b" "id:51,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*c" "id:52,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*d" "id:54,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*e" "id:60,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*e" "id:61,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*f" "id:62,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*g" "id:63,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
	`)
	body := make(map[string]string)
	for i := 0; i < 100; i++ {
		body[fmt.Sprintf("p%d", i)] = strings.Repeat("a", 1000) + "bcdefghijklmnopqrstuvwxyz"
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		b.Error(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		tx.SetMetadataInspection(true)
		tx.AddRequestHeader("Content-Type", "application/json")
		tx.ProcessURI("http://localhost/test.php", "GET", "1.1")
		tx.ProcessRequestHeaders()
		if _, _, err := tx.WriteRequestBody(jsonBody); err != nil {
			b.Error(err)
		}
		if _, err := tx.ProcessRequestBody(); err != nil {
			b.Error(err)
		}
		tx.AddResponseHeader("Content-Type", "application/json")
		tx.ProcessResponseHeaders(200, "OK")
		if _, err := tx.ProcessResponseBody(); err != nil {
			b.Error(err)
		}
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			b.Error(err)
		}
		matchedRules := tx.MatchedRules()
		if len(matchedRules) != 1 {
			b.Errorf("Expected 1 matched rule, got %d", len(matchedRules))
		}
		tx.Close()
	}
}

func BenchmarkAllowedMetadataTagsInspectionDisabled(b *testing.B) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	_ = p.FromString(`
		SecRuleEngine On
		SecRequestBodyAccess On
		SecResponseBodyMimeType text/plain text/html text/xml application/json
		# Enable JSON request body parser.
		SecRule REQUEST_HEADERS:Content-Type "^application/json" \
		"id:'200002',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
		SecRule ARGS "@rx a{100}.*a" "id:50,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*b" "id:51,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*c" "id:52,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*d" "id:54,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*e" "id:60,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*e" "id:61,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*f" "id:62,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
		SecRule ARGS "@rx a{100}.*g" "id:63,block,log,msg:"Match",tag:'metadatafilter/not_alphanumeric',phase:2"
	`)
	body := make(map[string]string)
	for i := 0; i < 100; i++ {
		body[fmt.Sprintf("p%d", i)] = strings.Repeat("a", 1000) + "bcdefghijklmnopqrstuvwxyz"
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		b.Error(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		tx.SetMetadataInspection(false)
		tx.AddRequestHeader("Content-Type", "application/json")
		tx.SetMetadataInspection(false)
		tx.ProcessURI("http://localhost/test.php", "GET", "1.1")
		tx.ProcessRequestHeaders()
		if _, _, err := tx.WriteRequestBody(jsonBody); err != nil {
			b.Error(err)
		}
		if _, err := tx.ProcessRequestBody(); err != nil {
			b.Error(err)
		}
		tx.AddResponseHeader("Content-Type", "application/json")
		tx.ProcessResponseHeaders(200, "OK")
		if _, err := tx.ProcessResponseBody(); err != nil {
			b.Error(err)
		}
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			b.Error(err)
		}
		matchedRules := tx.MatchedRules()
		if len(matchedRules) != 9 {
			b.Errorf("Expected 9 matched rule, got %d", len(matchedRules))
		}
		tx.Close()
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

	t.Run("existing recommended file", func(t *testing.T) {
		logsBuf := &bytes.Buffer{}
		p.options.WAF.Logger = debuglog.Default().WithLevel(debuglog.LevelWarn).WithOutput(logsBuf)
		err := p.FromFile("../../coraza.conf-recommended")
		if err != nil {
			t.Errorf("unexpected error: %s", err.Error())
		}
		// The recommended file is expected to have no warnings/error logs
		if logsBuf.Len() > 0 {
			t.Errorf("unexpected warnings logs while parsing recommended file: %s", logsBuf.String())
		}
	})

	t.Run("unexisting file", func(t *testing.T) {
		err := p.FromFile("../doesnotexist.conf")
		if err == nil {
			t.Error("expected not found error")
		}
	})

	t.Run("successful glob", func(t *testing.T) {
		err := p.FromFile("./testdata/glob/*.conf")
		if err != nil {
			t.Errorf("unexpected error: %s", err.Error())
		}
	})

	t.Run("empty glob result", func(t *testing.T) {
		err := p.FromFile("./testdata/glob/*.comf")
		if err != nil {
			t.Errorf("unexpected error despite glob not matching any file")
		}
	})
}

// Connectors are supporting embedding github.com/corazawaf/coraza-coreruleset to ease CRS integration
// mergefs.Merge is used to combine both CRS and local files. This test is to ensure that the parser
// is able to load configuration files from both filesystems.
func TestLoadConfigurationFileWithMultiFs(t *testing.T) {
	waf := coraza.NewWAF()
	p := NewParser(waf)
	p.SetRoot(mergefs.Merge(coreruleset.FS, io.OSFS))

	err := p.FromFile("../../coraza.conf-recommended")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	err = p.FromFile("../doesnotexist.conf")
	// Go and TinyGo have different error messages
	if !strings.Contains(err.Error(), "no such file or directory") && !strings.Contains(err.Error(), "file does not exist") {
		t.Errorf("expected not found error. Got: %s", err.Error())
	}

	err = p.FromFile("/tmp/doesnotexist.conf")
	if !strings.Contains(err.Error(), "no such file or directory") && !strings.Contains(err.Error(), "file does not exist") {
		t.Errorf("expected not found error. Got: %s", err.Error())
	}

	err = p.FromFile("./testdata/glob/*.conf")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	if err := p.FromString("Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf"); err != nil {
		t.Error(err)
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
	err = tmpFile2.Close()
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
