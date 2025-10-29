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

func TestSelect(t *testing.T) {
	tests := []struct {
		name          string
		rule          string
		expectedError bool
	}{
		{
			name:          "ARGS",
			rule:          `SecRule ARGS:foo "bar" "id:1"`,
			expectedError: false,
		},
		{
			name:          "ARGS_COMBINED_SIZE",
			rule:          `SecRule ARGS_COMBINED_SIZE:foo "bar" "id:1"`,
			expectedError: true,
		},
		{
			name:          "ARGS_GET",
			rule:          `SecRule ARGS_GET:foo "bar" "id:2"`,
			expectedError: false,
		},
		{
			name:          "ARGS_GET_NAMES",
			rule:          `SecRule ARGS_GET_NAMES:foo "bar" "id:3"`,
			expectedError: false,
		},
		{
			name:          "ARGS_NAMES",
			rule:          `SecRule ARGS_NAMES:foo "bar" "id:4"`,
			expectedError: false,
		},
		{
			name:          "ARGS_PATH",
			rule:          `SecRule ARGS_PATH:foo "bar" "id:5"`,
			expectedError: false,
		},
		{
			name:          "ARGS_POST",
			rule:          `SecRule ARGS_POST:foo "bar" "id:6"`,
			expectedError: false,
		},
		{
			name:          "ARGS_POST_NAMES",
			rule:          `SecRule ARGS_POST_NAMES:foo "bar" "id:7"`,
			expectedError: false,
		},
		{
			name:          "AUTH_TYPE",
			rule:          `SecRule AUTH_TYPE:foo "bar" "id:8"`,
			expectedError: true,
		},
		{
			name:          "DURATION",
			rule:          `SecRule DURATION:foo "bar" "id:9"`,
			expectedError: true,
		},
		{
			name:          "ENV",
			rule:          `SecRule ENV:foo "bar" "id:10"`,
			expectedError: false,
		},
		{
			name:          "FILES",
			rule:          `SecRule FILES:foo "bar" "id:11"`,
			expectedError: false,
		},
		{
			name:          "FILES_COMBINED_SIZE",
			rule:          `SecRule FILES_COMBINED_SIZE:foo "bar" "id:12"`,
			expectedError: true,
		},
		{
			name:          "FILES_NAMES",
			rule:          `SecRule FILES_NAMES:foo "bar" "id:13"`,
			expectedError: false,
		},
		{
			name:          "FILES_SIZES",
			rule:          `SecRule FILES_SIZES:foo "bar" "id:14"`,
			expectedError: false,
		},
		{
			name:          "FILES_TMPNAMES",
			rule:          `SecRule FILES_TMPNAMES:foo "bar" "id:15"`,
			expectedError: false,
		},
		{
			name:          "FILES_TMP_CONTENT",
			rule:          `SecRule FILES_TMP_CONTENT:foo "bar" "id:16"`,
			expectedError: false,
		},
		{
			name:          "FULL_REQUEST",
			rule:          `SecRule FULL_REQUEST:foo "bar" "id:17"`,
			expectedError: true,
		},
		{
			name:          "FULL_REQUEST_LENGTH",
			rule:          `SecRule FULL_REQUEST_LENGTH:foo "bar" "id:18"`,
			expectedError: true,
		},
		{
			name:          "GEO",
			rule:          `SecRule GEO:foo "bar" "id:19"`,
			expectedError: false,
		},
		{
			name:          "HIGHEST_SEVERITY",
			rule:          `SecRule HIGHEST_SEVERITY:foo "bar" "id:20"`,
			expectedError: true,
		},
		{
			name:          "INBOUND_DATA_ERROR",
			rule:          `SecRule INBOUND_DATA_ERROR:foo "bar" "id:21"`,
			expectedError: true,
		},
		{
			name:          "IP",
			rule:          `SecRule IP:foo "bar" "id:22"`,
			expectedError: true,
		},
		{
			name:          "JSON",
			rule:          `SecRule JSON:foo "bar" "id:23"`,
			expectedError: false,
		},
		{
			name:          "MATCHED_VAR",
			rule:          `SecRule MATCHED_VAR:foo "bar" "id:24"`,
			expectedError: true,
		},
		{
			name:          "MATCHED_VARS",
			rule:          `SecRule MATCHED_VARS:foo "bar" "id:25"`,
			expectedError: false,
		},
		{
			name:          "MATCHED_VARS_NAMES",
			rule:          `SecRule MATCHED_VARS_NAMES:foo "bar" "id:26"`,
			expectedError: false,
		},
		{
			name:          "MATCHED_VAR_NAME",
			rule:          `SecRule MATCHED_VAR_NAME:foo "bar" "id:27"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_BOUNDARY_QUOTED",
			rule:          `SecRule MULTIPART_BOUNDARY_QUOTED:foo "bar" "id:28"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_BOUNDARY_WHITESPACE",
			rule:          `SecRule MULTIPART_BOUNDARY_WHITESPACE:foo "bar" "id:29"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_CRLF_LF_LINES",
			rule:          `SecRule MULTIPART_CRLF_LF_LINES:foo "bar" "id:30"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_DATA_AFTER",
			rule:          `SecRule MULTIPART_DATA_AFTER:foo "bar" "id:31"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_DATA_BEFORE",
			rule:          `SecRule MULTIPART_DATA_BEFORE:foo "bar" "id:32"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_FILENAME",
			rule:          `SecRule MULTIPART_FILENAME:foo "bar" "id:33"`,
			expectedError: false,
		},
		{
			name:          "MULTIPART_FILE_LIMIT_EXCEEDED",
			rule:          `SecRule MULTIPART_FILE_LIMIT_EXCEEDED:foo "bar" "id:34"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_HEADER_FOLDING",
			rule:          `SecRule MULTIPART_HEADER_FOLDING:foo "bar" "id:35"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_INVALID_HEADER_FOLDING",
			rule:          `SecRule MULTIPART_INVALID_HEADER_FOLDING:foo "bar" "id:36"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_INVALID_PART",
			rule:          `SecRule MULTIPART_INVALID_PART:foo "bar" "id:37"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_INVALID_QUOTING",
			rule:          `SecRule MULTIPART_INVALID_QUOTING:foo "bar" "id:38"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_LF_LINE",
			rule:          `SecRule MULTIPART_LF_LINE:foo "bar" "id:39"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_MISSING_SEMICOLON",
			rule:          `SecRule MULTIPART_MISSING_SEMICOLON:foo "bar" "id:40"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_NAME",
			rule:          `SecRule MULTIPART_NAME:foo "bar" "id:41"`,
			expectedError: false,
		},
		{
			name:          "MULTIPART_PART_HEADERS",
			rule:          `SecRule MULTIPART_PART_HEADERS:foo "bar" "id:42"`,
			expectedError: false,
		},
		{
			name:          "MULTIPART_STRICT_ERROR",
			rule:          `SecRule MULTIPART_STRICT_ERROR:foo "bar" "id:43"`,
			expectedError: true,
		},
		{
			name:          "MULTIPART_UNMATCHED_BOUNDARY",
			rule:          `SecRule MULTIPART_UNMATCHED_BOUNDARY:foo "bar" "id:44"`,
			expectedError: true,
		},
		{
			name:          "OUTBOUND_DATA_ERROR",
			rule:          `SecRule OUTBOUND_DATA_ERROR:foo "bar" "id:45"`,
			expectedError: true,
		},
		{
			name:          "PATH_INFO",
			rule:          `SecRule PATH_INFO:foo "bar" "id:46"`,
			expectedError: true,
		},
		{
			name:          "QUERY_STRING",
			rule:          `SecRule QUERY_STRING:foo "bar" "id:47"`,
			expectedError: true,
		},
		{
			name:          "REMOTE_ADDR",
			rule:          `SecRule REMOTE_ADDR:foo "bar" "id:48"`,
			expectedError: true,
		},
		{
			name:          "REMOTE_HOST",
			rule:          `SecRule REMOTE_HOST:foo "bar" "id:49"`,
			expectedError: true,
		},
		{
			name:          "REMOTE_PORT",
			rule:          `SecRule REMOTE_PORT:foo "bar" "id:50"`,
			expectedError: true,
		},
		{
			name:          "REQBODY_ERROR",
			rule:          `SecRule REQBODY_ERROR:foo "bar" "id:51"`,
			expectedError: true,
		},
		{
			name:          "REQBODY_ERROR_MSG",
			rule:          `SecRule REQBODY_ERROR_MSG:foo "bar" "id:52"`,
			expectedError: true,
		},
		{
			name:          "REQBODY_PROCESSOR",
			rule:          `SecRule REQBODY_PROCESSOR:foo "bar" "id:53"`,
			expectedError: true,
		},
		{
			name:          "REQBODY_PROCESSOR_ERROR",
			rule:          `SecRule REQBODY_PROCESSOR_ERROR:foo "bar" "id:54"`,
			expectedError: true,
		},
		{
			name:          "REQBODY_PROCESSOR_ERROR_MSG",
			rule:          `SecRule REQBODY_PROCESSOR_ERROR_MSG:foo "bar" "id:55"`,
			expectedError: true,
		},
		{
			name:          "REQUEST_BASENAME",
			rule:          `SecRule REQUEST_BASENAME:foo "bar" "id:56"`,
			expectedError: true,
		},
		{
			name:          "REQUEST_BODY",
			rule:          `SecRule REQUEST_BODY:foo "bar" "id:57"`,
			expectedError: true,
		},
		{
			name:          "REQUEST_BODY_LENGTH",
			rule:          `SecRule REQUEST_BODY_LENGTH:foo "bar" "id:58"`,
			expectedError: true,
		},
		{
			name:          "REQUEST_COOKIES",
			rule:          `SecRule REQUEST_COOKIES:foo "bar" "id:59"`,
			expectedError: false,
		},
		{
			name:          "REQUEST_COOKIES_NAMES",
			rule:          `SecRule REQUEST_COOKIES_NAMES:foo "bar" "id:60"`,
			expectedError: false,
		},
		{
			name:          "REQUEST_FILENAME",
			rule:          `SecRule REQUEST_FILENAME:foo "bar" "id:61"`,
			expectedError: true,
		},
		{
			name:          "REQUEST_HEADERS",
			rule:          `SecRule REQUEST_HEADERS:foo "bar" "id:62"`,
			expectedError: false,
		},
		{
			name:          "REQUEST_HEADERS_NAMES",
			rule:          `SecRule REQUEST_HEADERS_NAMES:foo "bar" "id:63"`,
			expectedError: false,
		},
		{
			name:          "REQUEST_LINE",
			rule:          `SecRule REQUEST_LINE:foo "bar" "id:64"`,
			expectedError: true,
		},
		{
			name:          "REQUEST_METHOD",
			rule:          `SecRule REQUEST_METHOD:foo "bar" "id:65"`,
			expectedError: true,
		},
		{
			name:          "REQUEST_PROTOCOL",
			rule:          `SecRule REQUEST_PROTOCOL:foo "bar" "id:66"`,
			expectedError: true,
		},
		{
			name:          "REQUEST_URI",
			rule:          `SecRule REQUEST_URI:foo "bar" "id:67"`,
			expectedError: true,
		},
		{
			name:          "REQUEST_URI_RAW",
			rule:          `SecRule REQUEST_URI_RAW:foo "bar" "id:68"`,
			expectedError: true,
		},
		{
			name:          "REQUEST_XML",
			rule:          `SecRule REQUEST_XML:foo "bar" "id:69"`,
			expectedError: false,
		},
		{
			name:          "RESPONSE_ARGS",
			rule:          `SecRule RESPONSE_ARGS:foo "bar" "id:70"`,
			expectedError: false,
		},
		{
			name:          "RESPONSE_BODY",
			rule:          `SecRule RESPONSE_BODY:foo "bar" "id:71"`,
			expectedError: true,
		},
		{
			name:          "RESPONSE_CONTENT_LENGTH",
			rule:          `SecRule RESPONSE_CONTENT_LENGTH:foo "bar" "id:72"`,
			expectedError: true,
		},
		{
			name:          "RESPONSE_CONTENT_TYPE",
			rule:          `SecRule RESPONSE_CONTENT_TYPE:foo "bar" "id:73"`,
			expectedError: true,
		},
		{
			name:          "RESPONSE_HEADERS",
			rule:          `SecRule RESPONSE_HEADERS:foo "bar" "id:74"`,
			expectedError: false,
		},
		{
			name:          "RESPONSE_HEADERS_NAMES",
			rule:          `SecRule RESPONSE_HEADERS_NAMES:foo "bar" "id:75"`,
			expectedError: false,
		},
		{
			name:          "RESPONSE_PROTOCOL",
			rule:          `SecRule RESPONSE_PROTOCOL:foo "bar" "id:76"`,
			expectedError: true,
		},
		{
			name:          "RESPONSE_STATUS",
			rule:          `SecRule RESPONSE_STATUS:foo "bar" "id:77"`,
			expectedError: true,
		},
		{
			name:          "RESPONSE_XML",
			rule:          `SecRule RESPONSE_XML:foo "bar" "id:78"`,
			expectedError: false,
		},
		{
			name:          "RES_BODY_ERROR",
			rule:          `SecRule RES_BODY_ERROR:foo "bar" "id:79"`,
			expectedError: true,
		},
		{
			name:          "RES_BODY_ERROR_MSG",
			rule:          `SecRule RES_BODY_ERROR_MSG:foo "bar" "id:80"`,
			expectedError: true,
		},
		{
			name:          "RES_BODY_PROCESSOR",
			rule:          `SecRule RES_BODY_PROCESSOR:foo "bar" "id:81"`,
			expectedError: true,
		},
		{
			name:          "RES_BODY_PROCESSOR_ERROR",
			rule:          `SecRule RES_BODY_PROCESSOR_ERROR:foo "bar" "id:82"`,
			expectedError: true,
		},
		{
			name:          "RES_BODY_PROCESSOR_ERROR_MSG",
			rule:          `SecRule RES_BODY_PROCESSOR_ERROR_MSG:foo "bar" "id:83"`,
			expectedError: true,
		},
		{
			name:          "RULE",
			rule:          `SecRule RULE:foo "bar" "id:84"`,
			expectedError: false,
		},
		{
			name:          "SERVER_ADDR",
			rule:          `SecRule SERVER_ADDR:foo "bar" "id:85"`,
			expectedError: true,
		},
		{
			name:          "SERVER_NAME",
			rule:          `SecRule SERVER_NAME:foo "bar" "id:86"`,
			expectedError: true,
		},
		{
			name:          "SERVER_PORT",
			rule:          `SecRule SERVER_PORT:foo "bar" "id:87"`,
			expectedError: true,
		},
		{
			name:          "SESSIONID",
			rule:          `SecRule SESSIONID:foo "bar" "id:88"`,
			expectedError: true,
		},
		{
			name:          "STATUS_LINE",
			rule:          `SecRule STATUS_LINE:foo "bar" "id:89"`,
			expectedError: true,
		},
		{
			name:          "TIME",
			rule:          `SecRule TIME:foo "bar" "id:90"`,
			expectedError: true,
		},
		{
			name:          "TIME_DAY",
			rule:          `SecRule TIME_DAY:foo "bar" "id:91"`,
			expectedError: true,
		},
		{
			name:          "TIME_EPOCH",
			rule:          `SecRule TIME_EPOCH:foo "bar" "id:92"`,
			expectedError: true,
		},
		{
			name:          "TIME_HOUR",
			rule:          `SecRule TIME_HOUR:foo "bar" "id:93"`,
			expectedError: true,
		},
		{
			name:          "TIME_MIN",
			rule:          `SecRule TIME_MIN:foo "bar" "id:94"`,
			expectedError: true,
		},
		{
			name:          "TIME_MON",
			rule:          `SecRule TIME_MON:foo "bar" "id:95"`,
			expectedError: true,
		},
		{
			name:          "TIME_SEC",
			rule:          `SecRule TIME_SEC:foo "bar" "id:96"`,
			expectedError: true,
		},
		{
			name:          "TIME_WDAY",
			rule:          `SecRule TIME_WDAY:foo "bar" "id:97"`,
			expectedError: true,
		},
		{
			name:          "TIME_YEAR",
			rule:          `SecRule TIME_YEAR:foo "bar" "id:98"`,
			expectedError: true,
		},
		{
			name:          "TX",
			rule:          `SecRule TX:foo "bar" "id:99"`,
			expectedError: false,
		},
		{
			name:          "UNIQUE_ID",
			rule:          `SecRule UNIQUE_ID:foo "bar" "id:100"`,
			expectedError: true,
		},
		{
			name:          "UNKNOWN",
			rule:          `SecRule UNKNOWN:foo "bar" "id:101"`,
			expectedError: true,
		},
		{
			name:          "URLENCODED_ERROR",
			rule:          `SecRule URLENCODED_ERROR:foo "bar" "id:102"`,
			expectedError: true,
		},
		{
			name:          "USERID",
			rule:          `SecRule USERID:foo "bar" "id:103"`,
			expectedError: true,
		},
		{
			name:          "XML",
			rule:          `SecRule XML:foo "bar" "id:104"`,
			expectedError: false,
		},
	}

	waf := coraza.NewWAF()
	p := NewParser(waf)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.FromString(tt.rule)
			if (err != nil) != tt.expectedError {
				t.Errorf("FromString() error = %v, expectedError %v", err, tt.expectedError)
			}
		})
	}
}
