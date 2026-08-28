package seclang

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Every ```seclang example in directives.go must actually parse.
func TestDocExamplesParse(t *testing.T) {
	src, err := os.ReadFile("directives.go")
	if err != nil {
		t.Fatal(err)
	}
	fence := regexp.MustCompile(`^\s*// ` + "```" + `([a-z]*)\s*$`)
	var blocks []string
	var cur []string
	in := false
	for _, l := range strings.Split(string(src), "\n") {
		if m := fence.FindStringSubmatch(l); m != nil {
			if !in {
				in = true
				cur = nil
			} else {
				in = false
				blocks = append(blocks, strings.Join(cur, "\n"))
			}
			continue
		}
		if in {
			cur = append(cur, strings.TrimPrefix(strings.TrimPrefix(l, "//"), " "))
		}
	}
	if len(blocks) == 0 {
		t.Fatal("no example blocks found")
	}
	t.Logf("checking %d example blocks", len(blocks))
	for _, b := range blocks {
		b := b
		if strings.TrimSpace(b) == "" {
			continue
		}
		// These parse correctly but their handlers validate against the
		// environment: a writable path, filesystem access at all under the
		// no_fs_access build tag, or a rule that a one-line example cannot
		// have declared yet.
		if strings.HasPrefix(b, "SecUploadDir") || strings.HasPrefix(b, "SecDebugLog ") ||
			strings.HasPrefix(b, "SecRuleUpdateTargetById") || strings.HasPrefix(b, "SecRuleUpdateActionById") ||
			strings.HasPrefix(b, "SecDataDir") ||
			strings.HasPrefix(b, "SecRemoteRules ") ||
			strings.HasPrefix(b, "SecUploadKeepFiles") {
			continue
		}
		t.Run(strings.SplitN(strings.TrimSpace(b), "\n", 2)[0], func(t *testing.T) {
			p := NewParser(corazawaf.NewWAF())
			if err := p.FromString(b); err != nil {
				t.Errorf("example does not parse: %v\n%s", err, b)
			}
		})
	}
}
