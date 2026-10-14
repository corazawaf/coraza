// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

// rxprefilter_gen_test.go: a property test for the @rx prefilter. For a set of
// patterns it generates inputs from the pattern's own syntax tree, so that most
// of them are strings the regular expression matches, and requires the operator
// with the prefilter to give the same answer as the operator without it. A
// wrong prefilter rejects exactly such inputs, which is a missed attack.

package operators

import (
	"math/rand"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// regexGen writes strings that a regular expression is likely to match.
type regexGen struct {
	rnd *rand.Rand
	sb  strings.Builder
}

const regexGenMaxLen = 3000

func newRegexGen(seed int64) *regexGen {
	return &regexGen{rnd: rand.New(rand.NewSource(seed))} //nolint:gosec // reproducible test input, not security
}

func (g *regexGen) class(re *syntax.Regexp) {
	rs := re.Rune
	// Prefer printable ASCII ranges of the class, sometimes take any.
	type rng struct{ lo, hi rune }
	var all, ascii []rng
	for i := 0; i+1 < len(rs); i += 2 {
		r := rng{rs[i], rs[i+1]}
		all = append(all, r)
		lo, hi := max(r.lo, 0x20), min(r.hi, 0x7e)
		if lo <= hi {
			ascii = append(ascii, rng{lo, hi})
		}
	}
	pool := all
	if len(ascii) > 0 && g.rnd.Intn(100) < 85 {
		pool = ascii
	}
	if len(pool) == 0 {
		return
	}
	r := pool[g.rnd.Intn(len(pool))]
	g.sb.WriteRune(r.lo + rune(g.rnd.Int63n(int64(r.hi-r.lo)+1)))
}

func (g *regexGen) gen(re *syntax.Regexp) {
	if g.sb.Len() > regexGenMaxLen {
		return
	}
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 && g.rnd.Intn(2) == 0 {
				// Walk the case-folding orbit a random number of steps.
				for n := g.rnd.Intn(3); n > 0; n-- {
					r = unicode.SimpleFold(r)
				}
			}
			g.sb.WriteRune(r)
		}
	case syntax.OpCharClass:
		g.class(re)
	case syntax.OpAnyCharNotNL:
		g.sb.WriteByte(byte(0x20 + g.rnd.Intn(0x5f)))
	case syntax.OpAnyChar:
		if g.rnd.Intn(20) == 0 {
			g.sb.WriteByte('\n')
		} else {
			g.sb.WriteByte(byte(0x20 + g.rnd.Intn(0x5f)))
		}
	case syntax.OpCapture:
		g.gen(re.Sub[0])
	case syntax.OpStar:
		g.repeat(re.Sub[0], g.rnd.Intn(3))
	case syntax.OpPlus:
		g.repeat(re.Sub[0], 1+g.rnd.Intn(3))
	case syntax.OpQuest:
		g.repeat(re.Sub[0], g.rnd.Intn(2))
	case syntax.OpRepeat:
		hi := re.Max
		if hi < 0 || hi > re.Min+3 {
			hi = re.Min + 3
		}
		g.repeat(re.Sub[0], re.Min+g.rnd.Intn(hi-re.Min+1))
	case syntax.OpConcat:
		for _, s := range re.Sub {
			g.gen(s)
		}
	case syntax.OpAlternate:
		g.gen(re.Sub[g.rnd.Intn(len(re.Sub))])
	default:
		// Empty match and the zero-width assertions write nothing; OpNoMatch cannot
		// be generated, and an input the regex rejects is still a fair input.
	}
}

func (g *regexGen) repeat(re *syntax.Regexp, n int) {
	for i := 0; i < n && g.sb.Len() <= regexGenMaxLen; i++ {
		g.gen(re)
	}
}

// regexGenVariants returns s in the shapes a request value takes: on its own,
// embedded in other text, with a newline around it, in other cases and padded.
func regexGenVariants(s string) []string {
	return []string{
		s,
		"xx " + s + " yy",
		s + "\n",
		"\n" + s,
		strings.ToUpper(s),
		strings.ToLower(s),
		strings.Repeat("a", 64) + s + strings.Repeat("a", 64),
	}
}

// prefilterDisagreement compares the @rx operator with and without the prefilter
// on inputs generated from pattern. It returns how many inputs the regular
// expression matched, how many were compared, and the first input on which the
// two operators differ ("" if none).
func prefilterDisagreement(pattern string, samples int, tx plugintypes.TransactionState) (matched, compared, disagreements int, first string, err error) {
	off, err := newRX(plugintypes.OperatorOptions{Arguments: pattern, RxPreFilterEnabled: false})
	if err != nil {
		return 0, 0, 0, "", err
	}
	on, err := newRX(plugintypes.OperatorOptions{Arguments: pattern, RxPreFilterEnabled: true})
	if err != nil {
		return 0, 0, 0, "", err
	}

	// The tree is generated from the same expression newRX compiles.
	data := "(?s)" + pattern
	if !shouldNotUseMultilineRegexesOperatorByDefault {
		data = "(?sm)" + pattern
	}
	parsed, err := syntax.Parse(data, syntax.Perl)
	if err != nil {
		return 0, 0, 0, "", err
	}
	// A fixed seed per pattern keeps a failure reproducible.
	g := newRegexGen(int64(len(pattern))*7919 + int64(pattern[0]))
	for i := 0; i < samples; i++ {
		g.sb.Reset()
		g.gen(parsed)
		for _, v := range regexGenVariants(g.sb.String()) {
			want := off.Evaluate(tx, v)
			got := on.Evaluate(tx, v)
			compared++
			if want {
				matched++
			}
			if got != want {
				if disagreements == 0 {
					first = v
				}
				disagreements++
			}
		}
	}
	return matched, compared, disagreements, first, nil
}

// TestPrefilterAgreesWithRegexOnGeneratedInputs: the prefilter may only ever
// skip the regular expression for an input it cannot match.
func TestPrefilterAgreesWithRegexOnGeneratedInputs(t *testing.T) {
	patterns := []string{
		// Entities as the XSS rules of the Imunify360 ruleset write them: the
		// parser factors the common "&" and "#", leaving a star in front of a
		// literal inside a trie branch.
		`(?:&#0*60;|&#x0*3c;|&lt;|&amp;#0*60;|&amp;#x0*3c;|&amp;lt;)(?:script|img|svg|javascript:)`,
		`(?i)(?:&#0*60;|&#x0*3c;|&lt;|&amp;#0*60;|&amp;#x0*3c;|&amp;lt;)(?:(?:script|img|svg)[\s/>=\x00-\x20&"']|[a-z][a-z0-9-]{0,30}[\s/][^>]{0,300}\bon(?:error|load)\s*=|javascript:)`,
		`&#0*60;|&#x0*3c;`,

		// A suffix in a trie branch that is not at the branch's start.
		`s(?:x*elect|leep)`,
		`s(?:e+lect|leep)`,
		`a(?:b?cd|ef)`,
		`a(?:b.*cde|fg)`,
		`a(?:x*bcd(?:ef|gh)|y)`,
		`a(?:x*(?:bcd|efg)|yz)`,
		`(?i)s(?:elect.*into|ubstr)`,
		`s(?:elect.*from|leep)`,

		// The shapes the trie reconstruction is meant for.
		`(?i)(?:select|set|sleep)`,
		`(?i)(?:select|sleep|substr|union|update|insert|delete|alter|create|benchmark|floor|format|length|concat|decode|encode|replace|reverse|trim|upper)`,
		`(?i)(?:exec|execute|call|sp_|xp_|@@version|information_schema)`,
		`(?i)(?:^|["':;=])\s*(?:alert|prompt|confirm)\s*\(`,
		`(?i)union\s+(?:all\s+)?select`,
		`(?i)(?:e(?:xec|val)|s(?:ystem|hell_exec)|p(?:assthru|open))\s*\(`,
		`\.ph(?:p\d*|tml|ar|ps|t|pt)\.*$`,
	}

	tx := corazawaf.NewWAF().NewTransaction()
	defer tx.Close()

	for _, pat := range patterns {
		t.Run(pat, func(t *testing.T) {
			matched, compared, disagreements, first, err := prefilterDisagreement(pat, 300, tx)
			if err != nil {
				t.Fatalf("pattern: %v", err)
			}
			if matched == 0 {
				t.Errorf("no generated input matched the pattern: the generator is not exercising it (%d inputs)", compared)
			}
			if disagreements > 0 {
				t.Errorf("the prefilter changed the answer on %d of %d inputs; first: %q", disagreements, compared, first)
			}
		})
	}
}
