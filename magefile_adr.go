// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build mage

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const adrDir = "docs/adr"

var (
	adrFileRe       = regexp.MustCompile(`^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$`)
	adrTitleRe      = regexp.MustCompile(`(?m)^# ADR-(\d{4}): \S`)
	adrFieldRe      = regexp.MustCompile(`(?m)^- \*\*([^*]+):\*\* *(.*)$`)
	adrQuoteRe      = regexp.MustCompile(`(?m)^> — @[A-Za-z0-9_+.-]+ .*?\(\[[^\]]+\]\(([^)]+)\)\)`)
	adrPermalink    = regexp.MustCompile(`^https://github\.com/corazawaf/coraza/(?:pull|issues)/\d+#(?:discussion_r|issuecomment-)\d+$`)
	adrIndexRowRe   = regexp.MustCompile(`(?m)^\| *\[?(?:ADR-)?(\d{4})[\]|(]`)
	adrSupersededRe = regexp.MustCompile(`^superseded by ADR-\d{4}$`)
	// A bare category, or one followed by a single parenthetical qualifier
	// ("Parity (ModSecurity parity)"). The delimiter stops "Performance"
	// passing as "Perf"; allowing nothing after the qualifier keeps each
	// record countable under exactly one category.
	adrMarkerRe   = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(adrNoDiscussion))
	adrCategoryRe = regexp.MustCompile(`^(?:` + strings.Join(adrCategories, "|") + `)(?: \([^)]+\))?$`)
)

var (
	adrStatuses     = []string{"proposed", "accepted", "deprecated"}
	adrCategories   = []string{"Feature", "Parity", "Perf", "Refactor"}
	adrNoDiscussion = "No substantive technical discussion recorded"
)

// Adr validates the Architecture Decision Records under docs/adr.
//
// Structure only: it cannot tell whether a quote matches what the person
// actually wrote. Reviewers must open the permalinks and read them.
func Adr() error {
	entries, err := os.ReadDir(adrDir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", adrDir, err)
	}

	var problems []string
	seen := map[string]string{}
	var numbers []string

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".md") || name == "README.md" {
			continue
		}
		m := adrFileRe.FindStringSubmatch(name)
		if m == nil {
			problems = append(problems, fmt.Sprintf("%s: filename must be NNNN-lower-kebab-slug.md", name))
			continue
		}
		num := m[1]
		if prev, dup := seen[num]; dup {
			problems = append(problems, fmt.Sprintf("%s: duplicate ADR number %s (also %s)", name, num, prev))
		}
		seen[num] = name

		body, err := os.ReadFile(filepath.Join(adrDir, name))
		if err != nil {
			return fmt.Errorf("reading %s: %w", name, err)
		}
		if num == "0000" {
			continue // the template is exempt: it carries placeholders by design
		}
		numbers = append(numbers, num)
		problems = append(problems, checkADR(name, num, string(body))...)
	}

	if len(seen) == 0 {
		return errors.New(adrDir + ": no ADR files found")
	}
	problems = append(problems, checkADRIndex(numbers)...)

	if len(problems) > 0 {
		sort.Strings(problems)
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "  "+p)
		}
		return fmt.Errorf("%d ADR problem(s)", len(problems))
	}
	fmt.Printf("%s: %d record(s) OK\n", adrDir, len(numbers))
	return nil
}

func checkADR(name, num, body string) []string {
	var out []string
	bad := func(format string, args ...any) {
		out = append(out, name+": "+fmt.Sprintf(format, args...))
	}

	// Only the document's own title counts: a later heading, or one inside an
	// example, must not stand in for a missing or misnumbered title.
	title := ""
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "# ") {
			title = line
			break
		}
	}
	if m := adrTitleRe.FindStringSubmatch(title); m == nil {
		bad("missing '# ADR-%s: <title>' heading", num)
	} else if m[1] != num {
		bad("heading says ADR-%s but the filename says %s", m[1], num)
	}

	// Only the block above the first section counts: a "- **Status:** ..." line
	// further down the document must not stand in for a missing header field.
	fields := map[string]string{}
	for _, m := range adrFieldRe.FindAllStringSubmatch(adrHeaderBlock(body), -1) {
		fields[m[1]] = strings.TrimSpace(m[2])
	}
	for _, want := range []string{"Status", "Date", "Version", "PR", "Issue(s)", "Deciders", "Category"} {
		if fields[want] == "" {
			bad("missing or empty '- **%s:**' header field", want)
		}
	}

	if s := fields["Status"]; s != "" && !containsString(adrStatuses, s) && !adrSupersededRe.MatchString(s) {
		bad("Status %q must be one of %v or 'superseded by ADR-NNNN'", s, adrStatuses)
	}
	if c := fields["Category"]; c != "" && !adrCategoryRe.MatchString(c) {
		bad("Category %q must be one of %v, optionally followed by a parenthetical qualifier", c, adrCategories)
	}

	// The evidence has to be in the Technical Discussion section itself: a quote
	// elsewhere in the document does not make an empty section acceptable.
	discussion, ok := adrSection(body, "## Technical Discussion")
	if !ok {
		bad("missing '## Technical Discussion' section")
	} else if len(adrQuotedComments(discussion)) == 0 && !adrMarkerRe.MatchString(discussion) {
		bad("Technical Discussion needs an attributed quote with a permalink, or the marker %q", adrNoDiscussion)
	}

	for _, q := range adrQuoteRe.FindAllStringSubmatch(body, -1) {
		if !adrPermalink.MatchString(q[1]) {
			bad("quote attribution links to %q, want a corazawaf/coraza comment permalink", q[1])
		}
	}
	return out
}

func checkADRIndex(numbers []string) []string {
	body, err := os.ReadFile(filepath.Join(adrDir, "README.md"))
	if err != nil {
		return []string{"README.md: " + err.Error()}
	}
	indexed := map[string]int{}
	for _, m := range adrIndexRowRe.FindAllStringSubmatch(string(body), -1) {
		indexed[m[1]]++
	}
	var out []string
	for _, n := range numbers {
		switch rows := indexed[n]; {
		case rows == 0:
			out = append(out, fmt.Sprintf("README.md: ADR-%s is not listed in the index", n))
		case rows > 1:
			out = append(out, fmt.Sprintf("README.md: ADR-%s is listed %d times in the index", n, rows))
		}
		delete(indexed, n)
	}
	for n := range indexed {
		out = append(out, fmt.Sprintf("README.md: index lists ADR-%s but no such file exists", n))
	}
	sort.Strings(out)
	return out
}

// adrQuotedComments returns the attributions in a section that actually have
// quoted text above them. A bare "> — @user ([comment](...))" cites a source
// for nothing, so it does not count as discussion.
func adrQuotedComments(section string) []string {
	var links []string
	quoted := false
	for _, line := range strings.Split(section, "\n") {
		switch {
		case !strings.HasPrefix(line, ">"):
			quoted = false
		case adrQuoteRe.MatchString(line):
			if m := adrQuoteRe.FindStringSubmatch(line); quoted && m != nil {
				links = append(links, m[1])
			}
			quoted = false
		case strings.TrimSpace(strings.TrimPrefix(line, ">")) != "":
			quoted = true
		}
	}
	return links
}

// adrHeaderBlock returns the part of an ADR above its first "## " section.
func adrHeaderBlock(body string) string {
	if i := strings.Index(body, "\n## "); i >= 0 {
		return body[:i]
	}
	return body
}

// adrSection returns the body of one "## " section, up to the next one.
func adrSection(body, heading string) (string, bool) {
	i := strings.Index(body, "\n"+heading+"\n")
	if i < 0 {
		return "", false
	}
	rest := body[i+len(heading)+1:]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		rest = rest[:j]
	}
	return rest, true
}

func containsString(haystack []string, s string) bool {
	for _, h := range haystack {
		if h == s {
			return true
		}
	}
	return false
}
