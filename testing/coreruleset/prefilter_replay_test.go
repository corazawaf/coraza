// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

// Replays the requests a Coraza deployment logged through a ruleset twice, with SecRxPreFilter
// Off and On, and compares the matched rule ids and the interruption of every one, like
// prefilter_parity_test.go does for the CRS corpus. The input is production traffic: the JSON
// audit log (SecAuditLogFormat JSON, one object per line) with part C, which carries the request
// body. A request is replayed as it was logged: method, URI, headers and the body that survived.
//
// Skipped unless an environment variable asks for it, and the ruleset comes from
// CORAZA_RX_PARITY_RULES, as in the parity test:
//
//	CORAZA_RX_AUDIT_LOGS=<file or directory>  replay the requests in these audit logs (a
//	                                          directory is read recursively; *.gz is unzipped)
//	CORAZA_RX_AUDIT_LIMIT=<n>                 only the first n distinct requests
//	CORAZA_RX_AUDIT_REPORT=<file>             also write the report there
//	CORAZA_RX_AUDIT_SELFCHECK=1               write an audit log with this same ruleset and replay
//	                                          that, which proves the replay reads what Coraza writes
//	CORAZA_RX_AUDIT_SELFCHECK_LOG=<file>      keep that log there (the file must not exist yet)
//
// The report holds request lines, which can carry customer data: keep it inside the company.

// These tests don't currently compile with TinyGo
//go:build !tinygo

package coreruleset

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
)

// replayEntry is the part of one JSON audit log line the replay needs.
type replayEntry struct {
	Transaction struct {
		ID      string `json:"id"`
		Request *struct {
			Method string `json:"method"`
			URI    string `json:"uri"`
			// Coraza fills protocol (REQUEST_PROTOCOL) and leaves http_version empty.
			Protocol    string              `json:"protocol"`
			HTTPVersion string              `json:"http_version"`
			Headers     map[string][]string `json:"headers"`
			Body        string              `json:"body"`
		} `json:"request"`
	} `json:"transaction"`
	Messages []struct {
		Data *struct {
			ID int `json:"id"`
		} `json:"data"`
	} `json:"messages"`
}

// replayRequest is one logged request, ready to run.
type replayRequest struct {
	parityRequest
	logged   []int // distinct ids of the rules the log lists for it
	bodyless bool  // the request had a body and the log has none: no part C, or a rule removed it
	cut      bool  // the log has only the start of the body
}

// replayContentLength is the Content-Length the log carries for the request, or 0.
func replayContentLength(headers map[string][]string) int64 {
	for k, v := range headers {
		if strings.EqualFold(k, "content-length") && len(v) > 0 {
			if n, err := strconv.ParseInt(strings.TrimSpace(v[0]), 10, 64); err == nil {
				return n
			}
		}
	}
	return 0
}

type replayStats struct {
	files, lines, notJSON, noRequest, duplicates int
	bodyless, cut, withLoggedRules               int
}

func (s replayStats) String() string {
	return fmt.Sprintf("%d file(s), %d line(s): %d not JSON, %d without a request, %d duplicates dropped; "+
		"%d logged without their body (no part C, or a rule removed it), %d with only the start of the body, %d list the rules that matched",
		s.files, s.lines, s.notJSON, s.noRequest, s.duplicates, s.bodyless, s.cut, s.withLoggedRules)
}

func replayLogFiles(t *testing.T, path string) []string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		return []string{path}
	}
	var files []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

// replayEachLine calls fn for every line of the file, unzipping a *.gz first. A line is as long
// as it is: a logged body can be megabytes.
func replayEachLine(path string, fn func(line []byte)) error {
	f, err := os.Open(path) //nolint:gosec // a path the operator named
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			fn(line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// replayLoad reads the requests of every audit log under path. limit 0 means all.
func replayLoad(t *testing.T, path string, limit int) ([]replayRequest, replayStats) {
	t.Helper()
	var (
		out  []replayRequest
		st   replayStats
		seen = map[string]bool{}
	)
	for _, file := range replayLogFiles(t, path) {
		st.files++
		err := replayEachLine(file, func(line []byte) {
			st.lines++
			if limit > 0 && len(out) >= limit {
				return
			}
			var e replayEntry
			if err := json.Unmarshal(line, &e); err != nil {
				st.notJSON++
				return
			}
			rq := e.Transaction.Request
			if rq == nil {
				st.noRequest++
				return
			}
			version := rq.Protocol
			if version == "" {
				version = rq.HTTPVersion
			}
			r := replayRequest{parityRequest: parityRequest{
				base: e.Transaction.ID, carrier: "audit", method: rq.Method, uri: rq.URI, version: version,
				body: []byte(rq.Body), respStatus: 200, respHeaders: [][2]string{{"Content-Type", "text/html"}},
			}}
			if r.method == "" {
				r.method = "GET"
			}
			if r.uri == "" {
				r.uri = "/"
			}
			if r.version == "" {
				r.version = "HTTP/1.1"
			}
			names := make([]string, 0, len(rq.Headers))
			for k := range rq.Headers {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				for _, v := range rq.Headers[k] {
					r.headers = append(r.headers, [2]string{k, v})
				}
			}

			var key strings.Builder
			fmt.Fprintf(&key, "%s\x00%s\x00%s\x00%s", r.method, r.uri, r.version, rq.Body)
			for _, h := range r.headers {
				fmt.Fprintf(&key, "\x00%s\x00%s", h[0], h[1])
			}
			if seen[key.String()] {
				st.duplicates++
				return
			}
			seen[key.String()] = true

			ids := map[int]bool{}
			for _, m := range e.Messages {
				if m.Data != nil && m.Data.ID != 0 {
					ids[m.Data.ID] = true
				}
			}
			for id := range ids {
				r.logged = append(r.logged, id)
			}
			sort.Ints(r.logged)
			if len(r.logged) > 0 {
				st.withLoggedRules++
			}
			// The Content-Length the log carries says whether the whole body is there. A
			// ruleset can remove part C itself (ctl:auditLogParts) for some requests, and the
			// integration may log only the start of a body.
			if cl := replayContentLength(rq.Headers); cl > 0 {
				switch {
				case rq.Body == "":
					r.bodyless = true
					st.bodyless++
				case cl > int64(len(rq.Body)):
					r.cut = true
					st.cut++
				}
			}
			out = append(out, r)
		})
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	return out, st
}

// replayGroundTruth says how many of the rules the log lists the replay with the prefilter off
// found again. A rule missing there is not a prefilter finding: the ruleset can differ from the
// one that logged it, the body can be cut, and response-phase rules never ran.
func replayGroundTruth(reqs []replayRequest, res []parityResult) (text string, full, withLog int) {
	var partial, none, skipped int
	missing := map[int]int{}
	for i, r := range reqs {
		if len(r.logged) == 0 {
			continue
		}
		// Rules on the body cannot match again when the log does not have all of it.
		if r.bodyless || r.cut {
			skipped++
			continue
		}
		withLog++
		found := map[int]bool{}
		for _, id := range res[i].matched {
			found[id] = true
		}
		hit := 0
		for _, id := range r.logged {
			if found[id] {
				hit++
			} else {
				missing[id]++
			}
		}
		switch {
		case hit == len(r.logged):
			full++
		case hit > 0:
			partial++
		default:
			none++
		}
	}
	type idCount struct{ id, n int }
	top := make([]idCount, 0, len(missing))
	for id, n := range missing {
		top = append(top, idCount{id, n})
	}
	sort.Slice(top, func(a, b int) bool {
		if top[a].n != top[b].n {
			return top[a].n > top[b].n
		}
		return top[a].id < top[b].id
	})
	if len(top) > 10 {
		top = top[:10]
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "   requests with their whole body whose log lists rules: %d; replayed with the prefilter off, all of them matched again: %d, some: %d, none: %d\n",
		withLog, full, partial, none)
	if skipped > 0 {
		fmt.Fprintf(&sb, "   not compared with the log, because it lacks all of the body: %d (the ruleset or the integration left the body out)\n", skipped)
	}
	if len(top) > 0 {
		parts := make([]string, len(top))
		for i, c := range top {
			parts[i] = fmt.Sprintf("%d (x%d)", c.id, c.n)
		}
		fmt.Fprintf(&sb, "   logged rules that did not match again, most frequent first: %s\n", strings.Join(parts, ", "))
	}
	return sb.String(), full, withLog
}

// replayRun runs every request through the ruleset with the prefilter off and on and reports. It
// returns whether the two agreed everywhere and the results of the run.
func replayRun(t *testing.T, dir, engine, source string, ci int, reqs []replayRequest) (text string, ok bool, res []parityResult) {
	t.Helper()
	plain := make([]parityRequest, len(reqs))
	for i := range reqs {
		plain[i] = reqs[i].parityRequest
	}
	off := parityRulesWAF(t, dir, engine, "Off")
	on := parityRulesWAF(t, dir, engine, "On")
	defer parityClose(off)
	defer parityClose(on)

	res = make([]parityResult, len(plain))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < runtime.GOMAXPROCS(0); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				res[i] = parityCompareOne(off, on, parityIP(ci, i, 0), parityIP(ci, i, 1), plain[i], i%2 == 0)
			}
		}()
	}
	started := time.Now()
	for i := range plain {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	name := fmt.Sprintf("replay of %s through ruleset %s, SecRuleEngine %s", source, dir, engine)
	text, ok = parityReport(name, plain, res)
	return fmt.Sprintf("%s   (wall time %s)\n", text, time.Since(started).Round(time.Second)), ok, res
}

func replayRuleset(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("CORAZA_RX_PARITY_RULES")
	if dir == "" {
		t.Fatal("CORAZA_RX_PARITY_RULES must name the ruleset to replay through")
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.conf")); len(m) == 0 {
		t.Fatalf("CORAZA_RX_PARITY_RULES=%s has no *.conf", dir)
	}
	return dir
}

// TestRxPreFilterAuditReplay replays production requests from audit logs.
func TestRxPreFilterAuditReplay(t *testing.T) {
	logs := os.Getenv("CORAZA_RX_AUDIT_LOGS")
	if logs == "" {
		t.Skip("set CORAZA_RX_AUDIT_LOGS=<JSON audit log file or directory> and CORAZA_RX_PARITY_RULES=<ruleset dir>")
	}
	dir := replayRuleset(t)
	defer parityOfflineDNS()()

	limit := 0
	if s := os.Getenv("CORAZA_RX_AUDIT_LIMIT"); s != "" {
		if _, err := fmt.Sscan(s, &limit); err != nil || limit <= 0 {
			t.Fatalf("CORAZA_RX_AUDIT_LIMIT=%q is not a positive number", s)
		}
	}
	reqs, st := replayLoad(t, logs, limit)
	t.Logf("%s", st)
	if len(reqs) == 0 {
		t.Fatal("no replayable request in the audit logs")
	}
	if len(reqs) >= 1<<19 {
		t.Fatalf("%d requests is more than the per-run address space of parityIP", len(reqs))
	}

	var report strings.Builder
	fmt.Fprintf(&report, "audit logs: %s\n   %s\n\n", logs, st)
	allOK := true
	for ci, engine := range []string{"DetectionOnly", "On"} {
		text, ok, res := replayRun(t, dir, engine, logs, ci, reqs)
		if engine == "DetectionOnly" {
			truth, _, _ := replayGroundTruth(reqs, res)
			text += truth
		}
		allOK = allOK && ok
		fmt.Fprintf(&report, "%s\n", text)
		t.Logf("\n%s", text)
		if !ok {
			t.Errorf("%s: prefilter off and on disagree", engine)
		}
	}
	if path := os.Getenv("CORAZA_RX_AUDIT_REPORT"); path != "" {
		if err := os.WriteFile(path, []byte(report.String()), 0o600); err != nil {
			t.Errorf("writing %s: %v", path, err)
		}
	}
	if allOK {
		t.Logf("REPLAY OK: SecRxPreFilter Off and On agree on every logged request")
	}
}

// TestRxPreFilterAuditReplaySelfCheck writes a JSON audit log with part C, with
// the ruleset under test and the CRS corpus as traffic, then replays it. The rules the log lists
// must match again when the log is replayed through the same ruleset, so a replay that
// misreads what Coraza writes fails here instead of passing on an empty or garbled input.
func TestRxPreFilterAuditReplaySelfCheck(t *testing.T) {
	if os.Getenv("CORAZA_RX_AUDIT_SELFCHECK") == "" {
		t.Skip("set CORAZA_RX_AUDIT_SELFCHECK=1 and CORAZA_RX_PARITY_RULES=<ruleset dir>")
	}
	dir := replayRuleset(t)
	defer parityOfflineDNS()()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}

	// CORAZA_RX_AUDIT_SELFCHECK_LOG keeps the log (the file must not exist yet).
	logPath := os.Getenv("CORAZA_RX_AUDIT_SELFCHECK_LOG")
	if logPath == "" {
		logPath = filepath.Join(t.TempDir(), "audit.log")
	}
	cfg := coraza.NewWAFConfig().
		WithDirectives("SecRuleEngine DetectionOnly").
		WithDirectives(parityRulesBase).
		WithDirectives(fmt.Sprintf("SecTmpDir %s\nSecUploadDir %s", os.TempDir(), os.TempDir())).
		WithDirectives("SecAuditEngine On\nSecAuditLogParts ABCHZ\nSecAuditLogFormat JSON\nSecAuditLogType Serial\nSecAuditLog " + logPath).
		WithDirectives("Include " + filepath.ToSlash(filepath.Join(abs, "*.conf")))
	if ids := parityRemoveIDs(); ids != "" {
		cfg = cfg.WithDirectives("SecRuleRemoveById " + ids)
	}
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatal(err)
	}

	corpus := parityBuild(parityLoadCorpus(t), map[string]bool{"ftw": true})
	if len(corpus) > 600 {
		corpus = corpus[:600]
	}
	for i, r := range corpus {
		parityRunTx(waf, parityIP(2, i, 0), r)
	}
	parityClose(waf)

	reqs, st := replayLoad(t, logPath, 0)
	t.Logf("%d corpus requests written; read back: %d request(s); %s", len(corpus), len(reqs), st)
	if len(reqs) == 0 {
		t.Fatal("the audit log Coraza wrote has no request the replay can read")
	}
	if st.notJSON > 0 || st.noRequest > 0 {
		t.Errorf("the replay could not read %d line(s) of the log Coraza wrote (%d without a request)", st.notJSON+st.noRequest, st.noRequest)
	}
	if st.withLoggedRules == 0 {
		t.Fatal("no logged request lists the rules that matched: the replay has no ground truth to compare with")
	}
	if st.bodyless == 0 {
		// The ruleset removes part C for file uploads and body parse errors, and the corpus has both.
		t.Error("no request was logged without its body; the loader no longer sees the ruleset removing part C")
	}

	text, ok, res := replayRun(t, dir, "DetectionOnly", logPath, 3, reqs)
	truth, full, withLog := replayGroundTruth(reqs, res)
	t.Logf("\n%s%s", text, truth)
	if !ok {
		t.Error("prefilter off and on disagree on the replayed log")
	}
	if withLog == 0 {
		t.Fatal("no request with its whole body lists the rules that matched: nothing to compare the replay with")
	}
	// Some rules keep state between requests, so allow a few that do not come back.
	if full*10 < withLog*9 {
		t.Errorf("only %d of %d logged requests matched their logged rules again: the replay does not reproduce what was logged", full, withLog)
	}
}
