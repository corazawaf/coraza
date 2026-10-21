// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

// End-to-end check that SecRxPreFilter does not change what a ruleset detects. The CRS
// regression corpus (the FTW tests shipped in coraza-coreruleset) is replayed, with every
// payload carried several ways, through a full ruleset twice: once with SecRxPreFilter Off
// and once with it On. The matched rule ids and the interruption of every transaction are
// compared. Any difference is a detection the prefilter lost or made up.
//
// Skipped unless CORAZA_RX_PARITY is set:
//
//	CORAZA_RX_PARITY=1 go test -count=1 -run TestRxPreFilterParity -v ./testing/coreruleset/
//
// CORAZA_RX_PARITY_RULES=<dir with *.conf>  also runs that ruleset (an unzipped ruleset
//                                           archive), engine On and DetectionOnly
// CORAZA_RX_PARITY_LIMIT=<n>                only the first n distinct FTW requests (smoke run)
// CORAZA_RX_PARITY_CARRIERS=a,b             only these carriers (see parityBuild)
// CORAZA_RX_PARITY_REPORT=<file>            also write the report there
// CORAZA_RX_PARITY_REMOVE_IDS=<ids>         remove these rules from the ruleset (see parityRemoveIDs)
//
// The bundled CRS always runs, at paranoia level 4 in DetectionOnly (what the FTW run uses),
// so every rule gets to run and none of them is hidden behind an earlier block.

// These tests don't currently compile with TinyGo
//go:build !tinygo

package coreruleset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	crstests "github.com/corazawaf/coraza-coreruleset/v4/tests"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

const parityUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

// parityCRSSettings is what TestFTW and crsWAF load between coraza.conf-recommended and the CRS.
const parityCRSSettings = `
SecResponseBodyMimeType text/plain
SecDefaultAction "phase:3,log,auditlog,pass"
SecDefaultAction "phase:4,log,auditlog,pass"
SecDefaultAction "phase:5,log,auditlog,pass"

SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"
`

// parityRulesBase is the part of a typical deployment's configuration that shapes rule
// evaluation, minus logging, the engine mode and SecRxPreFilter, which the test sets.
const parityRulesBase = `
SecRequestBodyAccess On
SecRequestBodyLimitAction ProcessPartial
SecArgumentSeparator &
SecCookieFormat 0
`

// parityRemoveIDs is the SecRuleRemoveById argument CORAZA_RX_PARITY_REMOVE_IDS gives, ids
// separated by commas or spaces, or "" when it names none. It is for rules whose match is
// random, such as a rule that samples traffic by UNIQUE_ID: those fire on a different request
// in every run, so they differ between Off and On for reasons that have nothing to do with
// the prefilter.
func parityRemoveIDs() string {
	return strings.Join(strings.FieldsFunc(os.Getenv("CORAZA_RX_PARITY_REMOVE_IDS"), func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}), " ")
}

var parityWords = strings.Fields(`the quick brown fox jumps over lazy dog river mountain garden window kitchen morning
evening coffee summer winter forest yellow purple silver paper pencil bridge harbor island meadow market village
travel story picture family friend music dinner holiday weather season flower orange planet ocean valley cabin
lantern blanket pillow basket ribbon button candle pepper butter honey bread cheese apple grape lemon melon`)

// ---------------------------------------------------------------- the corpus

type parityFTWInput struct {
	Method         string         `yaml:"method"`
	URI            string         `yaml:"uri"`
	Version        string         `yaml:"version"`
	Headers        map[string]any `yaml:"headers"`
	OrderedHeaders []struct {
		Name  string `yaml:"name"`
		Value any    `yaml:"value"`
	} `yaml:"ordered_headers"`
	Data           string `yaml:"data"`
	RawRequest     string `yaml:"raw_request"`
	EncodedRequest string `yaml:"encoded_request"`
}

func (in parityFTWInput) empty() bool {
	return in.Method == "" && in.URI == "" && in.Data == "" && len(in.Headers) == 0 &&
		len(in.OrderedHeaders) == 0 && in.RawRequest == "" && in.EncodedRequest == ""
}

type parityFTWStage struct {
	Input parityFTWInput `yaml:"input"`
	// Older files wrap the stage: "- stage: input: ...".
	Stage struct {
		Input parityFTWInput `yaml:"input"`
	} `yaml:"stage"`
}

type parityFTWFile struct {
	Tests []struct {
		Stages []parityFTWStage `yaml:"stages"`
	} `yaml:"tests"`
}

// parityBase is one request of the FTW corpus as written.
type parityBase struct {
	id      string
	method  string
	uri     string
	version string
	headers [][2]string
	data    string
}

func (b parityBase) lookup(name string) (string, bool) {
	for _, h := range b.headers {
		if strings.EqualFold(h[0], name) {
			return h[1], true
		}
	}
	return "", false
}

func parityLoadCorpus(t *testing.T) []parityBase {
	t.Helper()
	var out []parityBase
	seen := map[string]bool{}
	files, unreadable, raw, dup := 0, 0, 0, 0
	err := doublestar.GlobWalk(crstests.FS, "**/*.yaml", func(path string, d os.DirEntry) error {
		src, err := fs.ReadFile(crstests.FS, path)
		if err != nil {
			return err
		}
		files++
		var f parityFTWFile
		if err := yaml.Unmarshal(src, &f); err != nil {
			t.Logf("corpus: skipping %s: %v", path, err)
			unreadable++
			return nil
		}
		for ti, tc := range f.Tests {
			for si, st := range tc.Stages {
				in := st.Input
				if in.empty() {
					in = st.Stage.Input
				}
				if in.RawRequest != "" || in.EncodedRequest != "" {
					raw++
					continue
				}
				b := parityBase{
					id:      fmt.Sprintf("%s#%d.%d", path, ti+1, si+1),
					method:  strings.ToUpper(in.Method),
					uri:     in.URI,
					version: in.Version,
					data:    in.Data,
				}
				if b.method == "" {
					b.method = "GET"
				}
				if b.uri == "" {
					b.uri = "/"
				}
				if b.version == "" {
					b.version = "HTTP/1.1"
				}
				if len(in.OrderedHeaders) > 0 {
					for _, h := range in.OrderedHeaders {
						b.headers = append(b.headers, [2]string{h.Name, fmt.Sprint(h.Value)})
					}
				} else {
					keys := make([]string, 0, len(in.Headers))
					for k := range in.Headers {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						b.headers = append(b.headers, [2]string{k, fmt.Sprint(in.Headers[k])})
					}
				}
				var key strings.Builder
				fmt.Fprintf(&key, "%s\x00%s\x00%s\x00%s", b.method, b.uri, b.version, b.data)
				for _, h := range b.headers {
					fmt.Fprintf(&key, "\x00%s\x00%s", h[0], h[1])
				}
				if seen[key.String()] {
					dup++
					continue
				}
				seen[key.String()] = true
				out = append(out, b)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("corpus: %d FTW files, %d distinct requests (%d duplicates dropped, %d raw/encoded requests skipped, %d files unreadable)",
		files, len(out), dup, raw, unreadable)
	if len(out) == 0 {
		t.Fatal("no FTW requests found")
	}
	return out
}

// ---------------------------------------------------------------- carriers

type parityRequest struct {
	base        string
	carrier     string
	method      string
	uri         string
	version     string
	headers     [][2]string
	body        []byte
	respStatus  int
	respHeaders [][2]string
	respBody    []byte
}

// parityForm returns the payload of a base request as an urlencoded string: its form
// body, else its query string, else its body quoted into one parameter. "" when it has none.
func parityForm(b parityBase) string {
	ct, _ := b.lookup("Content-Type")
	ct = strings.ToLower(ct)
	if b.data != "" {
		if strings.Contains(ct, "application/x-www-form-urlencoded") || (ct == "" && strings.Contains(b.data, "=")) {
			return b.data
		}
	}
	if i := strings.Index(b.uri, "?"); i >= 0 && i+1 < len(b.uri) {
		return b.uri[i+1:]
	}
	if b.data != "" {
		return "p=" + url.QueryEscape(b.data)
	}
	return ""
}

func parityPath(uri string) string {
	p := uri
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if !strings.HasPrefix(p, "/") {
		return "/"
	}
	return p
}

func parityJSONString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(buf.String(), "\n")
}

// parityJSONBody turns the parameters of a form into the members of a JSON object.
func parityJSONBody(form string) []byte {
	var members []string
	vals, err := url.ParseQuery(form)
	if err != nil || len(vals) == 0 {
		members = append(members, `"k0":`+parityJSONString(form))
	} else {
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for i, v := range vals[k] {
				name := k
				if i > 0 {
					name = fmt.Sprintf("%s_%d", k, i)
				}
				members = append(members, parityJSONString(name)+":"+parityJSONString(v))
			}
		}
	}
	members = append(members, `"benign":"hello world"`)
	return []byte("{" + strings.Join(members, ",") + "}")
}

func parityEchoText(form string) string {
	vals, err := url.ParseQuery(form)
	if err != nil || len(vals) == 0 {
		return form
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, vals[k]...)
	}
	return strings.Join(parts, " ")
}

// parityReflect reads the response an FTW request asks albedo's /reflect endpoint to send
// back: {"status":..,"headers":{..},"body":".."}. The response rules (950 to 954) are tested
// that way, so the payload is in the response and not in the request.
func parityReflect(b parityBase) (status int, headers [][2]string, body []byte, ok bool) {
	if !strings.Contains(b.uri, "reflect") || b.data == "" {
		return 0, nil, nil, false
	}
	var m struct {
		Status  int            `json:"status"`
		Headers map[string]any `json:"headers"`
		Body    string         `json:"body"`
	}
	if err := json.Unmarshal([]byte(b.data), &m); err != nil {
		return 200, [][2]string{{"Content-Type", "text/plain"}}, []byte(b.data), true
	}
	status = m.Status
	if status == 0 {
		status = 200
	}
	keys := make([]string, 0, len(m.Headers))
	for k := range m.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, "content-type") {
			continue
		}
		headers = append(headers, [2]string{k, fmt.Sprint(m.Headers[k])})
	}
	// TestFTW forces text/plain on every response, so the response body is inspected.
	headers = append(headers, [2]string{"Content-Type", "text/plain"})
	return status, headers, []byte(m.Body), true
}

func parityPad(prefix string, args int, rnd *rand.Rand) string {
	parts := make([]string, args)
	for i := range parts {
		var sb strings.Builder
		for sb.Len() < 300 {
			if sb.Len() > 0 {
				sb.WriteByte('+')
			}
			sb.WriteString(parityWords[rnd.Intn(len(parityWords))])
		}
		parts[i] = fmt.Sprintf("%s%02d=%s", prefix, i, sb.String())
	}
	return strings.Join(parts, "&")
}

func parityPost(base, carrier, uri, contentType string, body []byte) parityRequest {
	return parityRequest{
		base: base, carrier: carrier, method: "POST", uri: uri, version: "HTTP/1.1",
		headers: [][2]string{
			{"Host", "app.example.com"},
			{"User-Agent", parityUserAgent},
			{"Accept", "*/*"},
			{"Content-Type", contentType},
			{"Content-Length", fmt.Sprint(len(body))},
		},
		body:        body,
		respStatus:  200,
		respHeaders: [][2]string{{"Content-Type", "text/html"}},
	}
}

// parityBuild turns the corpus into the requests that are run. Carriers:
//
//	ftw          the request exactly as the FTW test sends it (plus the response an
//	             albedo /reflect request asks for)
//	get-query    the payload as a query string of a GET
//	post-form    the payload as an urlencoded POST body
//	post-json    the payload's parameters as members of a JSON POST body
//	post-padded  the form body between two ~14 KB runs of benign parameters, ~28 KB in
//	             all
//	echo         the form body, and the payload echoed back in the response body
func parityBuild(bases []parityBase, only map[string]bool) []parityRequest {
	rnd := rand.New(rand.NewSource(1)) //nolint:gosec // reproducible test input, not security
	pad1 := parityPad("pad1_", 45, rnd)
	pad2 := parityPad("pad2_", 45, rnd)

	var out []parityRequest
	add := func(r parityRequest) {
		if len(only) == 0 || only[r.carrier] {
			out = append(out, r)
		}
	}
	const form = "application/x-www-form-urlencoded"
	for _, b := range bases {
		r := parityRequest{
			base: b.id, carrier: "ftw", method: b.method, uri: b.uri, version: b.version,
			headers: append([][2]string(nil), b.headers...), body: []byte(b.data),
			respStatus: 200, respHeaders: [][2]string{{"Content-Type", "text/html"}},
		}
		if _, ok := b.lookup("Host"); !ok {
			r.headers = append(r.headers, [2]string{"Host", "localhost"})
		}
		if _, ok := b.lookup("Content-Length"); !ok && b.data != "" {
			r.headers = append(r.headers, [2]string{"Content-Length", fmt.Sprint(len(b.data))})
		}
		if status, hdrs, body, ok := parityReflect(b); ok {
			r.respStatus, r.respHeaders, r.respBody = status, hdrs, body
		}
		add(r)

		f := parityForm(b)
		if f == "" {
			continue
		}
		path := parityPath(b.uri)
		if len(f) <= 8000 {
			add(parityRequest{
				base: b.id, carrier: "get-query", method: "GET", uri: path + "?" + f, version: "HTTP/1.1",
				headers: [][2]string{
					{"Host", "app.example.com"}, {"User-Agent", parityUserAgent}, {"Accept", "*/*"},
				},
				respStatus: 200, respHeaders: [][2]string{{"Content-Type", "text/html"}},
			})
		}
		add(parityPost(b.id, "post-form", path, form, []byte(f)))
		add(parityPost(b.id, "post-json", path, "application/json", parityJSONBody(f)))
		add(parityPost(b.id, "post-padded", path, form, []byte(pad1+"&"+f+"&"+pad2)))
		e := parityPost(b.id, "echo", path, form, []byte(f))
		e.respHeaders = [][2]string{{"Content-Type", "text/plain"}}
		e.respBody = []byte("<html><body>" + parityEchoText(f) + "</body></html>")
		add(e)
	}
	return out
}

// ---------------------------------------------------------------- the WAFs

func parityCRSWAF(t *testing.T, mode string) coraza.WAF {
	t.Helper()
	rec, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		t.Fatal(err)
	}
	// SecRxPreFilter comes after coraza.conf-recommended, which sets it Off, and before the
	// rules, which it applies to.
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(string(rec)).
		WithDirectives(parityCRSSettings).
		WithDirectives("SecRxPreFilter " + mode).
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("Include @owasp_crs/*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return waf
}

func parityRulesWAF(t *testing.T, dir, engine, mode string) coraza.WAF {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := coraza.NewWAFConfig().
		WithDirectives("SecRuleEngine " + engine).
		WithDirectives(parityRulesBase).
		WithDirectives(fmt.Sprintf("SecTmpDir %s\nSecUploadDir %s", os.TempDir(), os.TempDir())).
		WithDirectives("SecRxPreFilter " + mode).
		WithDirectives("Include " + filepath.ToSlash(filepath.Join(abs, "*.conf")))
	if ids := parityRemoveIDs(); ids != "" {
		cfg = cfg.WithDirectives("SecRuleRemoveById " + ids)
	}
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return waf
}

func parityClose(w coraza.WAF) {
	if c, ok := w.(experimental.WAFCloser); ok {
		c.Close()
	}
}

// ---------------------------------------------------------------- running a request

type parityOutcome struct {
	rules   map[int]int
	intr    string
	detect  string
	err     string
	elapsed time.Duration
}

func parityNote(out *parityOutcome, what string, err error) {
	if err != nil && out.err == "" {
		out.err = what + ": " + err.Error()
	}
}

func parityIntr(i *types.Interruption) string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("%d/%s/%d", i.RuleID, i.Action, i.Status)
}

// parityRunTx runs one request through the phases the way a connector does: it stops at
// the first interruption.
func parityRunTx(waf coraza.WAF, ip string, r parityRequest) (out parityOutcome) {
	start := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			out.err = fmt.Sprint("panic: ", rec)
		}
		out.elapsed = time.Since(start)
	}()

	tx := waf.NewTransaction()
	var it *types.Interruption
	stop := func(i *types.Interruption) bool {
		if i != nil && it == nil {
			it = i
		}
		return it != nil
	}

	tx.ProcessConnection(ip, 40000, "127.0.0.1", 80)
	tx.ProcessURI(r.uri, r.method, r.version)
	for _, h := range r.headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	if !stop(tx.ProcessRequestHeaders()) {
		if len(r.body) > 0 {
			i, _, err := tx.WriteRequestBody(r.body)
			parityNote(&out, "write request body", err)
			stop(i)
		}
		if it == nil {
			i, err := tx.ProcessRequestBody()
			parityNote(&out, "process request body", err)
			stop(i)
		}
	}
	if it == nil {
		for _, h := range r.respHeaders {
			tx.AddResponseHeader(h[0], h[1])
		}
		if !stop(tx.ProcessResponseHeaders(r.respStatus, "HTTP/1.1")) {
			if len(r.respBody) > 0 {
				i, _, err := tx.WriteResponseBody(r.respBody)
				parityNote(&out, "write response body", err)
				stop(i)
			}
			if it == nil {
				i, err := tx.ProcessResponseBody()
				parityNote(&out, "process response body", err)
				stop(i)
			}
		}
	}
	tx.ProcessLogging()

	out.rules = map[int]int{}
	for _, mr := range tx.MatchedRules() {
		out.rules[mr.Rule().ID()]++
	}
	if it == nil {
		it = tx.Interruption()
	}
	out.intr = parityIntr(it)
	if d, ok := tx.(interface {
		DetectionOnlyInterruption() *types.Interruption
	}); ok {
		out.detect = parityIntr(d.DetectionOnlyInterruption())
	}
	parityNote(&out, "close", tx.Close())
	return out
}

// parityDiff returns the rule ids matched more often by a than by b, and the reverse.
func parityDiff(a, b map[int]int) (onlyA, onlyB []int) {
	for id, n := range a {
		if n > b[id] {
			onlyA = append(onlyA, id)
		}
	}
	for id, n := range b {
		if n > a[id] {
			onlyB = append(onlyB, id)
		}
	}
	sort.Ints(onlyA)
	sort.Ints(onlyB)
	return onlyA, onlyB
}

type parityResult struct {
	matched         []int // distinct rule ids matched with the prefilter off
	onlyOff, onlyOn []int
	intrOff, intrOn string
	detOff, detOn   string
	errOff, errOn   string
	tOff, tOn       time.Duration
}

func (x parityResult) differs() bool {
	return len(x.onlyOff) > 0 || len(x.onlyOn) > 0 || x.intrOff != x.intrOn || x.detOff != x.detOn || x.errOff != x.errOn
}

func parityCompareOne(off, on coraza.WAF, ipOff, ipOn string, r parityRequest, offFirst bool) parityResult {
	var a, b parityOutcome
	if offFirst {
		a = parityRunTx(off, ipOff, r)
		b = parityRunTx(on, ipOn, r)
	} else {
		b = parityRunTx(on, ipOn, r)
		a = parityRunTx(off, ipOff, r)
	}
	x := parityResult{
		intrOff: a.intr, intrOn: b.intr, detOff: a.detect, detOn: b.detect,
		errOff: a.err, errOn: b.err, tOff: a.elapsed, tOn: b.elapsed,
	}
	for id := range a.rules {
		x.matched = append(x.matched, id)
	}
	sort.Ints(x.matched)
	x.onlyOff, x.onlyOn = parityDiff(a.rules, b.rules)
	return x
}

// parityIP gives every transaction of every run an address of its own, so the persistent
// IP collections some rules keep do not carry anything from one request to the next.
func parityIP(cfg, idx, mode int) string {
	n := cfg<<20 | idx<<1 | mode
	return fmt.Sprintf("100.%d.%d.%d", 64+(n>>16)&63, (n>>8)&255, n&255)
}

// ---------------------------------------------------------------- the report

type parityAgg struct {
	requests, matched, differing int
	lost, extra, intr, det, errs int
	lostBy, extraBy              map[int]int
	distinct                     map[int]bool
	tOff, tOn                    time.Duration
}

func newParityAgg() *parityAgg {
	return &parityAgg{lostBy: map[int]int{}, extraBy: map[int]int{}, distinct: map[int]bool{}}
}

func (a *parityAgg) add(x parityResult) {
	a.requests++
	a.tOff += x.tOff
	a.tOn += x.tOn
	if len(x.matched) > 0 {
		a.matched++
	}
	for _, id := range x.matched {
		a.distinct[id] = true
	}
	if x.differs() {
		a.differing++
	}
	if len(x.onlyOff) > 0 {
		a.lost++
		for _, id := range x.onlyOff {
			a.lostBy[id]++
		}
	}
	if len(x.onlyOn) > 0 {
		a.extra++
		for _, id := range x.onlyOn {
			a.extraBy[id]++
		}
	}
	if x.intrOff != x.intrOn {
		a.intr++
	}
	if x.detOff != x.detOn {
		a.det++
	}
	if x.errOff != x.errOn {
		a.errs++
	}
}

func parityTrunc(s string, n int) string {
	s = strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func parityCounts(m map[int]int) string {
	ids := make([]int, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d (x%d)", id, m[id])
	}
	return strings.Join(parts, ", ")
}

const parityMaxDetail = 150

// parityReport summarises one configuration and returns false when Off and On disagreed.
func parityReport(name string, reqs []parityRequest, res []parityResult) (string, bool) {
	total := newParityAgg()
	per := map[string]*parityAgg{}
	var carriers []string
	var detail []string
	for i, x := range res {
		c := reqs[i].carrier
		if per[c] == nil {
			per[c] = newParityAgg()
			carriers = append(carriers, c)
		}
		per[c].add(x)
		total.add(x)
		if x.differs() && len(detail) < parityMaxDetail {
			var why []string
			if len(x.onlyOff) > 0 {
				why = append(why, fmt.Sprintf("LOST with prefilter on: %v", x.onlyOff))
			}
			if len(x.onlyOn) > 0 {
				why = append(why, fmt.Sprintf("EXTRA with prefilter on: %v", x.onlyOn))
			}
			if x.intrOff != x.intrOn {
				why = append(why, fmt.Sprintf("interruption off=%q on=%q", x.intrOff, x.intrOn))
			}
			if x.detOff != x.detOn {
				why = append(why, fmt.Sprintf("detection-only interruption off=%q on=%q", x.detOff, x.detOn))
			}
			if x.errOff != x.errOn {
				why = append(why, fmt.Sprintf("error off=%q on=%q", x.errOff, x.errOn))
			}
			detail = append(detail, fmt.Sprintf("  [%s] %s  %s %s\n      %s",
				reqs[i].carrier, reqs[i].base, reqs[i].method, parityTrunc(reqs[i].uri, 90), strings.Join(why, "; ")))
		}
	}
	sort.Strings(carriers)

	var sb strings.Builder
	fmt.Fprintf(&sb, "== %s\n", name)
	fmt.Fprintf(&sb, "   requests run (each twice, prefilter off and on): %d\n", total.requests)
	fmt.Fprintf(&sb, "   requests with at least one matched rule (prefilter off): %d (%.1f%%), distinct rules matched: %d\n",
		total.matched, 100*float64(total.matched)/float64(max(total.requests, 1)), len(total.distinct))
	fmt.Fprintf(&sb, "   requests that differ: %d   (lost a rule: %d, gained a rule: %d, interruption: %d, detection-only interruption: %d, error: %d)\n",
		total.differing, total.lost, total.extra, total.intr, total.det, total.errs)
	fmt.Fprintf(&sb, "   transaction time summed: off %.1fs, on %.1fs (%.2fx)\n",
		total.tOff.Seconds(), total.tOn.Seconds(), total.tOff.Seconds()/maxFloat(total.tOn.Seconds(), 1e-9))
	fmt.Fprintf(&sb, "\n   %-12s %9s %9s %9s %8s %9s %9s\n", "carrier", "requests", "matched", "distinct", "differ", "off s", "on s")
	for _, c := range carriers {
		a := per[c]
		fmt.Fprintf(&sb, "   %-12s %9d %9d %9d %8d %9.1f %9.1f\n", c, a.requests, a.matched, len(a.distinct), a.differing,
			a.tOff.Seconds(), a.tOn.Seconds())
	}
	if len(total.lostBy) > 0 {
		fmt.Fprintf(&sb, "\n   rules matched with the prefilter off but not on (requests): %s\n", parityCounts(total.lostBy))
	}
	if len(total.extraBy) > 0 {
		fmt.Fprintf(&sb, "\n   rules matched with the prefilter on but not off (requests): %s\n", parityCounts(total.extraBy))
	}
	if len(detail) > 0 {
		fmt.Fprintf(&sb, "\n   first %d differing requests:\n%s\n", len(detail), strings.Join(detail, "\n"))
	}
	return sb.String(), total.differing == 0
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// parityOfflineDNS makes every DNS lookup of the process fail at once and returns the function
// that puts the resolver back. A ruleset can query live DNS blocklists (@rbl). Answers
// change and offline they time out, so every @rbl rule reports "not listed", the same way in
// the run with the prefilter off and the one with it on.
func parityOfflineDNS() (restore func()) {
	oldPreferGo, oldDial := net.DefaultResolver.PreferGo, net.DefaultResolver.Dial
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("DNS is off in the prefilter tests")
	}
	return func() { net.DefaultResolver.PreferGo, net.DefaultResolver.Dial = oldPreferGo, oldDial }
}

// ---------------------------------------------------------------- the test

func TestRxPreFilterParity(t *testing.T) {
	if os.Getenv("CORAZA_RX_PARITY") == "" {
		t.Skip("set CORAZA_RX_PARITY=1 to run; CORAZA_RX_PARITY_RULES=<dir with *.conf> adds a ruleset")
	}

	defer parityOfflineDNS()()

	bases := parityLoadCorpus(t)
	if s := os.Getenv("CORAZA_RX_PARITY_LIMIT"); s != "" {
		var n int
		if _, err := fmt.Sscan(s, &n); err != nil || n <= 0 {
			t.Fatalf("CORAZA_RX_PARITY_LIMIT=%q is not a positive number", s)
		}
		if n < len(bases) {
			bases = bases[:n]
		}
	}
	only := map[string]bool{}
	if s := os.Getenv("CORAZA_RX_PARITY_CARRIERS"); s != "" {
		for _, c := range strings.Split(s, ",") {
			only[strings.TrimSpace(c)] = true
		}
	}
	reqs := parityBuild(bases, only)
	if len(reqs) >= 1<<19 {
		t.Fatalf("%d requests is more than the per-run address space of parityIP", len(reqs))
	}
	t.Logf("%d FTW requests carried into %d requests", len(bases), len(reqs))

	type config struct {
		name  string
		build func(mode string) coraza.WAF
	}
	configs := []config{{
		name:  "bundled CRS, paranoia level 4, DetectionOnly",
		build: func(mode string) coraza.WAF { return parityCRSWAF(t, mode) },
	}}
	if dir := os.Getenv("CORAZA_RX_PARITY_RULES"); dir != "" {
		if m, _ := filepath.Glob(filepath.Join(dir, "*.conf")); len(m) == 0 {
			t.Fatalf("CORAZA_RX_PARITY_RULES=%s has no *.conf", dir)
		}
		configs = append(configs,
			config{
				name:  "ruleset " + dir + ", SecRuleEngine DetectionOnly",
				build: func(mode string) coraza.WAF { return parityRulesWAF(t, dir, "DetectionOnly", mode) },
			},
			config{
				name:  "ruleset " + dir + ", SecRuleEngine On",
				build: func(mode string) coraza.WAF { return parityRulesWAF(t, dir, "On", mode) },
			})
	}

	var report strings.Builder
	allOK := true
	for ci, cfg := range configs {
		t.Logf("building %s", cfg.name)
		off := cfg.build("Off")
		on := cfg.build("On")

		res := make([]parityResult, len(reqs))
		jobs := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < runtime.GOMAXPROCS(0); w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					res[i] = parityCompareOne(off, on, parityIP(ci, i, 0), parityIP(ci, i, 1), reqs[i], i%2 == 0)
				}
			}()
		}
		started := time.Now()
		for i := range reqs {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		parityClose(off)
		parityClose(on)

		text, ok := parityReport(cfg.name, reqs, res)
		allOK = allOK && ok
		fmt.Fprintf(&report, "%s   (wall time %s)\n\n", text, time.Since(started).Round(time.Second))
		t.Logf("\n%s", text)
		if !ok {
			t.Errorf("%s: prefilter off and on disagree", cfg.name)
		}
	}
	if path := os.Getenv("CORAZA_RX_PARITY_REPORT"); path != "" {
		if err := os.WriteFile(path, []byte(report.String()), 0o600); err != nil {
			t.Errorf("writing %s: %v", path, err)
		}
	}
	if allOK {
		t.Logf("PARITY OK: SecRxPreFilter Off and On agree on every request of every configuration")
	}
}
