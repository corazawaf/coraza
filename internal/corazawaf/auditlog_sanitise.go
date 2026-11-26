// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"sort"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/url"
	"github.com/corazawaf/coraza/v3/internal/variables"
	"github.com/corazawaf/coraza/v3/types"
)

// auditLogSanitise holds what the sanitise* actions asked to mask in the audit
// log. Names are stored lowercased: as in ModSecurity v2, sanitiseArg compares
// argument names case-insensitively, and header names are case-insensitive.
// The inspected data is never changed; masking only happens when the audit log
// record is built.
type auditLogSanitise struct {
	args            map[string]struct{}
	requestHeaders  map[string]struct{}
	responseHeaders map[string]struct{}
}

func (s *auditLogSanitise) isEmpty() bool {
	return len(s.args) == 0 && len(s.requestHeaders) == 0 && len(s.responseHeaders) == 0
}

func addName(m *map[string]struct{}, name string) {
	if name == "" {
		return
	}
	if *m == nil {
		*m = map[string]struct{}{}
	}
	(*m)[strings.ToLower(name)] = struct{}{}
}

func hasName(m map[string]struct{}, name string) bool {
	_, ok := m[strings.ToLower(name)]
	return ok
}

// SanitiseArg masks every value of the named request argument in the audit log.
func (tx *Transaction) SanitiseArg(name string) {
	addName(&tx.sanitise.args, name)
}

// SanitiseRequestHeader masks the named request header in the audit log.
func (tx *Transaction) SanitiseRequestHeader(name string) {
	addName(&tx.sanitise.requestHeaders, name)
}

// SanitiseResponseHeader masks the named response header in the audit log.
func (tx *Transaction) SanitiseResponseHeader(name string) {
	addName(&tx.sanitise.responseHeaders, name)
}

// SanitiseMatched masks the argument, request header or response header that
// matched last. It reports false when the matched variable is none of these,
// which ModSecurity v2 also ignores.
func (tx *Transaction) SanitiseMatched() bool {
	key := tx.lastMatchedKey
	if key == "" {
		return false
	}
	switch tx.lastMatchedVariable {
	case variables.Args, variables.ArgsGet, variables.ArgsPost, variables.ArgsPath,
		variables.ArgsNames, variables.ArgsGetNames, variables.ArgsPostNames:
		tx.SanitiseArg(key)
	case variables.RequestHeaders, variables.RequestHeadersNames:
		tx.SanitiseRequestHeader(key)
	case variables.ResponseHeaders, variables.ResponseHeadersNames:
		tx.SanitiseResponseHeader(key)
	default:
		return false
	}
	return true
}

// argSeparator is the separator ExtractGetArguments and the url-encoded body
// processor split on. Masking has to split pairs the same way they do, or a
// pair they parsed is not found here.
const argSeparator = '&'

// mask replaces every byte of s with an asterisk, keeping its length.
func mask(s string) string {
	return strings.Repeat("*", len(s))
}

// sanitiseURLEncoded masks the raw value of every pair whose decoded name is
// sanitised and returns the masked string together with the raw values it
// masked. Pair order, separators and encoding of the other pairs are kept.
func sanitiseURLEncoded(s string, sanitised map[string]struct{}) (string, []string) {
	if s == "" || len(sanitised) == 0 {
		return s, nil
	}
	var (
		b      strings.Builder
		masked []string
	)
	b.Grow(len(s))
	for i, pair := range strings.Split(s, string(argSeparator)) {
		if i > 0 {
			b.WriteByte(argSeparator)
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 0 || !hasName(sanitised, url.QueryUnescape(pair[:eq])) {
			b.WriteString(pair)
			continue
		}
		value := pair[eq+1:]
		b.WriteString(pair[:eq+1])
		b.WriteString(mask(value))
		if value != "" {
			masked = append(masked, value)
		}
	}
	return b.String(), masked
}

// sanitiseURI masks the sanitised arguments of the query string of uri.
func sanitiseURI(uri string, sanitised map[string]struct{}) (string, []string) {
	q := strings.IndexByte(uri, '?')
	if q < 0 {
		return uri, nil
	}
	query, rawValues := sanitiseURLEncoded(uri[q+1:], sanitised)
	return uri[:q+1] + query, rawValues
}

// sanitisePath masks values in the path of uri and returns the masked uri
// together with the raw text it masked. A segment that decodes to one of the
// values is masked whole, however it is encoded. A value that is only part of
// a segment, or spans several, is masked where it appears literally.
func sanitisePath(uri string, values []string) (string, []string) {
	if len(values) == 0 {
		return uri, nil
	}
	path, rest := uri, ""
	if q := strings.IndexByte(uri, '?'); q >= 0 {
		path, rest = uri[:q], uri[q:]
	}
	var masked []string
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment == "" {
			continue
		}
		// A plus sign is literal in a path, unlike in a query string.
		decoded := url.QueryUnescape(strings.ReplaceAll(segment, "+", "%2B"))
		for _, v := range values {
			if decoded == v {
				masked = append(masked, segment)
				segments[i] = mask(segment)
				break
			}
		}
	}
	path = strings.Join(segments, "/")
	for _, v := range values {
		if strings.Contains(path, v) {
			path = strings.ReplaceAll(path, v, mask(v))
		}
	}
	return path + rest, masked
}

// auditLogRedactor applies the transaction's sanitise* requests to the data
// copied into the audit log record.
type auditLogRedactor struct {
	tx *Transaction
	// secrets are the values of every sanitised argument and header, decoded,
	// raw and as transformed by the rules that matched them, longest first.
	// They are masked wherever they reach the record in free text: rule
	// messages, log data, matched values and error messages.
	secrets []string
	// pathValues are the values of the sanitised ARGS_PATH arguments, longest
	// first. Only the integration knows where they sit in the path, so they
	// are looked for in it.
	pathValues []string
	// body is the request body as it goes to the record, and bodyErr the error
	// of reading it. The body is read once, so what is logged is what was
	// masked.
	body     string
	bodyErr  error
	bodyDone bool
}

// newAuditLogRedactor returns nil when no sanitise* action ran, so the common
// path builds the audit log exactly as before.
func (tx *Transaction) newAuditLogRedactor() *auditLogRedactor {
	if tx.sanitise.isEmpty() {
		return nil
	}
	r := &auditLogRedactor{tx: tx}

	seen := map[string]struct{}{}
	add := func(v string) {
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		r.secrets = append(r.secrets, v)
	}

	if len(tx.sanitise.args) > 0 {
		for _, md := range tx.variables.args.FindAll() {
			if hasName(tx.sanitise.args, md.Key()) {
				add(md.Value())
			}
		}
		for _, md := range tx.variables.argsPath.FindAll() {
			if v := md.Value(); v != "" && hasName(tx.sanitise.args, md.Key()) {
				r.pathValues = append(r.pathValues, v)
			}
		}
		sort.SliceStable(r.pathValues, func(i, j int) bool { return len(r.pathValues[i]) > len(r.pathValues[j]) })

		// Raw spellings are masked by position where they were found. They are
		// kept only to be looked for in free text, and a request can carry far
		// more of them than SecArgumentsLimit lets into ARGS, so the same limit
		// applies to them.
		rawLeft := tx.WAF.ArgumentLimit
		addRaw := func(values []string) {
			for _, v := range values {
				if rawLeft <= 0 {
					return
				}
				if _, ok := seen[v]; !ok && v != "" {
					rawLeft--
				}
				add(v)
			}
		}

		uri := tx.variables.requestURI.Get()
		_, raw := sanitiseURI(uri, tx.sanitise.args)
		addRaw(raw)
		_, raw = sanitisePath(uri, r.pathValues)
		addRaw(raw)
		if r.hasPositionalBody() {
			var body string
			body, r.bodyErr = tx.readRequestBodyForAuditLog()
			r.bodyDone = true
			if r.bodyErr == nil {
				r.body, raw = r.sanitiseBody(body)
				addRaw(raw)
			}
		}
	}
	for name := range tx.sanitise.requestHeaders {
		for _, v := range tx.variables.requestHeaders.Get(name) {
			add(v)
		}
	}
	for name := range tx.sanitise.responseHeaders {
		for _, v := range tx.variables.responseHeaders.Get(name) {
			add(v)
		}
	}

	// A rule sees a sanitised value after its transformations, and that is the
	// form its log data carries.
	for _, mr := range tx.matchedRules {
		for _, md := range mr.MatchedDatas() {
			if r.isSanitisedValue(md.Variable(), md.Key()) {
				add(md.Value())
			}
		}
	}

	sort.SliceStable(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
	return r
}

// hasPositionalBody reports whether the request body is in a format whose
// arguments sanitiseBody can locate.
func (r *auditLogRedactor) hasPositionalBody() bool {
	switch r.tx.variables.reqbodyProcessor.Get() {
	case "URLENCODED", "JSON":
		return true
	}
	return false
}

// sanitiseBody masks the sanitised arguments of a url-encoded or JSON body by
// position and returns the masked body together with the raw values it masked.
// A JSON body that cannot be walked to its end is masked whole, since the part
// that was not seen may hold a sanitised value.
func (r *auditLogRedactor) sanitiseBody(body string) (string, []string) {
	switch r.tx.variables.reqbodyProcessor.Get() {
	case "URLENCODED":
		return sanitiseURLEncoded(body, r.tx.sanitise.args)
	case "JSON":
		masked, raw, complete := bodyprocessors.MaskJSONValues(body, r.tx.WAF.RequestBodyJsonDepthLimit, func(key string) bool {
			return hasName(r.tx.sanitise.args, key)
		})
		if !complete {
			return mask(body), raw
		}
		return masked, raw
	}
	return body, nil
}

// maskSecrets masks every occurrence of a sanitised value in free text.
func (r *auditLogRedactor) maskSecrets(s string) string {
	for _, secret := range r.secrets {
		if strings.Contains(s, secret) {
			s = strings.ReplaceAll(s, secret, mask(secret))
		}
	}
	return s
}

func (r *auditLogRedactor) uri(uri string) string {
	masked, _ := sanitiseURI(uri, r.tx.sanitise.args)
	masked, _ = sanitisePath(masked, r.pathValues)
	return masked
}

// requestBody returns the request body for the record. A url-encoded or JSON
// body was masked by position when the redactor was built. Any other body has
// its sanitised values masked wherever they occur, which over-masks rather
// than leaks.
func (r *auditLogRedactor) requestBody() (string, error) {
	if !r.bodyDone {
		r.bodyDone = true
		r.body, r.bodyErr = r.tx.readRequestBodyForAuditLog()
		if r.bodyErr == nil && !r.hasPositionalBody() {
			r.body = r.maskSecrets(r.body)
		}
	}
	return r.body, r.bodyErr
}

// headers masks the sanitised entries of a header copy in place. Keys of the
// copy are already lowercased by the collection.
func (r *auditLogRedactor) headers(h map[string][]string, sanitised map[string]struct{}) map[string][]string {
	for name, values := range h {
		if !hasName(sanitised, name) {
			continue
		}
		for i, v := range values {
			values[i] = mask(v)
		}
	}
	return h
}

// args returns a copy of ARGS with sanitised values masked, so the formatters
// that serialise the collection never see the original values.
func (r *auditLogRedactor) args() *collections.ConcatKeyed {
	if len(r.tx.sanitise.args) == 0 {
		return r.tx.variables.args
	}
	cp := func(src *collections.NamedCollection, v variables.RuleVariable) collection.Keyed {
		dst := collections.NewCaseSensitiveNamedCollection(v)
		for _, md := range src.FindAll() {
			value := md.Value()
			if hasName(r.tx.sanitise.args, md.Key()) {
				value = mask(value)
			}
			dst.Add(md.Key(), value)
		}
		return dst
	}
	return collections.NewConcatKeyed(
		variables.Args,
		cp(r.tx.variables.argsGet, variables.ArgsGet),
		cp(r.tx.variables.argsPost, variables.ArgsPost),
		cp(r.tx.variables.argsPath, variables.ArgsPath),
	)
}

// matchedRule returns a copy of mr whose URI, matched values, messages and log
// data are masked. The copy produces the masked error message as well, since
// the error message is built from those fields.
func (r *auditLogRedactor) matchedRule(mr *corazarules.MatchedRule) *corazarules.MatchedRule {
	cp := *mr
	cp.URI_ = r.uri(mr.URI_)
	cp.MatchedDatas_ = make([]types.MatchData, len(mr.MatchedDatas_))
	for i, md := range mr.MatchedDatas_ {
		data, ok := md.(*corazarules.MatchData)
		if !ok {
			cp.MatchedDatas_[i] = md
			continue
		}
		mdCopy := *data
		if r.isSanitisedValue(data.Variable_, data.Key_) {
			mdCopy.Value_ = mask(data.Value_)
		} else {
			mdCopy.Value_ = r.maskSecrets(data.Value_)
		}
		mdCopy.Message_ = r.maskSecrets(data.Message_)
		mdCopy.Data_ = r.maskSecrets(data.Data_)
		cp.MatchedDatas_[i] = &mdCopy
	}
	return &cp
}

// isSanitisedValue reports whether a matched value is itself the value of a
// sanitised argument or header. Matches on *_NAMES variables carry the name,
// which is not masked.
func (r *auditLogRedactor) isSanitisedValue(v variables.RuleVariable, key string) bool {
	switch v {
	case variables.Args, variables.ArgsGet, variables.ArgsPost, variables.ArgsPath:
		return hasName(r.tx.sanitise.args, key)
	case variables.RequestHeaders:
		return hasName(r.tx.sanitise.requestHeaders, key)
	case variables.ResponseHeaders:
		return hasName(r.tx.sanitise.responseHeaders, key)
	}
	return false
}
