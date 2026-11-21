// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"sort"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
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

// mask replaces every byte of s with an asterisk, keeping its length.
func mask(s string) string {
	return strings.Repeat("*", len(s))
}

// sanitiseURLEncoded masks the raw value of every pair whose decoded name is
// sanitised and returns the masked string together with the raw values it
// masked. Pair order, separators and encoding of the other pairs are kept.
func sanitiseURLEncoded(s string, separator byte, sanitised map[string]struct{}) (string, []string) {
	if s == "" || len(sanitised) == 0 {
		return s, nil
	}
	var (
		b      strings.Builder
		masked []string
	)
	b.Grow(len(s))
	for i, pair := range strings.Split(s, string(separator)) {
		if i > 0 {
			b.WriteByte(separator)
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
func sanitiseURI(uri string, separator byte, sanitised map[string]struct{}) (string, []string) {
	q := strings.IndexByte(uri, '?')
	if q < 0 {
		return uri, nil
	}
	query, rawValues := sanitiseURLEncoded(uri[q+1:], separator, sanitised)
	return uri[:q+1] + query, rawValues
}

// auditLogRedactor applies the transaction's sanitise* requests to the data
// copied into the audit log record.
type auditLogRedactor struct {
	tx        *Transaction
	separator byte
	// secrets are the values of every sanitised argument and header, decoded and
	// raw, longest first. They are masked wherever they reach the record in
	// free text: rule messages, log data, matched values and error messages.
	secrets []string
}

// newAuditLogRedactor returns nil when no sanitise* action ran, so the common
// path builds the audit log exactly as before.
func (tx *Transaction) newAuditLogRedactor() *auditLogRedactor {
	if tx.sanitise.isEmpty() {
		return nil
	}
	r := &auditLogRedactor{tx: tx, separator: '&'}
	if sep := tx.WAF.ArgumentSeparator; sep != "" {
		r.separator = sep[0]
	}

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
		_, raw := sanitiseURI(tx.variables.requestURI.Get(), r.separator, tx.sanitise.args)
		for _, v := range raw {
			add(v)
		}
		if body, ok := r.urlencodedBody(); ok {
			_, raw = sanitiseURLEncoded(body, r.separator, tx.sanitise.args)
			for _, v := range raw {
				add(v)
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

	sort.SliceStable(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
	return r
}

// urlencodedBody returns the buffered request body when it was parsed as
// application/x-www-form-urlencoded.
func (r *auditLogRedactor) urlencodedBody() (string, bool) {
	if r.tx.variables.reqbodyProcessor.Get() != "URLENCODED" {
		return "", false
	}
	body, err := r.tx.readRequestBodyForAuditLog()
	if err != nil {
		return "", false
	}
	return body, true
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
	masked, _ := sanitiseURI(uri, r.separator, r.tx.sanitise.args)
	return masked
}

// requestBody masks sanitised arguments of a url-encoded body by position. Other
// body formats have no positional parser here, so their sanitised values are
// masked wherever they occur, which over-masks rather than leaks.
func (r *auditLogRedactor) requestBody(body string) string {
	if r.tx.variables.reqbodyProcessor.Get() == "URLENCODED" {
		masked, _ := sanitiseURLEncoded(body, r.separator, r.tx.sanitise.args)
		return masked
	}
	return r.maskSecrets(body)
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
