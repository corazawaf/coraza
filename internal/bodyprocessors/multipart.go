// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/environment"
)

type multipartBodyProcessor struct{}

func (mbp *multipartBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	mimeType := options.Mime
	storagePath := options.StoragePath
	mediaType, params, err := mime.ParseMediaType(mimeType)
	if err != nil {
		v.MultipartStrictError().(*collections.Single).Set("1")
		return err
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return errors.New("not a multipart body")
	}
	mr := multipart.NewReader(reader, params["boundary"])
	totalSize := int64(0)
	filesCol := v.Files()
	filesTmpNamesCol := v.FilesTmpNames()
	fileSizesCol := v.FilesSizes()
	postCol := v.ArgsPost()
	filesCombinedSizeCol := v.FilesCombinedSize()
	filesNamesCol := v.FilesNames()
	headersNames := v.MultipartPartHeaders()
	multipartFilenameCol := v.MultipartFilename()
	multipartFilenameCharsetCol := v.MultipartFilenameCharset()
	multipartFilenameLanguageCol := v.MultipartFilenameLanguage()
	multipartNameCol := v.MultipartName()
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			v.MultipartStrictError().(*collections.Single).Set("1")
			return err
		}
		partName := p.FormName()
		duplicateHeader := false
		for key, values := range p.Header {
			if len(values) > 1 {
				duplicateHeader = true
			}
			for _, value := range values {
				headersNames.Add(partName, fmt.Sprintf("%s: %s", key, value))
			}
		}
		fields := originFileName(p)
		if duplicateHeader || fields.duplicateParam {
			v.MultipartDuplicatePartHeader().(*collections.Single).Set("1")
		}
		if fields.invalidQuoting {
			v.MultipartInvalidQuoting().(*collections.Single).Set("1")
		}
		if duplicateHeader || fields.duplicateParam || fields.malformed || fields.invalidQuoting {
			v.MultipartStrictError().(*collections.Single).Set("1")
		}
		// Add, not Set: distinct parts sharing one "name" (e.g. a multi-file
		// input) must each keep their own filename visible to rules. Set
		// would let the last part silently overwrite the ones before it,
		// the same class of bypass this advisory already covers -- see
		// ModSecurity's GHSA-5pww-8rfg-9crf, which names this "a second,
		// distinct bypass" fixed by keeping MULTIPART_FILENAME/_NAME as
		// multi-valued collections rather than single overwritable slots.
		multipartNameCol.Add(partName, partName)
		if fields.filename != "" {
			multipartFilenameCol.Add(partName, fields.filename)
		}
		// altFilename is the reading a backend using different filename*
		// precedence than Coraza would resolve instead: added alongside the
		// primary one rather than picking a side, so a rule matches whichever
		// name is actually used downstream.
		if fields.altFilename != "" {
			multipartFilenameCol.Add(partName, fields.altFilename)
		}
		if fields.hasExtended {
			multipartFilenameCharsetCol.Add(partName, fields.charset)
			multipartFilenameLanguageCol.Add(partName, fields.language)
		}
		// if is a file
		filename := fields.filename
		if filename == "" {
			// An extended "filename*" that decodes to the empty string (e.g.
			// filename*=utf-8'') would otherwise misclassify the part as a
			// field even though a non-empty plain "filename" is present --
			// PHP, Go mime/multipart, python-multipart and formidable all
			// still resolve it as a file. See GHSA-3wr7-993q-jrff review.
			filename = fields.altFilename
		}
		if filename != "" {
			var size int64
			seenUnexpectedEOF := false
			if environment.HasAccessToFS {
				// Only copy file to temp when not running in TinyGo
				temp, err := os.CreateTemp(storagePath, "crzmp*")
				if err != nil {
					v.MultipartStrictError().(*collections.Single).Set("1")
					return err
				}
				sz, err := io.Copy(temp, p)
				if cerr := temp.Close(); cerr != nil && err == nil {
					err = cerr
				}
				// Record the temp file before checking the copy/close error: it is
				// already on disk at this point on every path, and only a name in
				// FILES_TMPNAMES gets cleaned up when the transaction closes.
				filesTmpNamesCol.Add("", temp.Name())
				if err != nil {
					if !errors.Is(err, io.ErrUnexpectedEOF) {
						v.MultipartStrictError().(*collections.Single).Set("1")
						return err
					}
					flagUnexpectedEOF(v, options.RequestBodyTruncated)
					seenUnexpectedEOF = true
				}
				size = sz
			} else {
				sz, err := io.Copy(io.Discard, p)
				if err != nil {
					if !errors.Is(err, io.ErrUnexpectedEOF) {
						v.MultipartStrictError().(*collections.Single).Set("1")
						return err
					}
					flagUnexpectedEOF(v, options.RequestBodyTruncated)
					seenUnexpectedEOF = true
				}
				size = sz
			}
			totalSize += size
			filesCol.Add("", filename)
			fileSizesCol.SetIndex(filename, 0, fmt.Sprintf("%d", size))
			if fields.altFilename != "" && fields.altFilename != filename {
				// Same part, same bytes, same size -- just a second name a
				// differently-implemented backend might resolve instead.
				// (Skipped when equal to filename: that happens when
				// fields.filename was empty and altFilename was already
				// promoted to primary above -- not two distinct readings.)
				filesCol.Add("", fields.altFilename)
				fileSizesCol.SetIndex(fields.altFilename, 0, fmt.Sprintf("%d", size))
			}
			filesNamesCol.Add("", p.FormName())
			filesCombinedSizeCol.(*collections.Single).Set(fmt.Sprintf("%d", totalSize))
			if seenUnexpectedEOF {
				break
			}
		} else {
			// if is a field
			data, err := io.ReadAll(p)
			if err != nil {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					v.MultipartStrictError().(*collections.Single).Set("1")
					return err
				}
				flagUnexpectedEOF(v, options.RequestBodyTruncated)
			}
			totalSize += int64(len(data))
			postCol.Add(p.FormName(), string(data))
			filesCombinedSizeCol.(*collections.Single).Set(fmt.Sprintf("%d", totalSize))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
		}
	}
	return nil
}

// flagUnexpectedEOF records that a part ended mid-content (io.ErrUnexpectedEOF)
// by setting MULTIPART_STRICT_ERROR, unless ProcessPartial cut the request body
// at SecRequestBodyLimit and dropped the bytes after it. A body that arrives
// truncated is a parser-disagreement risk and must fail rule 200003, but a body
// the WAF truncated itself is not: the backend still receives it in full, and
// ProcessPartial already accepts that the bytes past the limit go uninspected.
// Flagging it would make rule 200003 reject most oversized multipart bodies,
// since a limit set in bytes usually lands inside a part's content.
// INBOUND_DATA_ERROR is not enough to tell the two apart: it is also set by a
// body that ends exactly at the limit, with nothing dropped.
func flagUnexpectedEOF(v plugintypes.TransactionVariables, truncated bool) {
	if truncated {
		return
	}
	v.MultipartStrictError().(*collections.Single).Set("1")
}

func (mbp *multipartBodyProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

var (
	_ plugintypes.BodyProcessor = (*multipartBodyProcessor)(nil)
)

// filenameFields holds the effective filename of a multipart Part, plus the
// RFC 5987 charset/language its Content-Disposition "filename*" parameter
// declared, if any (both empty when the part has no "filename*").
type filenameFields struct {
	filename string
	// altFilename is the plain "filename" parameter's value when a
	// well-formed "filename*" was also present and picked a different value.
	// A rule-visible backend may resolve either reading depending on its own
	// parser, so both are surfaced (see originFileName) rather than the
	// engine silently discarding one. Empty when there is only one reading.
	altFilename string
	charset     string
	language    string
	// hasExtended reports whether a well-formed "filename*" parameter was
	// found, independent of whether charset/language themselves are empty
	// (language is optional and legitimately blank even when present).
	hasExtended bool
	// malformed reports that a Content-Disposition header was present but
	// could not be parsed, or carried a "filename*" that did not match the
	// RFC 5987 "charset'[language]'value" shape at all. The part is still
	// processed with whatever plain "filename" could be recovered; the flag
	// exists so the caller can raise MULTIPART_STRICT_ERROR rather than
	// dropping the discrepancy silently.
	malformed bool
	// duplicateParam reports that a parameter name appeared more than once
	// in the Content-Disposition header (e.g. two "filename" parameters).
	duplicateParam bool
	// invalidQuoting reports that "filename*" was wrapped in a quoted-string,
	// which RFC 5987 does not permit for ext-value. The value is still
	// unwrapped and used (see originFileName) rather than dropped, but the
	// flag lets the caller raise MULTIPART_INVALID_QUOTING/STRICT_ERROR for
	// the discrepancy.
	invalidQuoting bool
}

// originFileName returns the effective filename of the Part's
// Content-Disposition header, together with the charset/language declared by
// an RFC 5987 extended "filename*" parameter, if present.
//
// This intentionally does not rely on mime.ParseMediaType's own handling of
// "filename*": the stdlib only decodes it when the declared charset is
// exactly "us-ascii" or "utf-8" (mime/mediatype.go's decode2231Enc), silently
// leaving any other charset -- including "iso-8859-1", which RFC 5987
// explicitly permits -- undecoded, with no error and no way for a caller to
// detect it happened. That let an attacker present a decoy plain "filename"
// to Coraza while the real filename, carried in "filename*" under an
// unrecognized charset, reached the backend untouched. See
// GHSA-3wr7-993q-jrff.
//
// mime.ParseMediaType is still used for overall header validation (rejecting
// malformed headers and conflicting duplicate parameters); findFilenameStar
// independently locates "filename*" in the same raw header text to extract
// its charset/language/value without that restriction. Per RFC 7578 section
// 4.2, when both are present "filename*" is authoritative over "filename" for
// the primary filename field -- but a backend that itself does not implement
// that precedence (or implements it differently) may resolve the plain
// "filename" instead, so the discarded reading is returned as altFilename
// rather than dropped: the caller adds both to FILES/MULTIPART_FILENAME so a
// rule catches either interpretation.
//
// The charset and language are exposed as-is (not validated against the RFC
// 5987 grammar, and not used to transcode the filename -- it is always the
// raw percent-decoded bytes). A malformed "filename*" (not matching the
// "charset'[language]'value" shape at all) falls back to the plain "filename"
// parameter with empty charset/language, and reports itself through the
// malformed field so the discrepancy is still visible to rules.
func originFileName(p *multipart.Part) filenameFields {
	cd := p.Header.Get("Content-Disposition")
	var f filenameFields

	_, dispositionParams, err := mime.ParseMediaType(cd)
	if err != nil {
		// A part with no Content-Disposition at all simply carries no
		// filename; only a header that is present but unparseable is a
		// discrepancy worth surfacing.
		if cd != "" {
			f.malformed = true
			f.duplicateParam = hasDuplicateParam(cd)
		}
		return f
	}
	plainFilename := dispositionParams["filename"]
	f.filename = plainFilename

	raw, ok := findFilenameStar(cd)
	if !ok {
		if hasFilenameContinuation(cd) {
			// An RFC 2231 numbered continuation ("filename*0=", "filename*0*=",
			// ...) is not reassembled and decoded here -- a form real browsers
			// never emit, resolved by only a minority of backends (e.g.
			// Werkzeug/Flask). mime.ParseMediaType partially handles a single
			// continuation piece itself, blanking or silently overwriting
			// dispositionParams["filename"] with the continuation's own
			// (possibly still-encoded) value -- reliably for a utf-8/us-ascii
			// continuation, but unreliably otherwise (see the bare "filename*"
			// handling above). Neither reading is dropped: "filename" is
			// reparsed directly from the raw header as the primary value, and
			// plainFilename (mime.ParseMediaType's own, possibly
			// continuation-resolved reading) is kept as altFilename when it
			// differs, so a rule matches whichever one a given backend
			// actually resolves -- the same "don't pick a side" principle
			// already applied to the bare "filename*" case. malformed is still
			// set so MULTIPART_STRICT_ERROR fires: Coraza does not reassemble
			// or decode the continuation itself, so its own resolved value may
			// still disagree with a backend that does. See GHSA-3wr7-993q-jrff
			// review.
			f.malformed = true
			if rawPlain, pok := findParam(cd, "filename"); pok {
				if unquoted, wasQuoted := unquoteIfQuoted(rawPlain); wasQuoted {
					rawPlain = unquoted
				}
				f.filename = rawPlain
				if plainFilename != "" && plainFilename != rawPlain {
					f.altFilename = plainFilename
				}
			}
		}
		return f
	}
	// RFC 5987 does not permit ext-value to be a quoted-string, but a
	// general Content-Disposition parameter parser -- Go's mime.ParseMediaType
	// included -- accepts a quoted-string for any parameter, filename*
	// included. Matching that keeps Coraza's parsed value the same as what
	// the backend resolves; without it, the literal quote characters end up
	// inside the filename and charset, breaking anchored rules. See
	// GHSA-3wr7-993q-jrff. The quoting is still invalid RFC 5987, though, so
	// it is surfaced via MULTIPART_INVALID_QUOTING rather than accepted
	// silently -- ModSecurity's equivalent parser rejects a quoted filename*
	// outright rather than normalizing it.
	if unquoted, wasQuoted := unquoteIfQuoted(raw); wasQuoted {
		raw = unquoted
		f.invalidQuoting = true
	}
	parts := strings.SplitN(raw, "'", 3)
	if len(parts) != 3 {
		f.malformed = true
		return f
	}
	filename, invalidEscape := percentDecodeLenient(parts[2])
	f.filename = filename
	f.charset, f.language, f.hasExtended = parts[0], parts[1], true
	// plainFilename (from dispositionParams) cannot be trusted for the
	// altFilename comparison: mime.ParseMediaType decodes "filename*" itself
	// for utf-8/us-ascii charsets and overwrites the "filename" map entry
	// with that same decoded value, so plainFilename may already equal
	// filename rather than reflect what the plain "filename" parameter
	// actually said. Parse it independently, the same way filename* already
	// is, instead of relying on the stdlib's own precedence handling.
	if rawPlain, ok := findParam(cd, "filename"); ok {
		if unquoted, wasQuoted := unquoteIfQuoted(rawPlain); wasQuoted {
			rawPlain = unquoted
		}
		if rawPlain != "" && rawPlain != filename {
			f.altFilename = rawPlain
		}
	}
	// An unresolvable "%" escape leaves the raw bytes in place (see
	// percentDecodeLenient) rather than falling back to a decoy plain
	// filename, but it must still raise MULTIPART_STRICT_ERROR: a backend
	// decoding the same escape differently (or rejecting it outright, as
	// ModSecurity's GHSA-5pww-8rfg-9crf fix does) is exactly the kind of
	// discrepancy this advisory exists to surface.
	if invalidEscape {
		f.malformed = true
	}
	return f
}

// unquoteIfQuoted strips a surrounding RFC 2045 quoted-string from s,
// unescaping any backslash-escaped character, and reports whether s was
// quoted at all. s is returned unchanged with ok=false when it is not a
// quoted-string (no surrounding double quotes).
func unquoteIfQuoted(s string) (unquoted string, ok bool) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s, false
	}
	inner := s[1 : len(s)-1]
	var buf strings.Builder
	buf.Grow(len(inner))
	for i := 0; i < len(inner); i++ {
		if inner[i] == '\\' && i+1 < len(inner) {
			i++
		}
		buf.WriteByte(inner[i])
	}
	return buf.String(), true
}

// findFilenameStar scans a Content-Disposition-style parameter list for a
// "filename*" parameter and returns its raw (still percent-encoded) value.
func findFilenameStar(s string) (rawValue string, ok bool) {
	return findParam(s, "filename*")
}

// hasFilenameContinuation reports whether s declares an RFC 2231 numbered
// continuation of "filename" -- a parameter named "filename*N" or
// "filename*N*" for some decimal N (e.g. "filename*0=", "filename*1*=") --
// as distinct from the bare "filename*" extended parameter itself.
func hasFilenameContinuation(s string) bool {
	found := false
	forEachParam(s, func(seg string) bool {
		key, _, ok := strings.Cut(seg, "=")
		if !ok {
			return true
		}
		key = strings.TrimSuffix(strings.TrimSpace(key), "*")
		digits, ok := strings.CutPrefix(strings.ToLower(key), "filename*")
		if !ok || digits == "" {
			return true
		}
		for _, c := range digits {
			if c < '0' || c > '9' {
				return true
			}
		}
		found = true
		return false
	})
	return found
}

// findParam scans a Content-Disposition-style parameter list for a parameter
// named key (case-insensitive) and returns its raw value, honoring
// quoted-string boundaries so that a ';' or the substring "key=" appearing
// inside another parameter's quoted value (e.g. a crafted plain "filename")
// is never mistaken for a parameter separator or name.
func findParam(s, key string) (rawValue string, ok bool) {
	forEachParam(s, func(seg string) bool {
		k, value, found := strings.Cut(seg, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(k), key) {
			return true
		}
		rawValue, ok = strings.TrimSpace(value), true
		return false
	})
	return rawValue, ok
}

// hasDuplicateParam reports whether a parameter name occurs more than once in
// a Content-Disposition-style parameter list. It is only consulted once
// mime.ParseMediaType has already rejected the header -- the stdlib treats a
// repeated parameter name as a parse error -- so its allocation stays off the
// path taken by well-formed parts.
func hasDuplicateParam(s string) bool {
	var seen []string
	duplicate := false
	forEachParam(s, func(seg string) bool {
		key, _, found := strings.Cut(seg, "=")
		if !found {
			return true
		}
		key = strings.ToLower(strings.TrimSpace(key))
		for _, k := range seen {
			if k == key {
				duplicate = true
				return false
			}
		}
		seen = append(seen, key)
		return true
	})
	return duplicate
}

// forEachParam walks a Content-Disposition-style parameter list, calling fn
// with each "name=value" segment, and stops early when fn returns false.
func forEachParam(s string, fn func(seg string) bool) {
	inQuotes := false
	segStart := 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && inQuotes:
			i++ // an escaped character inside a quoted-string is never a boundary
		case s[i] == '"':
			inQuotes = !inQuotes
		case s[i] == ';' && !inQuotes:
			if !fn(s[segStart:i]) {
				return
			}
			segStart = i + 1
		}
	}
	fn(s[segStart:])
}

// percentDecodeLenient percent-decodes %XX escapes in s. A '%' not followed
// by two valid hex digits is left untouched rather than rejecting the whole
// value: this feeds a rule-matching string, not a filesystem path, so making
// a malformed escape visible as-is is preferable to hiding it behind an
// error and falling back to a possibly attacker-controlled decoy filename.
// invalidEscape reports whether such an unresolvable "%" was found, so the
// caller can still raise MULTIPART_STRICT_ERROR for the discrepancy.
func percentDecodeLenient(s string) (decoded string, invalidEscape bool) {
	if !strings.Contains(s, "%") {
		return s, false
	}
	var buf strings.Builder
	buf.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok := fromHex(s[i+1]); ok {
				if lo, ok := fromHex(s[i+2]); ok {
					buf.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		buf.WriteByte(s[i])
		if s[i] == '%' {
			invalidEscape = true
		}
	}
	return buf.String(), invalidEscape
}

func fromHex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func init() {
	RegisterBodyProcessor("multipart", func() plugintypes.BodyProcessor {
		return &multipartBodyProcessor{}
	})
}
