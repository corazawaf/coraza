// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/environment"
)

type multipartBodyProcessor struct{}

func (mbp *multipartBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return mbp.processRequest(reader, v, options, 0)
}

// ProcessMultipartWithNoFilesLimit keeps the accounting contract internal to
// the built-in parser. A registered replacement processor is never treated as
// file-aware by the transaction.
func ProcessMultipartWithNoFilesLimit(processor plugintypes.BodyProcessor, reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions, limit int64) (bool, error) {
	if builtin, ok := processor.(*multipartBodyProcessor); ok {
		return true, builtin.processRequest(reader, v, options, limit)
	}
	return false, nil
}

// IsBuiltInMultipart reports whether processor has the built-in file
// accounting behavior. Custom processors receive the ordinary body limit.
func IsBuiltInMultipart(processor plugintypes.BodyProcessor) bool {
	_, ok := processor.(*multipartBodyProcessor)
	return ok
}

// ErrNoFilesLimit reports that multipart non-file data exceeded its budget.
var ErrNoFilesLimit = errors.New("request body exceeds SecRequestBodyNoFilesLimit")

type multipartPartAccountingReader struct {
	reader io.Reader
	raw    int64
	count  func(int64) error
}

func (r *multipartPartAccountingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.raw += int64(n)
	if r.count != nil {
		if accountingErr := r.count(int64(n)); accountingErr != nil {
			return n, accountingErr
		}
	}
	return n, err
}

func addMultipartCount(counted *int64, limit, size int64) error {
	if size < 0 || *counted > math.MaxInt64-size {
		return errors.New("invalid multipart accounting state")
	}
	*counted += size
	if *counted > limit {
		return ErrNoFilesLimit
	}
	return nil
}

// multipartHeaderSize counts the normalized representation parsed by
// mime/multipart: each field line plus the terminating blank line. Using the
// parsed header keeps boundary and header recognition in one parser.
func multipartHeaderSize(header textproto.MIMEHeader) (int64, error) {
	size := int64(2)
	for key, values := range header {
		for _, value := range values {
			for _, partSize := range []int{len(key), len(": "), len(value), len("\r\n")} {
				if size > math.MaxInt64-int64(partSize) {
					return 0, errors.New("invalid multipart header size")
				}
				size += int64(partSize)
			}
		}
	}
	return size, nil
}

func (mbp *multipartBodyProcessor) processRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions, noFilesLimit int64) error {
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
	limited := noFilesLimit > 0
	var noFilesSize int64
	mr := multipart.NewReader(reader, params["boundary"])
	totalSize := int64(0)
	type pendingUpdate struct {
		collection collection.Map
		key, value string
		setIndex   bool
	}
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
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		// A body cut by SecRequestBodyLimit under ProcessPartial can also end
		// inside a boundary line, where NextPart wraps io.EOF: that is the end
		// of what was buffered, not a malformed body (see flagUnexpectedEOF).
		// Other errors, like a malformed part header, are flagged even then:
		// parsing stops there, so the rest of the body would go uninspected.
		if errors.Is(err, io.EOF) && v.InboundDataError().Get() == "1" {
			break
		}
		if err != nil {
			if errors.Is(err, ErrNoFilesLimit) {
				return err
			}
			v.MultipartStrictError().(*collections.Single).Set("1")
			return err
		}
		if limited {
			headerSize, err := multipartHeaderSize(p.Header)
			if err != nil {
				return err
			}
			if err := addMultipartCount(&noFilesSize, noFilesLimit, headerSize); err != nil {
				return err
			}
		}
		quotedPrintable := strings.EqualFold(p.Header.Get("Content-Transfer-Encoding"), "quoted-printable")
		if quotedPrintable {
			// NextPart hides this header and transparently decodes the part.
			p.Header.Del("Content-Transfer-Encoding")
		}
		var pending []pendingUpdate
		add := func(col collection.Map, key, value string) {
			if !limited {
				col.Add(key, value)
			} else {
				pending = append(pending, pendingUpdate{collection: col, key: key, value: value})
			}
		}
		setIndex := func(col collection.Map, key, value string) {
			if !limited {
				col.SetIndex(key, 0, value)
			} else {
				pending = append(pending, pendingUpdate{collection: col, key: key, value: value, setIndex: true})
			}
		}
		commit := func() {
			for _, update := range pending {
				if update.setIndex {
					update.collection.SetIndex(update.key, 0, update.value)
				} else {
					update.collection.Add(update.key, update.value)
				}
			}
		}
		commitNonLimitError := func(err error) error {
			if err != nil && !errors.Is(err, ErrNoFilesLimit) {
				commit()
			}
			return err
		}
		partName := p.FormName()
		duplicateHeader := false
		for key, values := range p.Header {
			if len(values) > 1 {
				duplicateHeader = true
			}
			for _, value := range values {
				add(headersNames, partName, fmt.Sprintf("%s: %s", key, value))
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
		add(multipartNameCol, partName, partName)
		if fields.filename != "" {
			add(multipartFilenameCol, partName, fields.filename)
		}
		// altFilename is the reading a backend using different filename*
		// precedence than Coraza would resolve instead: added alongside the
		// primary one rather than picking a side, so a rule matches whichever
		// name is actually used downstream.
		if fields.altFilename != "" {
			add(multipartFilenameCol, partName, fields.altFilename)
		}
		if fields.hasExtended {
			add(multipartFilenameCharsetCol, partName, fields.charset)
			add(multipartFilenameLanguageCol, partName, fields.language)
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
			rawReader := &multipartPartAccountingReader{reader: p}
			partReader := io.Reader(rawReader)
			if quotedPrintable {
				partReader = quotedprintable.NewReader(rawReader)
			}
			if environment.HasAccessToFS {
				// Only copy file to temp when not running in TinyGo
				temp, err := os.CreateTemp(storagePath, "crzmp*")
				if err != nil {
					v.MultipartStrictError().(*collections.Single).Set("1")
					return commitNonLimitError(err)
				}
				var sz int64
				sz, err = io.Copy(temp, partReader)
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
						return commitNonLimitError(err)
					}
					flagUnexpectedEOF(v)
					seenUnexpectedEOF = true
				}
				size = sz
			} else {
				var sz int64
				sz, err = io.Copy(io.Discard, partReader)
				if err != nil {
					if !errors.Is(err, io.ErrUnexpectedEOF) {
						v.MultipartStrictError().(*collections.Single).Set("1")
						return commitNonLimitError(err)
					}
					flagUnexpectedEOF(v)
					seenUnexpectedEOF = true
				}
				size = sz
			}
			totalSize += size
			if seenUnexpectedEOF && limited && v.InboundDataError().Get() != "1" {
				// A truncated file part has no verified closing boundary.
				// Do not exempt its payload as a complete upload.
				if err := addMultipartCount(&noFilesSize, noFilesLimit, rawReader.raw); err != nil {
					return err
				}
			}
			add(filesCol, "", filename)
			setIndex(fileSizesCol, filename, fmt.Sprintf("%d", size))
			if fields.altFilename != "" && fields.altFilename != filename {
				// Same part, same bytes, same size -- just a second name a
				// differently-implemented backend might resolve instead.
				// (Skipped when equal to filename: that happens when
				// fields.filename was empty and altFilename was already
				// promoted to primary above -- not two distinct readings.)
				add(filesCol, "", fields.altFilename)
				setIndex(fileSizesCol, fields.altFilename, fmt.Sprintf("%d", size))
			}
			add(filesNamesCol, "", p.FormName())
			commit()
			filesCombinedSizeCol.(*collections.Single).Set(fmt.Sprintf("%d", totalSize))
			if seenUnexpectedEOF {
				break
			}
		} else {
			// if is a field
			rawReader := &multipartPartAccountingReader{reader: p}
			if limited {
				rawReader.count = func(size int64) error {
					return addMultipartCount(&noFilesSize, noFilesLimit, size)
				}
			}
			fieldReader := io.Reader(rawReader)
			if quotedPrintable {
				fieldReader = quotedprintable.NewReader(rawReader)
			}
			data, err := io.ReadAll(fieldReader)
			if err != nil {
				if errors.Is(err, ErrNoFilesLimit) {
					return err
				}
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					v.MultipartStrictError().(*collections.Single).Set("1")
					return commitNonLimitError(err)
				}
				flagUnexpectedEOF(v)
			}
			totalSize += int64(len(data))
			add(postCol, p.FormName(), string(data))
			commit()
			filesCombinedSizeCol.(*collections.Single).Set(fmt.Sprintf("%d", totalSize))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
		}
	}
	return nil
}

// flagUnexpectedEOF records that a part ended mid-content (io.ErrUnexpectedEOF)
// by setting MULTIPART_STRICT_ERROR, unless the request body was cut by
// SecRequestBodyLimit under ProcessPartial (INBOUND_DATA_ERROR=1). A body
// that arrives truncated is a parser-disagreement risk and must fail rule
// 200003, but a body the WAF truncated itself is not: the backend still receives
// it in full, and ProcessPartial already accepts that the bytes past the limit go uninspected.
// Flagging it would make rule 200003 reject most oversized multipart bodies,
// since a limit set in bytes usually lands inside a part's content.
// INBOUND_DATA_ERROR is also set by a body that ends exactly at the limit with
// nothing cut. That body is not flagged either: telling the two apart would need
// a read past the limit, and would gain nothing, since the same malformed body
// padded by one byte is cut by the limit and not flagged anyway.
func flagUnexpectedEOF(v plugintypes.TransactionVariables) {
	if v.InboundDataError().Get() == "1" {
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
	// A continuation alongside a bare "filename*" is not reassembled either,
	// and Werkzeug/Flask lets the continuation win over both "filename*" and
	// "filename", so the value a backend resolves may be one Coraza never
	// exposes. Flag it the same way as the continuation-only case above.
	if hasFilenameContinuation(cd) {
		f.malformed = true
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
	// A set, not a slice: the header is attacker-controlled and can carry
	// hundreds of thousands of parameters, so a linear scan per key is
	// quadratic CPU.
	seen := map[string]struct{}{}
	duplicate := false
	forEachParam(s, func(seg string) bool {
		key, _, found := strings.Cut(seg, "=")
		if !found {
			return true
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if _, ok := seen[key]; ok {
			duplicate = true
			return false
		}
		seen[key] = struct{}{}
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
