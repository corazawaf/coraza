// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"os"
	"path"
	"slices"
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
	// Attribute values and element contents extracted from every XML file part,
	// merged so that a body carrying more than one XML part does not lose all
	// but the last of them.
	var xmlAttrs, xmlContents []string
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
		for key, values := range p.Header {
			for _, value := range values {
				headersNames.Add(partName, fmt.Sprintf("%s: %s", key, value))
			}
		}
		// if is a file
		filename := originFileName(p)
		if filename != "" {
			seenUnexpectedEOF := false
			// Only copy the file to a temporary one on builds with filesystem
			// access, otherwise the part is drained and only its size is kept.
			dst := io.Discard
			if environment.HasAccessToFS {
				temp, err := os.CreateTemp(storagePath, "crzmp*")
				if err != nil {
					v.MultipartStrictError().(*collections.Single).Set("1")
					return err
				}
				defer temp.Close()
				dst = temp
				filesTmpNamesCol.Add("", temp.Name())
			}
			size, attrs, contents, err := copyFilePart(dst, p, filename, options.MultipartXMLParts)
			if err != nil {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					v.MultipartStrictError().(*collections.Single).Set("1")
					return err
				}
				seenUnexpectedEOF = true
			}
			xmlAttrs = append(xmlAttrs, attrs...)
			xmlContents = append(xmlContents, contents...)
			totalSize += size
			filesCol.Add("", filename)
			fileSizesCol.SetIndex(filename, 0, fmt.Sprintf("%d", size))
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
			}
			totalSize += int64(len(data))
			postCol.Add(p.FormName(), string(data))
			filesCombinedSizeCol.(*collections.Single).Set(fmt.Sprintf("%d", totalSize))
			if errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
		}
	}
	if len(xmlAttrs) > 0 || len(xmlContents) > 0 {
		xmlCol := v.RequestXML()
		xmlCol.Set("//@*", xmlAttrs)
		xmlCol.Set("/*", xmlContents)
	}
	return nil
}

// xmlSniffLen is the number of leading bytes of a file part inspected to decide
// whether it holds XML. It only has to cover an optional BOM, leading whitespace
// and the beginning of an XML declaration.
const xmlSniffLen = 64

var (
	utf8BOM = []byte{0xEF, 0xBB, 0xBF}
	// xmlFileExtensions are the filename extensions treated as XML when the part
	// carries no usable Content-Type.
	xmlFileExtensions = []string{".xml", ".xsd", ".xsl", ".xslt", ".svg", ".xhtml", ".rss", ".atom"}
)

// looksLikeXML reports whether a file part should be handed to the XML tokenizer.
// A part qualifies on any of three independent hints: an XML media type, a known
// XML filename extension, or content starting with an XML declaration. All three
// are attacker controlled, so they widen coverage rather than establish trust: a
// part that is not XML simply fails to tokenize into anything.
func looksLikeXML(contentType, filename string, head []byte) bool {
	if mediaType, _, err := mime.ParseMediaType(contentType); err == nil && strings.Contains(mediaType, "xml") {
		return true
	}
	if slices.Contains(xmlFileExtensions, strings.ToLower(path.Ext(filename))) {
		return true
	}
	head = bytes.TrimLeft(bytes.TrimPrefix(head, utf8BOM), " \t\r\n")
	return bytes.HasPrefix(head, []byte("<?xml"))
}

// countingWriter counts the bytes written through it, so that a part copied by
// way of an io.TeeReader still reports its size.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// copyFilePart copies a file part into dst and returns the number of bytes
// copied. When parseXML is set and the part looks like XML, the part is
// tokenized on its way to dst and the attribute values and element contents it
// yields are returned. The part is always drained, so dst holds the whole file
// whether it parsed or not.
func copyFilePart(dst io.Writer, p *multipart.Part, filename string, parseXML bool) (int64, []string, []string, error) {
	if !parseXML {
		size, err := io.Copy(dst, p)
		return size, nil, nil, err
	}

	// Buffer the part so its first bytes can be examined without consuming them.
	br := bufio.NewReader(p)
	head, err := br.Peek(xmlSniffLen)
	// A part shorter than xmlSniffLen peeks fine, it just reports EOF.
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return 0, nil, nil, err
	}
	if !looksLikeXML(p.Header.Get("Content-Type"), filename, head) {
		size, err := io.Copy(dst, br)
		return size, nil, nil, err
	}

	counter := &countingWriter{w: dst}
	// A leading BOM is emitted by the tokenizer as character data, which would
	// show up as a bogus XML:/* value. Send it straight to dst instead, so it is
	// still stored and counted but never reaches the decoder.
	if bom, err := br.Peek(len(utf8BOM)); err == nil && bytes.Equal(bom, utf8BOM) {
		if _, err := io.CopyN(counter, br, int64(len(utf8BOM))); err != nil {
			return counter.n, nil, nil, err
		}
	}
	tee := io.TeeReader(br, counter)
	attrs, contents, xmlErr := readXML(tee)
	// readXML stops at the first token it cannot handle, which may be before the
	// end of the part. Drain the remainder through the tee so the stored file and
	// FILES_SIZES stay complete regardless of how far parsing got.
	_, err = io.Copy(io.Discard, tee)
	if xmlErr != nil {
		// A part that fails to parse is not a body error: the upload variables
		// are still populated, the part simply contributes no XML.
		return counter.n, nil, nil, err
	}
	return counter.n, attrs, contents, err
}

func (mbp *multipartBodyProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

var (
	_ plugintypes.BodyProcessor = (*multipartBodyProcessor)(nil)
)

// OriginFileName returns the filename parameter of the Part's Content-Disposition header.
// This function is based on (multipart.Part).parseContentDisposition,
// See https://go.googlesource.com/go/+/refs/tags/go1.17.9/src/mime/multipart/multipart.go#87
// for the current implementation and also notice this function hasn't change since go1.4, as in
// https://go.googlesource.com/go/+/refs/tags/go1.4/src/mime/multipart/multipart.go#75
func originFileName(p *multipart.Part) string {
	v := p.Header.Get("Content-Disposition")
	_, dispositionParams, err := mime.ParseMediaType(v)
	if err != nil {
		return ""
	}

	return dispositionParams["filename"]
}

func init() {
	RegisterBodyProcessor("multipart", func() plugintypes.BodyProcessor {
		return &multipartBodyProcessor{}
	})
}
