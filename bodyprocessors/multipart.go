// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type multipartBodyProcessor struct {
}

func (mbp *multipartBodyProcessor) ProcessRequest(reader io.Reader, collections [types.VariablesCount]collection.Collection, options Options) error {
	mimeType := options.Mime
	storagePath := options.StoragePath
	mediaType, params, err := mime.ParseMediaType(mimeType)
	if err != nil {
		log.Fatal(err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return fmt.Errorf("not a multipart body")
	}
	mr := multipart.NewReader(reader, params["boundary"])
	totalSize := int64(0)
	filesCol := (collections[variables.Files]).(*collection.Map)
	filesTmpNamesCol := (collections[variables.FilesTmpNames]).(*collection.Map)
	fileSizesCol := (collections[variables.FilesSizes]).(*collection.Map)
	postCol := (collections[variables.ArgsPost]).(*collection.Map)
	filesCombinedSizeCol := (collections[variables.FilesCombinedSize]).(*collection.Simple)
	filesNamesCol := (collections[variables.FilesNames]).(*collection.Map)
	headersNames := (collections[variables.MultipartPartHeaders]).(*collection.Map)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
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
			var size int64
			if !environment.IsTinyGo {
				// Only copy file to temp when not running in TinyGo
				temp, err := os.CreateTemp(storagePath, "crzmp*")
				if err != nil {
					return err
				}
				sz, err := io.Copy(temp, p)
				if err != nil {
					return err
				}
				size = sz
				filesTmpNamesCol.Add("", temp.Name())
			} else {
				sz, err := io.Copy(io.Discard, p)
				if err != nil {
					return err
				}
				size = sz
			}
			totalSize += size
			filesCol.Add("", filename)
			fileSizesCol.SetIndex(filename, 0, fmt.Sprintf("%d", size))
			filesNamesCol.Add("", p.FormName())
		} else {
			// if is a field
			data, err := io.ReadAll(p)
			if err != nil {
				return err
			}
			totalSize += int64(len(data))
			postCol.Add(p.FormName(), string(data))
		}
		filesCombinedSizeCol.Set(fmt.Sprintf("%d", totalSize))
	}
	return nil
}

func (mbp *multipartBodyProcessor) ProcessResponse(reader io.Reader, collection [types.VariablesCount]collection.Collection, options Options) error {
	return nil
}

var (
	_ BodyProcessor = (*multipartBodyProcessor)(nil)
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
	Register("multipart", func() BodyProcessor {
		return &multipartBodyProcessor{}
	})
}
