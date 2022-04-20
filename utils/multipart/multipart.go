package multipart

import (
	"mime"
	"mime/multipart"
)

// OriginFileName returns the filename parameter of the Part's Content-Disposition header.
// This function is based on (multipart.Part).parseContentDisposition,
// See https://go.googlesource.com/go/+/refs/tags/go1.17.9/src/mime/multipart/multipart.go#87
// for the current implementation and also notice this function hasn't change since go1.4, as in
// https://go.googlesource.com/go/+/refs/tags/go1.4/src/mime/multipart/multipart.go#75
func OriginFileName(p *multipart.Part) string {
	v := p.Header.Get("Content-Disposition")
	_, dispositionParams, err := mime.ParseMediaType(v)
	if err != nil {
		return ""
	}

	return dispositionParams["filename"]
}
