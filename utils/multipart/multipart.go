package multipart

import (
	"mime/multipart"
	"reflect"
	"unsafe"
)

//go:linkname parseContentDisposition mime/multipart.(*Part).parseContentDisposition
func parseContentDisposition(p *multipart.Part)

// OriginFileName returns the filename parameter of the Part's Content-Disposition header.
func OriginFileName(p *multipart.Part) string {
	field, ok := reflect.TypeOf(p).Elem().FieldByName("dispositionParams")
	if !ok {
		return p.FileName()
	}

	dispositionParams := (*map[string]string)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + field.Offset))
	if *dispositionParams == nil {
		parseContentDisposition(p)
	}

	return (*dispositionParams)["filename"]
}
