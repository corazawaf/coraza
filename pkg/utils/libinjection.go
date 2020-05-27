package utils

/*
#cgo LDFLAGS: -L./libinjection/src -linjection
#cgo CFLAGS: -I./libinjection/src
#include "libinjection.h"
#include "libinjection_sqli.h"
*/
import "C"
import (
	"bytes"
	"unsafe"
)

func IsSQLi(statement string) (bool, string) {
	var out [8]C.char
	pointer := (*C.char)(unsafe.Pointer(&out[0]))
	if found := C.libinjection_sqli(C.CString(statement), C.size_t(len(statement)), pointer); found == 1 {
		output := C.GoBytes(unsafe.Pointer(&out[0]), 8)
		return true, string(output[:bytes.Index(output, []byte{0})])
	}
	return false, ""
}

func IsXSS(input string) bool {
	if found := C.libinjection_xss(C.CString(input), C.size_t(len(input))); found == 1 {
		return true
	}
	return false
}