package multipart

import (
	"mime/multipart"
	"net/textproto"
	"testing"
)

func TestOriginalFileName(t *testing.T) {
	tests := map[string][2]string{
		"no filename":       {` form-data ; name=foo`, ""},
		"contains filename": {`form-data; name="file"; filename="test.txt"`, "test.txt"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := &multipart.Part{
				Header: textproto.MIMEHeader{
					"Content-Disposition": []string{test[0]},
				},
			}
			if got, want := OriginFileName(p), test[1]; got != want {
				t.Errorf("OriginFileName(%v) = %v, want %v", p, got, want)
			}
		})
	}
}
