package plugins_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// ExampleRegisterAuditLogFormatter shows how to register a custom audit log formatter
// and tests the output of the formatter.
func ExampleRegisterAuditLogFormatter() {
	plugins.RegisterAuditLogFormatter("txid", func(al plugintypes.AuditLog) ([]byte, error) {
		return []byte(al.Transaction().ID()), nil
	})

	w, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecAuditEngine On
				SecAuditLogParts ABCFHZ
				SecAuditLog /dev/stdout
				SecAuditLogFormat txid
				SecAuditLogType serial
			`),
	)
	if err != nil {
		panic(err)
	}

	tx := w.NewTransactionWithID("abc123")
	tx.ProcessLogging()
	tx.Close()

	// Output: abc123
}

type urlWriter struct {
	url string
}

func (s *urlWriter) Init(cfg plugintypes.AuditLogConfig) error {
	s.url = cfg.Target
	return nil
}

func (s *urlWriter) Write(al plugintypes.AuditLog) error {
	res, err := http.DefaultClient.Post(s.url, "application/json", strings.NewReader(al.Transaction().ID()))
	if err != nil {
		return err
	}
	res.Body.Close()
	_, err = io.Copy(io.Discard, res.Body)
	return err
}

func (s *urlWriter) Close() error { return nil }

// ExampleRegisterAuditLogFormatter shows how to register a custom audit log formatter
// and tests the output of the formatter.
func ExampleRegisterAuditLogWriter() {
	plugins.RegisterAuditLogWriter("url", func() plugintypes.AuditLogWriter {
		return &urlWriter{}
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Println(string(b))
	}))
	defer srv.Close()

	w, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecAuditEngine On
				SecAuditLogParts ABCFHZ
				SecAuditLog ` + srv.URL + `
				SecAuditLogType url
			`),
	)
	if err != nil {
		panic(err)
	}

	tx := w.NewTransactionWithID("xyz456")
	tx.ProcessLogging()
	tx.Close()

	// Output: xyz456
}
