package plugins_test

import (
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

	w, _ := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecAuditEngine On
				SecAuditLogParts ABCFHZ
				SecAuditLog /dev/stdout
				SecAuditLogFormat txid
				SecAuditLogType serial
			`),
	)
	tx := w.NewTransactionWithID("abc123")
	tx.ProcessLogging()
	tx.Close()

	// Output: abc123
}
