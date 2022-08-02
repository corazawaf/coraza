// Audit logs are currently disabled for tinygo

//go:build !tinygo
// +build !tinygo

package seclang

import (
	"github.com/corazawaf/coraza/v3"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/types"
	"os"
	"strings"
	"testing"
)

func TestSecAuditLogDirectivesConcurrent(t *testing.T) {
	waf := coraza.NewWaf()
	auditpath := "/tmp/"
	parser, _ := NewParser(waf)
	if err := parser.FromString(`
	SecAuditLog /tmp/audit.log
	SecAuditLogFormat json
	SecAuditLogDir /tmp
	SecAuditLogDirMode 0777
	SecAuditLogFileMode 0777
	SecAuditLogType concurrent
	`); err != nil {
		t.Error(err)
	}
	id := utils.SafeRandom(10)
	if waf.AuditLogWriter == nil {
		t.Error("Invalid audit logger (nil)")
		return
	}
	if err := waf.AuditLogWriter.Write(&loggers.AuditLog{
		Parts: types.AuditLogParts("ABCDEFGHIJKZ"),
		Transaction: loggers.AuditTransaction{
			ID: id,
		},
	}); err != nil {
		t.Error(err)
	}
	f, err := findFileContaining(auditpath, id)
	if err != nil {
		t.Error(err)
	}
	data, err := os.ReadFile(f)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(data), id) {
		t.Error("failed to write audit log")
	}
	// we test it is a valid json
	j := loggers.AuditLog{}
	if err := j.UnmarshalJSON(data); err != nil {
		t.Error(err)
	}
}
