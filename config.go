package coraza

import (
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/types"
)

type WAFConfig interface {
	WithRule(rule *Rule) error
	WithRulesFromFile(path string) error
	WithRulesFromString(rules string) error

	WithAuditLog(config AuditLogConfig)

	WithContentInjection()

	WithRequestBodyAccess(config RequestBodyConfig)
	WithResponseBodyAccess(config ResponseBodyConfig)

	WithDebugLogger(logger DebugLogger)
	WithErrorLogger(logger ErrorLogCallback)
}

type RequestBodyConfig interface {
	WithLimit(limit int)
	WithInMemoryLimit(limit int)
}

type ResponseBodyConfig interface {
	WithLimit(limit int)
	WithInMemoryLimit(limit int)
	WithMimeTypes(mimeTypes []string)
}

type AuditLogConfig interface {
	LogRelevantOnly()
	WithParts(parts types.AuditLogParts)
	WithLogger(logger loggers.LogWriter)
}
