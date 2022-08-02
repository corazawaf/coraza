// Currently only used with TinyGo
//go:build tinygo
// +build tinygo

package loggers

func noopFormater(al *AuditLog) ([]byte, error) {
	return nil, nil
}
