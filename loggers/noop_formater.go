package loggers

func noopFormater(al *AuditLog) ([]byte, error) {
	return nil, nil
}
