package auditlog

type noopCloser struct{}

func (noopCloser) Close() error { return nil }
