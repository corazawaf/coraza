package loggers

import "testing"

func TestDefaultWriters(t *testing.T) {
	ws := []string{"serial", "concurrent"}
	for _, writer := range ws {
		if w, err := getLogWriter(writer); err != nil {
			t.Error(err)
		} else if w == nil {
			t.Errorf("invalid %s writer", writer)
		}
	}

}
func TestWriterPlugins(t *testing.T) {

}

func TestDefaultAuditLogger(t *testing.T) {
	al, err := NewAuditLogger()
	if err != nil {
		t.Error(err)
	}
	log := AuditLog{}
	if err := al.Write(log); err != nil {
		t.Error(err)
	}
}
