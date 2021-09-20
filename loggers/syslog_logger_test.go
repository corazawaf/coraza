package loggers

import (
	"fmt"
	"net"
	"testing"
)

func TestSysLogger(t *testing.T) {
	logger := &SyslogLogger{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	defer l.Close()
	err = logger.New(map[string]string{
		"server": fmt.Sprintf("127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port),
	})
	if err != nil {
		t.Error(err)
	}

	if err = logger.Close(); err != nil {
		t.Error(err)
	}
}
