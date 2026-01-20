// Copyright 2023 the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !windows && !plan9

package auditlog

import (
	"log/syslog"
	"net"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var SyslogDialer = new(syslogDialerStub)

func init() {
	syslogDialer = SyslogDialer.Dial
}

func Test_syslogWriter_Init(t *testing.T) {
	type args struct {
		c plugintypes.AuditLogConfig
	}
	type want struct {
		network string
		raddr   string
	}
	tests := []struct {
		name    string
		args    args
		want    want
		wantErr bool
	}{
		{
			name: "Default",
			args: args{
				c: plugintypes.AuditLogConfig{
					Target: "",
				},
			},
			want: want{
				network: "",
				raddr:   "",
			},
		},
		{
			name: "AddrOnly",
			args: args{
				c: plugintypes.AuditLogConfig{
					Target: "127.0.0.1:514",
				},
			},
			want: want{
				network: "tcp",
				raddr:   "127.0.0.1:514",
			},
		},
		{
			name: "UDP",
			args: args{
				c: plugintypes.AuditLogConfig{
					Target: "udp://127.0.0.1:514",
				},
			},
			want: want{
				network: "udp",
				raddr:   "127.0.0.1:514",
			},
		},
		{
			name: "Socket",
			args: args{
				c: plugintypes.AuditLogConfig{
					Target: "unixgram:///var/run/syslog",
				},
			},
			want: want{
				network: "unixgram",
				raddr:   "/var/run/syslog",
			},
		},
		{
			name: "Formatter",
			args: args{
				c: plugintypes.AuditLogConfig{
					Formatter: new(noopFormatter),
				},
			},
		},
		{
			name:    "Failure",
			args:    args{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := GetWriter("syslog")
			if err != nil {
				t.FailNow()
			}
			syslogW := w.(*syslogWriter)

			SyslogDialer.Lock()
			t.Cleanup(SyslogDialer.Unlock)
			SyslogDialer.wantErr = tt.wantErr

			if err := w.Init(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("syslogWriter.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if syslogW.formatter != tt.args.c.Formatter {
				t.Errorf("syslogWriter.formatter want = %#v, got %#v", tt.args.c.Formatter, syslogW.formatter)
			}

			if !SyslogDialer.dialed {
				t.Errorf("syslogWriter.dialer not called")
			}
			if SyslogDialer.network != tt.want.network {
				t.Errorf("syslogWriter.Syslog.network want = %v, got %v", tt.want.network, SyslogDialer.network)
			}
			if SyslogDialer.raddr != tt.want.raddr {
				t.Errorf("syslogWriter.Syslog.raddr want = %v, got %v", tt.want.raddr, SyslogDialer.raddr)
			}
		})
	}
}

func Test_syslogWriter_Write(t *testing.T) {
	type fields struct {
		formatter plugintypes.AuditLogFormatter
	}
	type args struct {
		al plugintypes.AuditLog
	}
	type want struct {
		priority syslog.Priority
		message  string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    want
		wantErr bool
	}{
		{
			name: "Default",
			fields: fields{
				formatter: new(jsonFormatter),
			},
			args: args{
				al: &Log{
					Transaction_: Transaction{
						ID_:            "42",
						IsInterrupted_: false,
					},
				},
			},
			want: want{
				priority: syslog.LOG_INFO,
				message:  `{"transaction":{"timestamp":"","unix_timestamp":0,"id":"42","client_ip":"","client_port":0,"host_ip":"","host_port":0,"server_id":"","highest_severity":"","is_interrupted":false}}`,
			},
		},
		{
			name: "Interrupted",
			fields: fields{
				formatter: new(noopFormatter),
			},
			args: args{
				al: &Log{
					Transaction_: Transaction{
						IsInterrupted_: true,
					},
				},
			},
			want: want{
				priority: syslog.LOG_ERR,
			},
		},
		{
			name: "FailureDefault",
			fields: fields{
				formatter: new(noopFormatter),
			},
			args: args{
				al: &Log{},
			},
			wantErr: true,
		},
		{
			name: "FailureInterrupted",
			fields: fields{
				formatter: new(noopFormatter),
			},
			args: args{
				al: &Log{
					Transaction_: Transaction{
						IsInterrupted_: true,
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := GetWriter("syslog")
			if err != nil {
				t.FailNow()
			}
			syslogW := w.(*syslogWriter)
			syslogW.formatter = tt.fields.formatter

			var (
				priority syslog.Priority
				message  string
			)
			syslogW.Syslog = syslogMock(func(p syslog.Priority, m string) error {
				if tt.wantErr {
					return &net.OpError{Op: "write"}
				}

				priority = p
				message = m

				return nil
			})

			if err := w.Write(tt.args.al); (err != nil) != tt.wantErr {
				t.Errorf("syslogWriter.Write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if priority != tt.want.priority {
				t.Errorf("priority want = %v, got %v", tt.want.priority, priority)
			}
			if message != tt.want.message {
				t.Errorf("message want = %v, got %v", tt.want.message, message)
			}
		})
	}
}

type syslogDialerStub struct {
	sync.Mutex
	wantErr bool
	dialed  bool
	network string
	raddr   string
}

func (s *syslogDialerStub) Dial(network, raddr string, _ syslog.Priority, _ string) (*syslog.Writer, error) {
	s.dialed = true
	s.network = network
	s.raddr = raddr
	if s.wantErr {
		return nil, &net.OpError{Op: "dial", Net: network}
	}

	return nil, nil
}

func (s *syslogDialerStub) Lock() {
	s.dialed = false
	s.Mutex.Lock()
}

type syslogMock func(syslog.Priority, string) error

func (s syslogMock) Err(m string) error {
	return s(syslog.LOG_ERR, m)
}

func (s syslogMock) Info(m string) error {
	return s(syslog.LOG_INFO, m)
}

func (syslogMock) Close() error {
	return nil
}
