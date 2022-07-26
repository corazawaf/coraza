// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loggers

import (
	"os"
	"path"
	"testing"

	"github.com/corazawaf/coraza/v2/types"
	utils "github.com/corazawaf/coraza/v2/utils/strings"
	"github.com/stretchr/testify/require"
)

func TestSerialLogger_Write(t *testing.T) {
	tmp := path.Join("/tmp", utils.SafeRandom(10)+"-audit.log")
	defer os.Remove(tmp)
	writer := &serialWriter{}
	config := types.Config{
		"auditlog_file":      tmp,
		"auditlog_formatter": jsonFormatter,
	}

	err := writer.Init(config)
	require.NoError(t, err)

	al := &AuditLog{
		Transaction: AuditTransaction{
			ID: "test123",
		},
		Messages: []AuditMessage{
			{
				Data: AuditMessageData{
					ID:  100,
					Raw: "SecAction \"id:100\"",
				},
			},
		},
	}
	err = writer.Write(al)
	require.NoError(t, err, "failed to write to serial logger")

	data, err := os.ReadFile(tmp)
	require.NoError(t, err, "failed to read serial logger file")
	require.Contains(t, string(data), "test123", "failed to parse log tx id from serial log")
	require.Contains(t, string(data), "id:100", "failed to parse log rule id")
}
