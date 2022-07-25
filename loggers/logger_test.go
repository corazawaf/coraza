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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultWriters(t *testing.T) {
	ws := []string{"serial", "concurrent"}
	for _, writer := range ws {
		t.Run(writer, func(t *testing.T) {
			w, err := GetLogWriter(writer)
			require.NoError(t, err)
			require.NotNil(t, w)
		})
	}
}
func TestWriterPlugins(t *testing.T) {

}
