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

package operators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaildateNid(t *testing.T) {
	vn := &validateNid{}
	notOk := []string{"cl11.111.111-1", "us16100407-2", "clc 12345", "uss 1234567"}
	for _, no := range notOk {
		err := vn.Init(no)
		assert.NotNilf(t, err, "wrong valid data for %q", no)
	}
}

func TestNidCl(t *testing.T) {
	ok := []string{"11.111.111-1", "16100407-3", "8.492.655-8", "84926558", "111111111", "5348281-3", "10727393-k", "10727393-K"}
	nok := []string{"11.111.111-k", "16100407-2", "8.492.655-7", "84926557", "111111112", "5348281-4"}
	for _, o := range ok {
		t.Run(o, func(t *testing.T) {
			assert.True(t, nidCl(o), "invalid NID CL")
		})
	}

	for _, o := range nok {
		t.Run(o, func(t *testing.T) {
			assert.False(t, nidCl(o), "valid NID CL")
		})
	}

	require.False(t, nidCl(""), "valid NID CL for empty string")
}
