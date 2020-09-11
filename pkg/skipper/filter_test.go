// Copyright 2020 Juan Pablo Tosso
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

package skipper

import(
	"testing"
	"os"
    _"github.com/zalando/skipper"
    _"github.com/zalando/skipper/config"
)

func TestFilterInitialization(t *testing.T){
	config := make([]interface{}, 1)
	pwd, _ := os.Getwd()
	config[0] = pwd + "/../../examples/skipper/default.conf"
	spec := &CorazaSpec{}
	_, err := spec.CreateFilter(config)
	if err != nil{
		t.Error("Error creating skipper filter")
	}
}