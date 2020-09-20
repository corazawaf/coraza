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

package engine

import(
	"testing"
)

func TestLocalCollection(t *testing.T){
	lc := NewCollection("test")

	lc.InitCollection("test2")
	if lc.Data["test2"] == nil {
		t.Error("Failed to initialize Local Collection")
	}

	lc.Update("test2", []string{"test3"})
	if lc.GetData()["test2"][0] != "test3"{
		t.Error("Failed to update local collection")
	}

	lc.Remove("test2")
	if lc.GetData()["test2"] != nil {
		t.Error("Failed to remove from local collection")
	}
}

func TestLocalCollectionMatchData(t *testing.T){
	lc := NewCollection("test")
	lc.InitCollection("test2")
	lc.Update("test2", []string{"test3"})

	md := lc.GetWithExceptions("test2", []string{})
	if len(md) == 0{
		t.Error("Failed to get matched data")
		return
	}
	md0 := md[0]
	if md0.Collection != "test"{
		t.Error("Failed to set matched data collection")
	}
	if md0.Key != "test2"{
		t.Error("Failed to set matched data key")
	}	
	if md0.Value != "test3"{
		t.Error("Failed to set matched data value")
	}		
}