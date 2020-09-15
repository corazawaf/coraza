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

import (
	_ "fmt"
	_ "testing"
	_ "time"
)

/*
func TestHttpLogger(t *testing.T) {
	logger := &HttpLogger{}
	logger.Init("https://postman-echo.com/post")
	logger.Start()
	defer logger.Stop()
	tx := &Transaction{}
	w := &Waf{}
	w.Init()
	tx.Init(w)
	tx.InitTxCollection()
	al := &models.AuditLog{}
	al.Parse(&tx.Transaction)
	logger.Add(al)
	counter := 0
	for logger.UploadCount == 0{
		time.Sleep(100 * time.Millisecond)
		counter += 1
		if counter >= 300{
			break
		}
	}

	if logger.LastError != nil || logger.UploadCount == 0{
		t.Errorf("Failed to upload https log")
	}

	logger.Init("https://postman-echo.com/get")
	logger.Add(al)

	for logger.UploadCount < 2{
		time.Sleep(100 * time.Millisecond)
		counter += 1
		fmt.Println(counter)
		if counter >= 300{
			break
		}
	}
	if logger.LastError == nil{
		t.Errorf("False negative while uploading logs")
	}
}*/
