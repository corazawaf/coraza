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
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

type HttpLogger struct {
	working  bool
	endpoint string
	mux      *sync.RWMutex
	wg       sync.WaitGroup
	timeout  int

	queue []*Transaction

	LastError   error
	UploadCount int64
}

func (hl *HttpLogger) Init(endpoint string) {
	hl.endpoint = endpoint
	hl.mux = &sync.RWMutex{}
	hl.working = true
	hl.start()
}

func (hl *HttpLogger) start() {
	//TODO multithreading
	hl.wg.Add(1)
	go func() {
		for hl.working {
			next := hl.next()
			//We could use statistical models to adjust this time
			if next == nil {
				time.Sleep(1 * time.Millisecond)
				continue
			}
			err := hl.upload(next.ToAuditLog())
			if err != nil {
				hl.LastError = err
				hl.Add(next)
			} else {
				hl.mux.Lock()
				hl.UploadCount++
				hl.mux.Unlock()
			}
		}
		defer hl.wg.Done()
	}()
}

func (hl *HttpLogger) next() *Transaction {
	hl.mux.Lock()
	defer hl.mux.Unlock()
	if len(hl.queue) == 0 {
		return nil
	}
	n := hl.queue[0]
	hl.queue = hl.queue[1:]
	return n
}

func (hl *HttpLogger) Stop() {
	hl.working = false
}

func (hl *HttpLogger) Add(tx *Transaction) error {
	hl.mux.Lock()
	defer hl.mux.Unlock()
	hl.queue = append(hl.queue, tx)
	return nil
}

func (hl *HttpLogger) upload(al *AuditLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequest("POST", hl.endpoint, bytes.NewBuffer(al.ToJson()))

	if err != nil {
		return err
	}
	req.Header.Set("X-Coraza-Version", "")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("Invalid response code from server")
	}
	return nil
}
