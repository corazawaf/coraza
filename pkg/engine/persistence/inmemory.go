// Copyright 2021 Juan Pablo Tosso
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

package persistence

import (
	"errors"
	ttlcache "github.com/ReneKroon/ttlcache/v2"
	"sync"
	"time"
)

type collection struct {
	Data    map[string][]string
	Timeout map[string]int64
	Mux     sync.Mutex
}

type MemoryEngine struct {
	//data map[string]map[string][]string
	data *ttlcache.Cache
	ttl  int
}

func (r *MemoryEngine) Init(url string, ttl int) error {
	r.data = ttlcache.NewCache()
	r.data.SetTTL(time.Duration(ttl) * time.Second)
	return nil
}

func (r *MemoryEngine) Get(key string) map[string][]string {
	if value, exists := r.data.Get(key); exists == nil {
		col := value.(collection)
		col.Mux.Lock()
		defer col.Mux.Unlock()
		for k, _ := range col.Data {
			to := col.Timeout[k]
			diff := to - time.Now().Unix()
			if diff <= 0 {
				//We delete the timeout subkey
				delete(col.Data, k)
				delete(col.Timeout, k)
			}
		}

		return col.Data
	}
	return nil
}

func (r *MemoryEngine) Set(key string, value map[string][]string) error {
	var col collection
	if val, exists := r.data.Get(key); exists == nil {
		col = val.(collection)
		col.Mux.Lock()
		defer col.Mux.Unlock()
		col.Data = value
		//We renew the collection with new ttl
	} else {
		to := map[string]int64{}
		for k, _ := range value {
			to[k] = time.Now().Unix() + 3600
		}
		col = collection{
			Data:    value,
			Timeout: to,
		}
	}
	r.data.SetWithTTL(key, col, time.Duration(r.ttl)*time.Second)

	return nil
}

func (r *MemoryEngine) SetTtl(key string, subkey string, ttl int) error {
	if value, exists := r.data.Get(key); exists == nil {
		col := value.(collection)
		col.Mux.Lock()
		defer col.Mux.Unlock()
		if ttl == 0 {
			delete(col.Data, subkey)
			delete(col.Timeout, subkey)
		} else {
			col.Timeout[subkey] = time.Now().Unix() + int64(ttl)
		}
		return nil
	}
	return errors.New("Failed to set ttl")
}

func (r *MemoryEngine) Delete(key string) error {
	if result := r.data.Remove(key); result == ttlcache.ErrNotFound {
		return errors.New("Key not found")
	}
	return nil
}