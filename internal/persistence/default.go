// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package persistence

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

const DefaultEngine = "default"

// defaultEngine
// defaultEngine is just a sample and it shouldn't be used in production.
// It's not thread safe enough and it's not persistent on disk.
type defaultEngine struct {
	data   sync.Map
	ttl    int
	stopGC chan bool
}

func (d *defaultEngine) Open(uri string, ttl int) error {
	d.data = sync.Map{}
	d.ttl = ttl
	d.stopGC = make(chan bool)
	// we start the garbage collector
	go d.gc()
	return nil
}

func (d *defaultEngine) Close() error {
	// Close will just stop the GC
	// it won't delete the data as it would cause race conditions.
	d.stopGC <- true
	return nil
}

func (d *defaultEngine) Sum(collectionName string, collectionKey string, key string, sum int) error {
	col := d.getCollection(collectionName, collectionKey)
	if col == nil {
		d.set(collectionName, collectionKey, key, sum)
	} else {
		if v, ok := col[key]; ok {
			if v2, ok := v.(int); ok {
				d.set(collectionName, collectionKey, key, v2+sum)
			}
		} else {
			d.set(collectionName, collectionKey, key, sum)
		}
	}
	return nil
}

func (d *defaultEngine) Get(collectionName string, collectionKey string, key string) (string, error) {
	res := d.get(collectionName, collectionKey, key)
	switch v := res.(type) {
	case string:
		return v, nil
	case int:
		return strconv.Itoa(v), nil
	case nil:
		return "", nil
	}

	return "", nil
}

func (d *defaultEngine) Set(collection string, collectionKey string, key string, value string) error {
	d.set(collection, collectionKey, key, value)
	return nil
}

func (d *defaultEngine) Remove(collection string, collectionKey string, key string) error {
	data := d.getCollection(collection, collectionKey)
	if data == nil {
		return nil
	}
	delete(data, key)
	return nil
}

func (d *defaultEngine) All(collectionName string, collectionKey string) (map[string]string, error) {
	data := d.getCollection(collectionName, collectionKey)
	if data == nil {
		return nil, nil
	}
	res := map[string]string{}
	for k, v := range data {
		if v == nil {
			res[k] = ""
		} else {
			switch v2 := v.(type) {
			case string:
				res[k] = v2
			case int:
				res[k] = strconv.Itoa(v2)
			}
		}
	}
	return res, nil
}

func (d *defaultEngine) SetTTL(collection string, collectionKey string, key string, ttl int) error {
	data := d.getCollection(collection, collectionKey)
	if data == nil {
		return nil
	}
	v, ok := data["TTL_SET"]
	if ok {
		setTTL, ok := v.(bool)
		if ok && setTTL {
			return nil
		}
	}

	data["TIMEOUT"] = int(time.Now().Unix()) + ttl
	data["TTL_SET"] = true
	return nil
}

func (d *defaultEngine) gc() {
	ticker := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-d.stopGC:
			ticker.Stop()
			return
		case <-ticker.C:
			d.data.Range(func(key, value interface{}) bool {
				col := value.(map[string]interface{})
				timeout, ok := col["TIMEOUT"].(int)
				if !ok {
					return true
				}
				if timeout < int(time.Now().Unix()) {
					d.data.Delete(key)
				}
				return true
			})
		}
	}
}

func (d *defaultEngine) getCollection(collectionName string, collectionKey string) map[string]interface{} {
	k := d.getCollectionName(collectionName, collectionKey)
	data, ok := d.data.Load(k)
	if !ok {
		return nil
	}
	return data.(map[string]interface{})
}

func (d *defaultEngine) get(collectionName string, collectionKey string, key string) interface{} {
	data := d.getCollection(collectionName, collectionKey)
	if data == nil {
		return nil
	}
	if res, ok := data[key]; ok {
		return res
	}
	return nil
}

func (d *defaultEngine) set(collection string, collectionKey string, key string, value interface{}) {
	data := d.getCollection(collection, collectionKey)
	now := int(time.Now().Unix())
	if data == nil {
		data := map[string]interface{}{
			key:                value,
			"CREATE_TIME":      now,
			"IS_NEW":           1,
			"KEY":              collectionKey,
			"LAST_UPDATE_TIME": 0,
			"TIMEOUT":          now + d.ttl,
			"UPDATE_COUNTER":   0,
			"UPDATE_RATE":      0,
		}
		d.data.Store(d.getCollectionName(collection, collectionKey), data)
	} else {
		data[key] = value
		d.updateCollection(data)
	}
}

func (*defaultEngine) getCollectionName(collectionName string, collectionKey string) string {
	return fmt.Sprintf("%s_%s", collectionName, collectionKey)
}

func (d *defaultEngine) updateCollection(col map[string]interface{}) {
	update_counter := col["UPDATE_COUNTER"].(int)
	time_now := int(time.Now().Unix())
	col["IS_NEW"] = 0
	col["LAST_UPDATE_TIME"] = time_now
	col["UPDATE_COUNTER"] = update_counter + 1
	// we compute the update rate by using UPDATE_COUNTER and CREATE_TIME
	// UPDATE_RATE = UPDATE_COUNTER / (CURRENT_TIME - CREATE_TIME)
	delta := (time_now - col["CREATE_TIME"].(int))
	if delta > 0 {
		col["UPDATE_RATE"] = int(update_counter / delta)
	}
}

func init() {
	Register(DefaultEngine, &defaultEngine{})
}
