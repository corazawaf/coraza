package customttl

import (
	"fmt"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

type (
	Engine struct {
		store *ttlcache.Cache[string, collectionRecord]
	}

	collectionRecord struct {
		key          string
		val          string
		updateCouter int
		isNew        bool
		createTime   int64
		timeout      int64
	}
)

func NewTTLCacheEngine() *Engine {
	cache := ttlcache.New[string, collectionRecord]()

	return &Engine{
		store: cache,
	}
}

func (e *Engine) Get(collectionName string, collectionKey string, key string) (string, error) {
	res := e.get(collectionName, collectionKey, key)
	return res.val, nil
}

func (e *Engine) Set(collection string, collectionKey string, key string, value string) error {
	e.set(collection, collectionKey, key, value)
	return nil
}

func (e *Engine) Remove(collection string, collectionKey string, key string) error {
	k := getKey(collection, collectionKey, key)
	e.store.Delete(k)
	return nil
}

func (e *Engine) SetTTL(collection string, collectionKey string, key string, ttl int) error {
	record := e.get(collection, collectionKey, key)
	if record.isEmpty() {
		return nil
	}
	if !record.isNew { // set ttl only for just created records
		return nil
	}
	record.isNew = false
	durTTL := time.Duration(ttl) * time.Second
	record.timeout = time.Now().Add(durTTL).Unix()
	e.store.Set(getKey(collection, collectionKey, key), record, durTTL)
	return nil
}

func (e *Engine) get(collectionName string, collectionKey string, key string) collectionRecord {
	k := getKey(collectionName, collectionKey, key)
	record := e.store.Get(k)
	if record == nil {
		return collectionRecord{}
	}
	return record.Value()
}

func (e *Engine) set(collection string, collectionKey string, key string, value string) {
	k := getKey(collection, collectionKey, key)
	record := e.get(collection, collectionKey, key)
	if record.isEmpty() {
		// create new record
		e.store.Set(k, collectionRecord{
			key:          key,
			val:          value,
			timeout:      int64(ttlcache.NoTTL),
			createTime:   time.Now().Unix(),
			updateCouter: 0,
			isNew:        true,
		}, ttlcache.NoTTL) // we update ttl only in SetTTL method
	} else {
		// update existing record
		record.val = value
		record.updateCouter++
		// unfortunately this library doesn't provide the way to update data without setting ttl once again
		ttl := time.Duration(record.timeout)
		if ttl != ttlcache.NoTTL {
			ttl = time.Unix(record.timeout, 0).Sub(time.Now())
		}
		e.store.Set(k, record, ttl)
	}
}

func (cr collectionRecord) isEmpty() bool {
	return cr == collectionRecord{}
}

func getKey(collectionName, collectionKey, key string) string {
	return fmt.Sprintf("%s_%s_%s", collectionName, collectionKey, key)
}

func (d *Engine) Open(_ string, _ int) error {
	return nil
}

func (d *Engine) Close() error {
	return nil
}

func (d *Engine) Sum(collectionName string, collectionKey string, key string, sum int) error {
	return nil
}

func (d *Engine) All(collectionName string, collectionKey string) (map[string]string, error) {
	return nil, nil
}
