package customttl

import (
	"fmt"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

type (
	Engine struct {
		store *ttlcache.Cache[string, collectionItem]
		ttl   int
	}

	collectionItem struct {
		key          string
		val          string
		updateCouter int
		createTime   int64
		timeout      int64
		isNew        bool
	}
)

func NewTTLCacheEngine(defaultTTL int) *Engine {
	cache := ttlcache.New[string, collectionItem]()

	return &Engine{
		store: cache,
		ttl:   defaultTTL,
	}
}

/* ---=== candidates to remove ===--- */

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

/* ---=== end ===--- */

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
	data := e.get(collection, collectionKey, key)
	if emptyCollectionItem(data) {
		return nil
	}
	if !data.isNew { // set ttl only for just created items
		return nil
	}
	data.isNew = false
	durTTL := time.Duration(ttl) * time.Second
	data.timeout = time.Now().Add(durTTL).Unix()
	e.store.Set(getKey(collection, collectionKey, key), data, durTTL)
	return nil
}

func (e *Engine) get(collectionName string, collectionKey string, key string) collectionItem {
	k := getKey(collectionName, collectionKey, key)
	item := e.store.Get(k)
	if item == nil {
		return collectionItem{}
	}
	return item.Value()
}

func (e *Engine) set(collection string, collectionKey string, key string, value string) {
	k := getKey(collection, collectionKey, key)
	data := e.get(collection, collectionKey, key)
	if emptyCollectionItem(data) {
		e.store.Set(k, collectionItem{
			key:          key,
			val:          value,
			timeout:      int64(ttlcache.NoTTL),
			createTime:   time.Now().Unix(),
			updateCouter: 0,
			isNew:        true,
		}, ttlcache.NoTTL) // we update ttl only in SetTTL method
	} else {
		data.val = value
		data.updateCouter++
		// unfortunately there are no ways to update data without setting ttl once again
		ttl := time.Duration(data.timeout)
		if ttl != ttlcache.NoTTL {
			ttl = time.Unix(data.timeout, 0).Sub(time.Now())
		}
		e.store.Set(k, data, ttl)
	}
}

func emptyCollectionItem(item collectionItem) bool {
	return item == collectionItem{}
}

func getKey(collectionName, collectionKey, key string) string {
	return fmt.Sprintf("%s_%s_%s", collectionName, collectionKey, key)
}
