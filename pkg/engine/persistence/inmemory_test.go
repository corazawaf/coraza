package persistence

import (
	ttlcache "github.com/ReneKroon/ttlcache/v2"
	"testing"
	"time"
)

func TestInmemoryTtlcache(t *testing.T) {
	cache := ttlcache.NewCache()
	defer cache.Close()
	cache.SetTTL(time.Duration(1 * time.Second))
	cache.SetWithTTL("key", "value", 1*time.Second)
	workChan := make(chan bool, 1)
	expirationCallback := func(key string, value interface{}) {
		workChan <- true
	}
	cache.SetExpirationCallback(expirationCallback)

	if value, exists := cache.Get("key"); exists != nil {
		t.Error("Failed to key key")
	} else {
		if value != "value" {
			t.Error("Failed to key key")
		}
	}
	<-workChan
	if _, exists := cache.Get("key"); exists == nil {
		t.Error("Persistent key failed to expire over TTL")
	}

}

func TestInmemoryPersistence(t *testing.T) {
	me := MemoryEngine{}
	me.Init("")
	st := map[string][]string{
		"test": []string{
			"test2",
		},
	}
	me.Set("test", st)
	if me.Get("test")["test"][0] != "test2" {
		t.Error("Failed to create inmemory persistent collection")
	}
	me.Delete("test")
	if me.Get("test") != nil {
		t.Error("Failed to delete inmemory persistent collection")
	}
}
