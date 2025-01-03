// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package persistence

import (
	"testing"
	"time"
)

func TestDefaultEngineSetAndGet(t *testing.T) {
	t.Parallel()
	engine := &defaultEngine{ttl: int(time.Now().Add(10 * time.Minute).Unix())}
	err := engine.Set("testCol", "testColKey", "testKey", "testValue")
	if err != nil {
		t.Errorf("Set failed: %v", err)
	}

	val, err := engine.Get("testCol", "testColKey", "testKey")
	if err != nil || val != "testValue" {
		t.Errorf("Get failed or returned incorrect value: %v, %v", err, val)
	}

	// now we test the updates

	err = engine.Set("testCol", "testColKey", "testKey", "testValue2")
	if err != nil {
		t.Errorf("Set failed: %v", err)
	}

	val, err = engine.Get("testCol", "testColKey", "testKey")
	if err != nil || val != "testValue2" {
		t.Errorf("Get failed or returned incorrect value: %v, %v", err, val)
	}

	// now we validate the time update worked
	time_now := int(time.Now().Unix())
	create_time := engine.get("testCol", "testColKey", "CREATE_TIME")
	if err != nil {
		t.Errorf("Get failed: %v", err)
	}
	ct, ok := create_time.(int)
	if !ok {
		t.Errorf("Create time is not an int: %v", create_time)
	}
	if ct == 0 {
		t.Errorf("Create time is 0")
	}
	// time difference should be small
	if time_now-ct > 10 {
		t.Errorf("Time difference is too big: %v", time_now-int(ct))
	}

	err = engine.Sum("testCol", "testColKey", "sum", 5)
	if err != nil {
		t.Errorf("Set failed: %v", err)
	}
	if val := engine.get("testCol", "testColKey", "sum"); val != 5 {
		t.Errorf("Sum failed, got %v", val)
	}

	err = engine.Sum("testCol", "testColKey", "sum", 2)
	if err != nil {
		t.Errorf("Set failed: %v", err)
	}
	if val := engine.get("testCol", "testColKey", "sum"); val != 7 {
		t.Errorf("Sum failed, got %v", val)
	}

	err = engine.Remove("testCol", "testColKey", "sum")
	if err != nil {
		t.Errorf("Set failed: %v", err)
	}
	if val := engine.get("testCol", "testColKey", "sum"); val != nil {
		t.Errorf("Sum failed, got %v", val)
	}
}

func TestDefaultGC(t *testing.T) {
	t.Parallel()
	engine := &defaultEngine{}
	engine.Open("", 1)   //nolint:errcheck
	defer engine.Close() //nolint:errcheck
	err := engine.Set("testCol", "testColKey", "testKey", "testValue")
	if err != nil {
		t.Errorf("Set failed: %v", err)
	}
	// we sleep 2 second
	time.Sleep(2000 * time.Millisecond)
	// now we should have no data
	val, err := engine.Get("testCol", "testColKey", "testKey")
	if err != nil {
		t.Errorf("Get failed or returned incorrect value: %v, %v", err, val)
	}
	if val == "testValue" {
		t.Errorf("Value was not deleted")
	}

}

func TestDefaultAll(t *testing.T) {
	t.Parallel()
	engine := &defaultEngine{}
	engine.Open("", 3600) //nolint:errcheck
	defer engine.Close()  //nolint:errcheck
	if err := engine.Set("testCol", "testColKey", "testKey", "testValue"); err != nil {
		t.Errorf("Set failed: %v", err)
	}
	all, err := engine.All("testCol", "testColKey")
	if err != nil {
		t.Errorf("All failed: %v", err)
	}
	if all["testKey"] != "testValue" {
		t.Errorf("All failed: %v", all)
	}
}

func TestSetTTL(t *testing.T) {
	t.Parallel()

	t.Run("set value then set ttl", func(t *testing.T) {
		t.Parallel()

		e := &defaultEngine{}
		err := e.Open("", 3600)
		if err != nil {
			t.Errorf("error should be nil, got %v", err)
		}
		defer e.Close() //nolint:errcheck
		if err := e.Set("testCol", "testColKey", "testKey", "testValue"); err != nil {
			t.Errorf("set failed: %v", err)
		}

		data := e.getCollection("testCol", "testColKey")
		_, ok := data["TTL_SET"]
		if ok {
			t.Error("TTL_SET should not exist in data map")
		}
		to, ok := data["TIMEOUT"]
		if !ok {
			t.Error("TIMEOUT should be set")
		}
		timeout, ok := to.(int)
		if !ok {
			t.Error("TIMEOUT should have type assertion to int")
		}
		now := int(time.Now().Unix())
		if timeout < now && timeout > now+e.ttl+1 {
			t.Errorf("timeout should be between %d and %d, got %d",
				now-1, now+e.ttl+1, timeout)
		}

		newTTL := 6000
		err = e.SetTTL("testCol", "testColKey", "testKey", newTTL)
		if err != nil {
			t.Errorf("error should be nil, got %v", err)
		}

		// same check after SetTTL
		data = e.getCollection("testCol", "testColKey")
		ttlSet, ok := data["TTL_SET"]
		if !ok {
			t.Error("TTL_SET should exist in data map")
		}
		isTTLSet, ok := ttlSet.(bool)
		if !ok {
			t.Error("TTL_SET should have type assertion to bool")
		}
		if !isTTLSet {
			t.Error("TTL_SET should should be true")
		}
		to, ok = data["TIMEOUT"]
		if !ok {
			t.Error("TIMEOUT should be set")
		}
		timeout, ok = to.(int)
		if !ok {
			t.Error("TIMEOUT should have type assertion to int")
		}
		now = int(time.Now().Unix())
		if timeout < now && timeout > now+newTTL+1 {
			t.Errorf("timeout should be between %d and %d, got %d",
				now-1, now+newTTL+1, timeout)
		}

	})
}
