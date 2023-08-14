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
	engine := &defaultEngine{}
	engine.Open("", 1) //nolint:errcheck
	err := engine.Set("testCol", "testColKey", "testKey", "testValue")
	if err != nil {
		t.Errorf("Set failed: %v", err)
	}
	// we sleep 1.3 second
	time.Sleep(1300 * time.Millisecond)
	// now we should have no data
	val, err := engine.Get("testCol", "testColKey", "testKey")
	if err != nil {
		t.Errorf("Get failed or returned incorrect value: %v, %v", err, val)
	}
	if val == "testValue" {
		t.Errorf("Value was not deleted")
	}

}
