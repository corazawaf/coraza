// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"strconv"
	"testing"
	"time"
)

func TestDuration(t *testing.T) {
	d := NewDuration()
	time.Sleep(100 * time.Millisecond)
	if d.Get() == "" {
		t.Error("Duration is empty")
	}
	if d.FindAll()[0].Value() == "" {
		t.Error("Duration is empty")
	}
	if v, err := strconv.Atoi(d.Get()); err != nil {
		t.Errorf("Duration is not a number, got %d", v)
	} else if v < 0 {
		t.Error("Duration is negative")
	}
	// set should be noop
	d.Set("test")
	if d.Name() != "Duration" {
		t.Error("Name is not Duration")
	}
}
