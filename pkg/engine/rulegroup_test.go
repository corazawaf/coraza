package engine

import (
	"testing"
)

func TestRG(t *testing.T) {
	r := &Rule{}
	r.Init()
	r.Msg = "test"
	r.Id = 1
	r.Tags = []string{
		"test",
	}

	rg := &RuleGroup{}
	rg.Init()
	rg.Add(r)

	if rg.Count() != 1 {
		t.Error("Failed to add rule to rulegroup")
	}

	if len(rg.FindByMsg("test")) != 1 {
		t.Error("Failed to find rules by msg")
	}

	if len(rg.FindByTag("test")) != 1 {
		t.Error("Failed to find rules by tag")
	}

	rg.DeleteById(1)
	if rg.Count() != 0 {
		t.Error("Failed to remove rule from rulegroup")
	}
}
