package test

import(
	"testing"
	test"github.com/jptosso/coraza-waf/test/utils"
)

func TestEngine(t *testing.T){
	files := []string{
		"data/engine/phases.yaml",
		"data/engine/actions.yaml",
		"data/engine/directives.yaml",
	}

	ts := &test.TestSuite{}
	ts.Init("/dev/null")

	for _, f := range files{
		err := ts.AddProfile(f)
		if err != nil{
			t.Error(err)
		}
	}
	ts.Start(func(a string, b bool){
		if !b{
			t.Error("Failed to run engine test: " + a)
		}
	})
}