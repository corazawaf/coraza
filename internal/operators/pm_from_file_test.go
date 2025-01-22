package operators

import (
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestPmFromFileAlias(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "testfile.txt",
		Path:      []string{"/mock/path"},
		Root:      "/mock/root",
	}

	mockFileContent := []byte("test_1\ntest_2\n")
	loadFromFile = func(filepath string, paths []string, root string) ([]byte, error) {
		if filepath == "testfile.txt" {
			return mockFileContent, nil
		}
		return nil, fmt.Errorf("file not found")
	}

	pmFromFile, err := newPMFromFile(opts)
	if err != nil {
		t.Fatalf("Failed to initialize @pmFromFile: %v", err)
	}

	opts.Arguments = "testfile.txt"
	pmfAlias, err := newPMFromFile(opts)
	if err != nil {
		t.Fatalf("Failed to initialize @pmf alias: %v", err)
	}

	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	tx.Capture = true

	tests := []struct {
		operator plugintypes.Operator
		input    string
		expect   bool
	}{
		{pmFromFile, "test_1", true},
		{pmFromFile, "nonexistent", false},
		{pmfAlias, "test_2", true},
		{pmfAlias, "another_test", false},
	}

	for _, test := range tests {
		if res := test.operator.Evaluate(tx, test.input); res != test.expect {
			t.Errorf("Operator evaluation failed: input=%q, expected=%v, got=%v", test.input, test.expect, res)
		}
	}

	opts.Arguments = "invalidfile.txt"
	if _, err := newPMFromFile(opts); err == nil {
		t.Errorf("Expected failure for invalid file, but got no error")
	}
}
