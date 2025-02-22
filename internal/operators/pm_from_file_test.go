package operators
import (
    "testing"

    "github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)
func TestPmFromFileAlias(t *testing.T) {
    opts := plugintypes.OperatorOptions{
        Arguments: "test_1",
        Datasets: map[string][]string{
            "test_1": {"value1", "value2"},
        },
    }
    pm, err := newPM(opts)
    if err != nil {
        t.Fatalf("Failed to initialize pm: %v", err)
    }
    pmFromFile, err := newPMFromFile(opts)
    if err != nil {
        t.Fatalf("Failed to initialize pmFromFile: %v", err)
    }
    input := "value1"
    if pm.Evaluate(nil, input) != pmFromFile.Evaluate(nil, input) {
        t.Errorf("pm and pmFromFile returned different results for input: %s", input)
    }
}

