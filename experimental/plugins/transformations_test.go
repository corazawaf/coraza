package plugins_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/internal/transformations"
)

func TestTransformation(t *testing.T) {
	t.Run("get existing transformation", func(t *testing.T) {
		transformation := func(input string) (string, error) {
			return "", nil
		}

		plugins.RegisterTransformation("custom_transformation", transformation)
		_, err := transformations.GetTransformation("custom_transformation")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
