package transformations

import (
	"testing"
)

func TestCompressWhitespace(t *testing.T) {
    cw := CompressWhitespace

    if cw("aaa aaa aaa          aaa aa    aaa") != "aaa aaa aaa aaa aa aaa" {
    	t.Errorf("Invalid compressWhitespace transformation")
    }
}