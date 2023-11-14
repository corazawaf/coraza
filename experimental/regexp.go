package experimental

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/internal/regexp"
)

// SetRegexpCompiler sets the regex compiler used by the WAF. This is specially
// useful when we want to lazily compile regexes in a mono thread environment as
// we don't need to synchronize the regex compilation.
func SetRegexpCompiler(fn func(expr string) (regexp.Regexp, error)) {
	if fn == nil {
		fmt.Println("invalid regex compiler")
		return
	}

	if regexp.RegexCompiler != nil {
		fmt.Println("regex compiler already set")
		return
	}

	regexp.RegexCompiler = fn
}
