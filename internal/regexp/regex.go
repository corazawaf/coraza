package regexp

import (
	"regexp"
)

var RegexCompiler func(expr string) (Regexp, error)

func init() {
	RegexCompiler = func(expr string) (Regexp, error) {
		return regexp.Compile(expr)
	}
}

func MustCompile(str string) *regexp.Regexp {
	return regexp.MustCompile(str)
}

type Regexp interface {
	MatchString(s string) bool
	FindStringSubmatch(s string) []string
	FindAllStringSubmatch(s string, n int) [][]string
	SubexpNames() []string
	Match(s []byte) bool
	String() string
}

func Compile(expr string) (Regexp, error) {
	return RegexCompiler(expr)
}

var _ Regexp = (*regexp.Regexp)(nil)
