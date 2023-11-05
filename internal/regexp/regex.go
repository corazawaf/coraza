package regexp

import (
	"regexp"
	"sync"
)

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

type lazyRegexp struct {
	expr string
	re   *regexp.Regexp
	once sync.Once
}

var _ Regexp = (*lazyRegexp)(nil)

func (r *lazyRegexp) MatchString(s string) bool {
	r.once.Do(func() {
		r.re = regexp.MustCompile(r.expr)
	})

	return r.re.MatchString(s)
}

func (r *lazyRegexp) FindStringSubmatch(s string) []string {
	r.once.Do(func() {
		r.re = regexp.MustCompile(r.expr)
	})

	return r.re.FindStringSubmatch(s)
}

func (r *lazyRegexp) FindAllStringSubmatch(s string, n int) [][]string {
	r.once.Do(func() {
		r.re = regexp.MustCompile(r.expr)
	})

	return r.re.FindAllStringSubmatch(s, n)
}

func (r *lazyRegexp) SubexpNames() []string {
	r.once.Do(func() {
		r.re = regexp.MustCompile(r.expr)
	})

	return r.re.SubexpNames()
}

func (r *lazyRegexp) Match(b []byte) bool {
	r.once.Do(func() {
		r.re = regexp.MustCompile(r.expr)
	})

	return r.re.Match(b)
}

func (r *lazyRegexp) String() string {
	return r.expr
}

func Compile(expr string) (Regexp, error) {
	_, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}

	return &lazyRegexp{expr: expr}, nil
}

var _ Regexp = (*regexp.Regexp)(nil)
