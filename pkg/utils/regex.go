package utils

type Matcher interface {
	Groups() int
	GroupString(int) string
	Matches() bool
}

type Regex interface {
	MatcherString(string, int) *Matcher
}

//type MustCompile = func(input string, flags int) *Regex
