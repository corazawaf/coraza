// +build !cgo,never

package regex
import(
	"regexp"
)


type Matcher struct {
	input string
	rx *regexp.Regexp

	count int
	match []string
}

func (m *Matcher) Matches() bool{
	return m.count > 0
}

func (m *Matcher) MatchString(input string, flags int) bool{
	m.match = []string{input}
	m.match = append(m.match, m.rx.FindAllString(input, 0)...)
	m.count = len(m.match)
	return m.count > 0
}

func (m *Matcher) Match(input []byte, flags int) bool{
	return m.MatchString(string(input), 0)
}

func (m *Matcher) Groups() int{
	return m.count
}

func (m *Matcher) Index() []int{
	return m.rx.FindStringIndex(m.input)
}

func (m *Matcher) GroupString(index int) string{
	if m.count > index {
		return m.match[index]
	}
	return ""
}

type Regexp struct{
	pattern *regexp.Regexp
}

func (rx *Regexp) ReplaceAllString(input string, asdf string, flags int) string {
	return input
}

func (rx *Regexp) Matcher(input []byte, flags int) Matcher {
	return rx.MatcherString(string(input), 0)
}

func (rx *Regexp) NewMatcher() Matcher {
	return rx.MatcherString("", 0)
}

func (rx *Regexp) MatcherString(input string, flags int) Matcher {
	m := Matcher{
		input: input,
		rx: rx.pattern,
	}
	m.MatchString(input, 0)
	return m	
}


func MustCompile(input string, flags int) Regexp {
	pattern, _ := regexp.Compile(input)
	return Regexp{
		pattern: pattern,
	}
}