package parser

const (
	EXPECT_DIRECTIVE = 0
	EXPECT_DIRECTIVE_BOOLEAN
	EXPECT_DIRECTIVE_STRING

	EXPECT_VARIABLE
	EXPECT_VARIABLE_OR_KEY
	EXPECT_NEXT_VARIABLE

	EXPECT_OPERATOR
	EXPECT_ACTION
)

type directive struct {
	expectedEnd string
	expect int
}

var directives = map[string]*directive

type Tokenizer struct {
	buffer string
	index int
	expectedEnd string
	expect int
}

func (t * Tokenizer) Init(data string){
	t.expect = EXPECT_DIRECTIVE
	t.expectedEnd = " "
}


func (t * Tokenizer) NextToken() (string, error){
	kw := true
	limit := 1500 // avoid breaking?
	token := ""
	for kw {
		t.index++
		c := buffer[index]
		if c == t.expectedEnd{
			return token
		}else{
			token += c
		}
	}
	return "", error
}