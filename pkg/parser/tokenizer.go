package parser

const (
	EXPECT_DIRECTIVE = 0
	EXPECT_DIRECTIVE_BOOLEAN
	EXPECT_DIRECTIVE_STRING

	EXPECT_VARIABLE
	EXPECT_NEXT_VARIABLE

	EXPECT_OPERATOR
	EXPECT_ACTION
)

type directive struct {
	expectedEnd string
	expect int
}

type Tokenizer struct {
	buffer string
	index int
	expectedEnd string
	expect int
	escaped bool
}

func (t * Tokenizer) Init(data string){
	t.expect = EXPECT_DIRECTIVE
	t.expectedEnd = " "
}


func (t * Tokenizer) NextToken() (string, int, error){
	kw := true
	token := ""
	for kw {
		c := c.buffer[t.index]
		token += c
		if c == '\\'{
			t.escaped = true
			t.index++
			c = buffer[t.index]
		}else{
			t.escaped = false
		}
		if c == t.expectedEnd && !t.escaped{
			return token, t.nil
		}else{
			token += c
		}
		t.index++
	}
	return "", 0, errors.New("Cannot find token")
}

func (t * Tokenizer) parseDirective() (string, error){

}

func (t * Tokenizer) parseVariables() (string, error){
	kw := true
	modifiers := []string{"!", "&"}
	keyseparator := ":"
	separator := "|"
	cvar := nil
	for kw {
		c := t.buffer[t.index]
		token += c
		if c == '\\'{
			t.escaped = true
			t.index++
			c = buffer[t.index]
		}else{
			t.escaped = false
		}
		if c == t.expectedEnd && !t.escaped{
			return token, t.nil
		}else{
			token += c
		}
		t.index++
	}
}