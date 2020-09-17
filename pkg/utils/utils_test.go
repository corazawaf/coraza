package utils

import (
	"testing"
)

func TestOpenFile(t *testing.T){
	b, err := OpenFile("https://github.com/")
	if len(b) == 0 || err != nil{
		t.Error("Failed to read remote file with OpenFile")
	}

	b, err = OpenFile("../../readme.md")
	if len(b) == 0 || err != nil{
		t.Error("Failed to read local file with OpenFile")
	}	
}

func TestRandomString(t *testing.T){
	s1 := RandomString(10)
	s2 := RandomString(10)
	if len(s1)+len(s2) != 20{
		t.Error("Failed to generate random string")
	}

	if s1 == s2 {
		t.Error("Failed to generate entropy")
	}
}