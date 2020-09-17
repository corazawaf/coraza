package utils

import (
	"testing"
)

func TestLibijection(t *testing.T){
	sqli := "' or ''='"
	xss := "<script>alert(123)</Script>"
	issqli, _ := IsSQLi(sqli)
	if !issqli{
		t.Error("Failed to detect sql injection")
	}

	if !IsXSS(xss){
		t.Error("Failed to detect Cross Site Scripting")
	}	
}