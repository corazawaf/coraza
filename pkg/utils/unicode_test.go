package utils

import(
	"testing"
)

func TestUnicode(t *testing.T){
	uni := &Unicode{}
	uni.Init()
	if uni.At(0x00a1) != 0x21{
		t.Error("Invalid unicode character")
	}
}