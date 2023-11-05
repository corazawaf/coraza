package regexp

import (
	"testing"
)

func TestCompile(t *testing.T) {
	_, err := Compile(`[]`)
	if err == nil {
		t.Fatalf("expected error")
	}

	_, err = Compile("[a-z]+")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMustCompile(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustCompile panicked with error: %v", r)
		}
	}()
	MustCompile("[a-z]+")
}

func TestCompileCompilesJustOnce(t *testing.T) {
	re, _ := Compile("[a-z]+")
	lre := re.(*lazyRegexp)

	if lre.re != nil {
		t.Fatalf("expected nil")
	}

	m := re.Match([]byte("abc"))
	if !m {
		t.Fatalf("expected match")
	}

	if lre.re == nil {
		t.Fatalf("unexpected nil")
	}
}
