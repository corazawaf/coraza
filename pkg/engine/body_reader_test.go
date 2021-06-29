package engine

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestBodyReaderMemory(t *testing.T) {
	br := NewBodyReader("/tmp", 500)
	br.Write([]byte("test"))
	buf := new(strings.Builder)
	io.Copy(buf, br.Reader())
	if buf.String() != "test" {
		t.Error("Failed to get BodyReader from memory")
	}
	br.Close()
}

func TestBodyReaderFile(t *testing.T) {
	// body reader memory limit is 1 byte
	br := NewBodyReader("/tmp", 1)
	br.Write([]byte("test"))
	buf := new(strings.Builder)
	io.Copy(buf, br.Reader())
	if buf.String() != "test" {
		t.Error("Failed to get BodyReader from file")
	}
	// Let's check if files are being deleted
	f := br.Reader().(*os.File)
	if _, err := os.Stat(f.Name()); os.IsNotExist(err) {
		t.Error("BodyReader's Tmp file does not exist")
	}
	br.Close()
	if _, err := os.Stat(f.Name()); err == nil {
		t.Error("BodyReader's Tmp file was not deleted")
	}
}

func TestBodyReaderWriteFromReader(t *testing.T) {
	br := NewBodyReader("/tmp", 5)
	b := strings.NewReader("test")
	io.Copy(br, b)
	buf := new(strings.Builder)
	io.Copy(buf, br.Reader())
	if buf.String() != "test" {
		t.Error("Failed to write bodyreader from io.Reader")
	}
	br.Close()
}
