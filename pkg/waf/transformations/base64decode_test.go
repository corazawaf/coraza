package transformations

import (
	"testing"
	"encoding/base64"
	"github.com/jptosso/coraza/test/utils"
)

func TestUnicodeString(t *testing.T) {
    data := utils.UnicodeString()
    encode := base64.StdEncoding.EncodeToString([]byte(data))
    decode := Base64decode(encode)
    if decode != data {
    	t.Errorf("Invalid base64 transformation")
    }
}

func TestHugeString(t *testing.T) {
    data := utils.GiantString(1000000)
    encode := base64.StdEncoding.EncodeToString([]byte(data))
    decode := Base64decode(encode)
    if decode != data {
    	t.Errorf("Invalid base64 transformation")
    }
}

func TestEmptyString(t *testing.T) {
	data := ""
    encode := base64.StdEncoding.EncodeToString([]byte(data))
    decode := Base64decode(encode)
    if decode != data {
    	t.Errorf("Invalid base64 transformation")
    }
}

func TestBinaryString(t *testing.T) {
    data := utils.BinaryString(1000)
    encode := base64.StdEncoding.EncodeToString([]byte(data))
    decode := Base64decode(encode)
    if decode != data {
    	t.Errorf("Invalid base64 transformation")
    }    
}