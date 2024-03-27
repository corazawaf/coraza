// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestRx(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		{
			pattern: "som(.*)ta",
			input:   "somedata",
			want:    true,
		},
		{
			pattern: "som(.*)ta",
			input:   "notdata",
			want:    false,
		},
		{
			pattern: "ハロー",
			input:   "ハローワールド",
			want:    true,
		},
		{
			pattern: "ハロー",
			input:   "グッバイワールド",
			want:    false,
		},
		{
			pattern: `\xac\xed\x00\x05`,
			input:   "\xac\xed\x00\x05t\x00\x04test",
			want:    true,
		},
		{
			pattern: `\xac\xed\x00\x05`,
			input:   "\xac\xed\x00t\x00\x04test",
			want:    false,
		},
		{
			// Requires dotall
			pattern: `hello.*world`,
			input:   "hello\nworld",
			want:    true,
		},
		{
			// Requires multiline disabled by default
			pattern: `^hello.*world`,
			input:   "test\nhello\nworld",
			want:    false,
		},
		{
			// Makes sure multiline can be enabled by the user
			pattern: `(?m)^hello.*world`,
			input:   "test\nhello\nworld",
			want:    true,
		},
		{
			// Makes sure, (?s) passed by the user does not
			// break the regex.
			pattern: `(?s)hello.*world`,
			input:   "hello\nworld",
			want:    true,
		},
		{
			// Make sure user flags are also applied
			pattern: `(?i)hello.*world`,
			input:   "testHELLO\nworld",
			want:    true,
		},
		{
			// The so called DOLLAR_ENDONLY modifier in PCRE2 is meant to tweak the meaning of dollar '$'
			// so that it matches only at the very end of the string (see: https://www.pcre.org/current/doc/html/pcre2pattern.html#SEC6)
			// It seems that re2 already behaves like that by default.
			pattern: `123$`,
			input:   "123\n",
			want:    false,
		},
		{
			// Dollar endonly match
			pattern: `123$`,
			input:   "test123",
			want:    true,
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(fmt.Sprintf("%s/%s", tt.pattern, tt.input), func(t *testing.T) {

			opts := plugintypes.OperatorOptions{
				Arguments: tt.pattern,
			}
			rx, err := newRX(opts)
			if err != nil {
				t.Error(err)
			}
			waf := corazawaf.NewWAF()
			tx := waf.NewTransaction()
			tx.Capture = true
			res := rx.Evaluate(tx, tt.input)
			if res != tt.want {
				t.Errorf("want %v, got %v", tt.want, res)
			}
			/*
				vars := tx.GetCollection(variables.TX).Data()
				if vars["0"][0] != "somedata" {
					t.Error("rx1 failed")
				}
				if vars["1"][0] != "eda" {
					t.Error("rx1 failed")
				}
			*/
		})
	}
}

func BenchmarkRxSubstringVsMatch(b *testing.B) {
	str := "hello world; heelloo Woorld; hello; heeeelloooo wooooooorld;hello world; heelloo Woorld; hello; heeeelloooo wooooooorld;hello world; heelloo Woorld; hello; heeeelloooo wooooooorld;hello world; heelloo Woorld; hello; heeeelloooo wooooooorld;hello world; heelloo Woorld; hello; heeeelloooo wooooooorld;hello world; heelloo Woorld; hello; heeeelloooo wooooooorld;hello world; heelloo Woorld; hello; heeeelloooo wooooooorld;"
	rx := regexp.MustCompile(`((h.*e.*l.*l.*o.*)|\d+)`)
	b.Run("Find all RX", func(b *testing.B) {
		rx.FindStringSubmatch(str)
	})
	b.Run("Find only first", func(b *testing.B) {
		rx.MatchString(str)
	})
	b.Run("Find only N", func(b *testing.B) {
		rx.FindAllString(str, 3)
	})
}
