// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"context"
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"testing"
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
	}

	for _, tc := range tests {
		tt := tc
		t.Run(fmt.Sprintf("%s/%s", tt.pattern, tt.input), func(t *testing.T) {

			rx := &rx{}
			opts := coraza.RuleOperatorOptions{
				Arguments: tt.pattern,
			}
			if err := rx.Init(opts); err != nil {
				t.Error(err)
			}
			waf := coraza.NewWAF()
			tx := waf.NewTransaction(context.Background())
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
