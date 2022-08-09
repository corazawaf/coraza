package transformations

import "testing"

func BenchmarkB64Decode(b *testing.B) {
	tests := []string{
		"VGVzdENhc2U=",
		"P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		"VGVzdABDYXNl",
	}

	for _, tt := range tests {
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := base64decode(tt)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}
