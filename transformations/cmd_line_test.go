package transformations

import "testing"

func BenchmarkCMDLine(b *testing.B) {
	tests := []string{
		"",
		"test",
		"C^OMMAND /C DIR",
		"\"command\" /c DiR",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := cmdLine(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
