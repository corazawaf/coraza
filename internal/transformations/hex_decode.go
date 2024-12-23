package transformations

// import (
// 	"encoding/hex"

// 	"github.com/corazawaf/coraza/v3/internal/strings"
// )

// func hexDecode(data string) (string, bool, error) {
// 	src := []byte(data)

// 	if len(src)%2 != 0 {
// 		src = src[:len(src)-1]
// 	}
// 	dst := make([]byte, hex.DecodedLen(len(src)))

// 	_, err := hex.Decode(dst, src)
// 	if err != nil {
// 		return "", false, err
// 	}

// 	return strings.WrapUnsafe(dst), true, nil
// }

// // escapePrintableAndNonPrintable converts printable characters directly, and non-printable bytes to \xNN format.
// func escapePrintableAndNonPrintable(data []byte) string {
// 	var result strings.Builder
// 	for _, b := range data {
// 		if b >= 32 && b <= 126 { // Printable ASCII characters
// 			result.WriteByte(b)
// 		} else {
// 			// Non-printable characters, format as \xNN
// 			result.WriteString(fmt.Sprintf("\\x%02x", b))
// 		}
// 	}
// 	return result.String()
// }

// package transformations

// // hexDecode decodes a hexadecimal-encoded string into a string representation.
// // Invalid or incomplete hex sequences are ignored.
// func hexDecode(data string) (string, bool, error) {
// 	// Filter out invalid characters
// 	removeNext := len(data)%2 == 0
// 	cleaned := make([]byte, 0, len(data)*2)
// 	for i := 0; i < len(data); i++ {
// 		if cstrings.ValidHex(data[i]) {
// 			cleaned = append(cleaned, data[i])
// 			continue
// 		}
// 		if removeNext {
// 			i++
// 			removeNext = false
// 		}
// 	}

// 	// Drop the last character for odd-length strings
// 	if len(cleaned)%2 != 0 {
// 		cleaned = cleaned[:len(cleaned)-1]
// 	}

// 	// Decode cleaned input
// 	decoded := make([]byte, hex.DecodedLen(len(cleaned)))
// 	_, err := hex.Decode(decoded, cleaned)
// 	if err != nil {
// 		return "", false, fmt.Errorf("failed to decode: %w", err)
// 	}

// 	return cstrings.WrapUnsafe(decoded), true, nil
// }

// func hexDecode(data string) (string, bool, error) {
// 	src := []byte(data)
// 	dst := make([]byte, 0, hex.DecodedLen(len(src)))

// 	var processed int

// 	for {
// 		if processed >= len(src) {
// 			break
// 		}
// 		s := src[processed:]
// 		d := make([]byte, hex.DecodedLen(len(s)))
// 		n, err := hex.Decode(d, s)
// 		if err != nil {
// 			return "", false, fmt.Errorf("failed to decode: %w", err)
// 		}
// 		dst = append(dst, d...)

// 		if processed < len(dst) {
// 			// will try to start from the next character after invalid
// 			processed = processed + n + 1
// 			fmt.Println("here", processed)
// 		}
// 	}

// 	return cstrings.WrapUnsafe(dst), true, nil
// }

// func hexDecodeFrom()

// const (
// 	hextable        = "0123456789abcdef"
// 	reverseHexTable = "" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff" +
// 		"\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
// 		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
// )

// func hDecode(dst, src []byte) {
// 	j := 1
// OUT:
// 	for j < len(src) {
// 		p := src[j-1]
// 		q := src[j]

// 		a := reverseHexTable[p]
// 		b := reverseHexTable[q]
// 		if a > 0x0f {
// 			// skip the symbol and continue with the next as first
// 			j++
// 			continue
// 		}
// 		if b > 0x0f {
// 			if j+1 < len(src) {
// 				b := reverseHexTable[src[j+1]]
// 				if b > 0x0f {
// 					j += 2
// 					continue
// 				}
// 			} else {
// 				break OUT
// 			}
// 		}
// 		dst = append(dst, (a<<4)|b)
// 		j += 2
// 	}
// }
