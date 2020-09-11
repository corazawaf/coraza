package transformations
import(
)

func Base64decode(data string) string{
	res := doBase64decode(data)
	if res == ""{
		return data
	}else{
		return res
	}
}

func doBase64decode(input string) string {
    slen := len(input)
    src := []byte(input)
    var j, x, i, n int
    dst := make([]byte, slen)
	base64_dec_map := []byte{
	    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	    127, 127, 127,  62, 127, 127, 127,  63,  52,  53,
	     54,  55,  56,  57,  58,  59,  60,  61, 127, 127,
	    127,  64, 127, 127, 127,   0,   1,   2,   3,   4,
	      5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
	     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
	     25, 127, 127, 127, 127, 127, 127,  26,  27,  28,
	     29,  30,  31,  32,  33,  34,  35,  36,  37,  38,
	     39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
	     49,  50,  51, 127, 127, 127, 127, 127,
	}

    /* First pass: check for validity and get output length */
    for ;i < slen; i++ {
        /* Skip spaces before checking for EOL */
        x = 0
        for i < slen && src[i] == ' '  {
            i++
            x++
        }

        /* Spaces at end of buffer are OK */
        if( i == slen ){
            break
        }

        if ( slen - i ) >= 2 && src[i] == '\r' && src[i + 1] == '\n' {
            continue
        }

        if( src[i] == '\n' ){
            continue
        }

        /* Space inside a line is an error */
        if( x != 0 ){
            return input
        }
        if src[i] == '=' {
        	j++
        	if j > 2{
        		//ERROR
            	return input
        	}
        }

        if( src[i] > 127 || base64_dec_map[src[i]] == 127 ){
        	//ERROR
            return input
        }

        if( base64_dec_map[src[i]] < 64 && j != 0 ){
        	//ERROR
            return input
        }
        n++
    }

    n = ( ( n * 6 ) + 7 ) >> 3
    n -= j

    j = 3
    n = 0
    x = 0
    srcc := 0

    dstc := 0

	for ; i > 0; i-- {
        if( src[srcc] == '\r' || src[srcc] == '\n' || src[srcc] == ' ' ){
			srcc++
            continue
        }
        if base64_dec_map[src[srcc]] == 64 {
        	j--
        }
        
        x  = ( x << 6 ) | int( base64_dec_map[src[srcc]] & 0x3F )
        n++
        if( n == 4 ) {
            n = 0
            if( j > 0 ) {
            	dst[dstc] = byte(x >> 16)
            	dstc++
            }
            if( j > 1 ) {
            	dst[dstc] = byte(x >> 8)
            	dstc++
            }
            if( j > 2 ) {
            	dst[dstc] = byte(x)
            	dstc++
            }
        }
		srcc++
    }

    return string(dst[:dstc])
}