package transformations
import(
	"encoding/base64"
)

func Base64decode(data string) string{
	ndata, err := base64.StdEncoding.DecodeString(data)
	if err != nil{
		return data
	}
	return string(ndata)
}

//func doBase64decode(input string) string {
//    slen := len(input)
//    src := input
//    var j, x, i, n int
//    p := []byte{}
//    dst := []byte{}
//    olen := 0
//

//    /* First pass: check for validity and get output length */
//    for ;i < slen; i++ {
//        /* Skip spaces before checking for EOL */
//        x = 0
//        for i < slen && src[i] == ' '  {
//            i++
//            x++
//        }

//        /* Spaces at end of buffer are OK */
//        if( i == slen ){
//            break;
//        }

//        if( ( slen - i ) >= 2 && src[i] == '\r' && src[i + 1] == '\n' ){
//            continue;
//        }

//        if( src[i] == '\n' ){
//            continue;
//        }

//        /* Space inside a line is an error */
//        if( x != 0 ){
//            return input
//        }
//        j++
//        if( src[i] == '=' && j > 2 ){
//            return input
//        }

//        if( src[i] > 127 || base64_dec_map[src[i]] == 127 ){
//            return input
//        }

//        if( base64_dec_map[src[i]] < 64 && j != 0 ){
//            return input
//        }
//        n++
//    }

//    if n == 0 {
//        *olen = 0;
//        return( 0 );
//    }

//    n = ( ( n * 6 ) + 7 ) >> 3;
//    n -= j;

//    if( dst == NULL || dlen < n ) {
//        *olen = n;
//        return input
//    }

//    j = 3
//    n = 0
//    x = 0
//    p = dst
//	for ; i > 0; i-- {
//        if( *src == '\r' || *src == '\n' || *src == ' ' ){
//			src++
//            continue
//        }

//        j -= ( base64_dec_map[*src] == 64 );
//        x  = ( x << 6 ) | ( base64_dec_map[*src] & 0x3F );
//        n++
//        if( n == 4 ) {
//            n = 0;
//            if( j > 0 ) {
//            	p[0] = x >> 16
//            }
//            if( j > 1 ) {
//            	p[1] = x >> 16
//            }
//            if( j > 2 ) {
//            	p[2] = x >> 16
//            }
//        }
//		src++
//    }

//    olen = p - dst

//    return string(dst)
//}