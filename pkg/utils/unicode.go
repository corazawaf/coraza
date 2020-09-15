// Copyright 2020 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"fmt"
	"strings"
	"sync"
)

//UnicodeMapping Public unicode mapping object
var UnicodeMapping *Unicode

type Unicode struct {
	wmap map[int]int
	mux  *sync.RWMutex
}

func (u *Unicode) Init() {
	//TODO find a better method to do this
	text := []string{
		//defaults
		"3002:2e ff61:2e ff0e:2e 002e:2e",
		//20127 (US-ASCII)
		"00a0:20 00a1:21 00a2:63 00a4:24 00a5:59 00a6:7c 00a9:43 00aa:61 00ab:3c 00ad:2d 00ae:52 00b2:32 00b3:33 00b7:2e 00b8:2c 00b9:31 00ba:6f 00bb:3e 00c0:41 00c1:41 00c2:41 00c3:41 00c4:41 00c5:41 00c6:41 00c7:43 00c8:45 00c9:45 00ca:45 00cb:45 00cc:49 00cd:49 00ce:49 00cf:49 00d0:44 00d1:4e 00d2:4f 00d3:4f 00d4:4f 00d5:4f 00d6:4f 00d8:4f 00d9:55 00da:55 00db:55 00dc:55 00dd:59 00e0:61 00e1:61 00e2:61 00e3:61 00e4:61 00e5:61 00e6:61 00e7:63 00e8:65 00e9:65 00ea:65 00eb:65 00ec:69 00ed:69 00ee:69 00ef:69 00f1:6e 00f2:6f 00f3:6f 00f4:6f 00f5:6f 00f6:6f 00f8:6f 00f9:75 00fa:75 00fb:75 00fc:75 00fd:79 00ff:79 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0152:4f 0153:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0189:44 0191:46 0192:66 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02cb:60 02cd:5f 02dc:7e 0300:60 0302:5e 0303:7e 030e:22 0331:5f 0332:5f 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2013:2d 2014:2d 2018:27 2019:27 201a:2c 201c:22 201d:22 201e:22 2022:2e 2026:2e 2032:27 2035:60 2039:3c 203a:3e 2122:54 ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e",
	}
	u.wmap = map[int]int{}

	for _, l := range text {
		spl := strings.Split(l, " ")
		for _, l2 := range spl {
			spl2 := strings.Split(l2, ":")
			var b1, b2 int
			fmt.Sscanf(spl2[0], "%x", &b1)
			fmt.Sscanf(spl2[1], "%x", &b2)
			if b1 >= 0 && b1 <= 65535 {
				u.wmap[b1] = b2
			}
		}
	}
	u.mux = &sync.RWMutex{}
}

//At Get unicode mapping for input
func (u *Unicode) At(input int) int {
	u.mux.RLock()
	defer u.mux.RUnlock()
	return u.wmap[input]
}

// InitUnicodeMapping creates unicode global mappings
func InitUnicodeMapping() {
	if UnicodeMapping != nil {
		return
	}
	UnicodeMapping = &Unicode{}
	UnicodeMapping.Init()
}
