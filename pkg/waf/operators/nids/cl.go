package nids

import(
	"regexp"
	"strings"
	"strconv"
)

type NidCl struct{}

func (n *NidCl) Evaluate(nid string) bool{
	re, err := regexp.Compile(`[^\dk]`)
	if err != nil {
		return false
	}	
	nid = strings.ToLower(nid)
	nid = re.ReplaceAllString(nid, "")
	rut, _ := strconv.Atoi(nid[:len(nid)-1])
	dv := nid[len(nid)-1:len(nid)]

	var sum = 0
	var factor = 2
	var ndv = "0"
	for ; rut != 0; rut /= 10 {
		sum += rut % 10 * factor
		if factor == 7 {
			factor = 2
		} else {
			factor++
		}
	}

	if val := 11 - (sum %11) ; val == 11 {
		ndv = "0"
	} else if val == 10 {
		ndv = "k"
	} else {
		ndv = strconv.Itoa(val)
	}
	return ndv == dv
}