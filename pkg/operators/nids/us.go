package nids

import(
	"regexp"
	"strconv"
)

type NidUs struct{}

func (n *NidUs) Evaluate(nid string) bool{
	re, err := regexp.Compile(`[^\d]`)
	if err != nil {
		return false
	}	
	nid = re.ReplaceAllString(nid, "")
	if len(nid) < 9{
		return false
	}
	area, _ := strconv.Atoi(nid[0:2])
	group, _ := strconv.Atoi(nid[3:4])
	serial, _ := strconv.Atoi(nid[5:8])
	if area == 0 || group == 0 || serial == 0 || area >= 740 || area == 666{
		return false
	}
	
	sequence := true
	equals := true
	prev, _ := strconv.Atoi(string(nid[0]))
	for i := 1;i < len(nid);i++{
		curr, _ := strconv.Atoi(string(nid[i]))
		if prev != curr{
			equals = false
		}
		if curr != prev+1{
			sequence = false
		}
		prev = curr
	}

	return !(sequence || equals)
}