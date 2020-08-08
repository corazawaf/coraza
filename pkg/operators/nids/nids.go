package nids

type Nid interface {
	Evaluate(string) bool
}

func NidMap() map[string]Nid {
	return map[string]Nid{
		"us": &NidUs{},
		"cl": &NidCl{},
	}
}