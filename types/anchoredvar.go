package types

type AnchoredVar struct {
	Name  string
	Value string
}

// Get returns the value
func (v *AnchoredVar) getValue() string {
	return v.Value
}

// getName returns the name
func (v *AnchoredVar) getName() string {
	return v.Name
}
