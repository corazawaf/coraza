package types

// AnchoredVar stores the case preserved Original name and value
// of the variable
type AnchoredVar struct {
	Name  string
	Value string
}

// GetValue returns the value
func (v *AnchoredVar) GetValue() string {
	return v.Value
}

// GetName returns the name
func (v *AnchoredVar) GetName() string {
	return v.Name
}
