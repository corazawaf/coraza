package types

type RuleActionType int

const (
	ActionTypeMetadata      RuleActionType = 1
	ActionTypeDisruptive    RuleActionType = 2
	ActionTypeData          RuleActionType = 3
	ActionTypeNondisruptive RuleActionType = 4
	ActionTypeFlow          RuleActionType = 5
)
