package types

import "github.com/corazawaf/coraza/v3/internal/corazawaf"

// Transaction is created from a WAF instance to handle web requests and responses,
// it contains a copy of most WAF configurations that can be safely changed.
// Transactions are used to store all data like URLs, request and response
// headers. Transactions are used to evaluate rules by phase and generate disruptive
// actions. Disruptive actions can be read from *tx.Interruption.
// It is safe to manage multiple transactions but transactions themself are not
// thread safe
type Transaction interface {
	corazawaf.Transaction
	// UnixTimestamp returns the transaction timestamp
	UnixTimestamp() int64
}
