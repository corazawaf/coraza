package operators

// We run tests both with Go and TinyGo. TinyGo does not support the default encoding/json package so we generate
// marshalers using tinyjson. Unfortunately tinyjson does not work properly with _test.go files so we define private
// structs here instead.

// testing_tinyjson.go can be regenerated with
//
// go run github.com/CosmWasm/tinyjson/tinyjson@v0.9.0 ./operators/testing.go

//tinyjson:json
type test struct {
	Input string `json:"input"`
	Param string `json:"param"`
	Name  string `json:"name"`
	Ret   int    `json:"ret"`
	Type  string `json:"type"`
}

//tinyjson:json
type tests []test
