package rpc

import "encoding/json"

const (
	serviceMethodSeparator = "_"
)

type jsonRequest struct {
	Method  string          `json:"method"`
	Version string          `json:"jsonrpc"`
	Id      json.RawMessage `json:"id,omitempty"`
	Payload json.RawMessage `json:"params,omitempty"`
}

// Args
type Args struct {
	S string
}

// Result
type Result struct {
	Output string
}

// API
type API struct {
	Namespace    string
	Version      string
	Service      interface{}
	Enabled      bool
	AuthRequired string
}
