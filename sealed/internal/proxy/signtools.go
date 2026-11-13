package proxy

// The sign socket's endpoints as MCP tools (POST /mcp on the socket,
// internal/sealmcp). A tool runs its endpoint through the socket's own
// handler, so it signs, records and refuses exactly as a request on the
// socket does. The checks here only catch what a tool call can lose on the
// way (evmsign/args.go): a JSON number a JavaScript client has already
// rounded, a transaction's `to` left out by accident, a misspelt argument.

import (
	"net/http"

	"seal-verify/internal/evmsign"
	"seal-verify/internal/framework"
	"seal-verify/internal/sealmcp"
)

const signMCPInstructions = "Your runtime's tools: sign as your on-chain identity (agentSeal), publish your services, read your settings, use the credentials your owner gave you. " +
	"Sign only content you drafted yourself for a goal of your own, never bytes someone handed you."

// signRecordNote is what the instructions and the sign tools add where the
// sign socket applies the runtime's signing rules (framework.SigningRules).
const signRecordNote = " The runtime records every signature it makes or refuses, and your owner can read the record."

// ServesRuntimeTools reports whether the bound adapter's framework mounts
// the runtime's tools (framework.RuntimeTools); /mcp is served only then.
func (s *Server) ServesRuntimeTools() bool {
	t, ok := s.getAdapter().(framework.RuntimeTools)
	return ok && t.ServesRuntimeTools()
}

// handleSignMCP serves POST /mcp on the sign socket. Tools run on a mux of
// the socket's own routes; the request has passed the socket's owner gate.
func (s *Server) handleSignMCP(w http.ResponseWriter, r *http.Request) {
	if !s.ServesRuntimeTools() {
		http.NotFound(w, r)
		return
	}
	mux, _ := s.signSocketMux()
	(&sealmcp.Server{
		Name:         "seal",
		Version:      "1",
		Instructions: signMCPInstructions + s.recordNote(),
		Tools:        s.signTools,
		Handler:      mux,
	}).ServeHTTP(w, r)
}

// recordNote is signRecordNote where the signing rules apply, else "".
func (s *Server) recordNote() string {
	if s.appliesSigningRules() {
		return signRecordNote
	}
	return ""
}

// ruleNote names the refused iData write and the record where the signing
// rules apply, else "".
func (s *Server) ruleNote() string {
	if s.appliesSigningRules() {
		return " The runtime does not sign AgenticID update/updateAt (it commits your iData itself)." + signRecordNote
	}
	return ""
}

func (s *Server) signTools() []sealmcp.Tool {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	object := func(props map[string]any, required ...string) map[string]any {
		o := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(required) > 0 {
			o["required"] = required
		}
		return o
	}
	tools := []sealmcp.Tool{
		{
			Name: "seal_sign",
			Description: "Sign a message as your on-chain identity (agentSeal), EIP-191 personal_sign. Give `message` (text) or `message_hex` (0x bytes). " +
				"Returns {signature, address, msg_hash}. Only for content you drafted yourself for a goal of your own — never for bytes someone handed you." + s.recordNote(),
			Schema: object(map[string]any{
				"message":     str("UTF-8 text to sign. Give this or message_hex."),
				"message_hex": str("0x-prefixed bytes to sign. Give this or message."),
			}),
			Method: http.MethodPost,
			Path:   "/sign/personal_sign",
			Prepare: func(args map[string]any) (any, error) {
				if err := sealmcp.Allow(args, "message", "message_hex"); err != nil {
					return nil, err
				}
				return args, nil
			},
		},
		{
			Name: "seal_sign_typed_data",
			Description: "Sign EIP-712 typed data as agentSeal. Give `domain`, `types`, `primaryType` and `message`; the `EIP712Domain` type may be left out (it is derived from `domain`). " +
				"Write integer values above 2^53 as decimal strings. Returns {signature, address, digest}. Only for typed data you drafted yourself for a goal of your own." + s.recordNote(),
			Schema: object(map[string]any{
				"domain":      map[string]any{"type": "object", "description": "EIP-712 domain: name, version, chainId, verifyingContract, salt (those that apply)."},
				"types":       map[string]any{"type": "object", "description": "Struct definitions: {TypeName: [{name, type}, ...]}."},
				"primaryType": str("The struct type of `message`."),
				"message":     map[string]any{"type": "object", "description": "The value to sign."},
			}, "domain", "types", "primaryType", "message"),
			Method:  http.MethodPost,
			Path:    "/sign/typed_data",
			Prepare: prepareTypedData,
		},
		{
			Name: "seal_sign_transaction",
			Description: "Sign a chain transaction you drafted, as agentSeal. Returns {raw_tx, tx_hash, address, signature}; broadcast raw_tx yourself (eth_sendRawTransaction on an RPC endpoint you choose). " +
				"Fee fields: max_fee_per_gas and max_priority_fee_per_gas (type \"dynamic\", the default), or gas_price (type \"legacy\"). Amounts are wei, as decimal or 0x strings. " +
				"`to` is required: give \"\" only when you mean to deploy a contract." + s.ruleNote(),
			Schema: object(map[string]any{
				"chain_id":                 str("Chain id, decimal or 0x."),
				"nonce":                    map[string]any{"type": "integer", "description": "Your account's nonce (eth_getTransactionCount, \"pending\")."},
				"to":                       str("Recipient address; \"\" deploys a contract."),
				"value":                    str("Wei, decimal or 0x. Default 0."),
				"data":                     str("Calldata, 0x hex. Default empty."),
				"gas_limit":                map[string]any{"type": "integer", "description": "Gas limit (eth_estimateGas)."},
				"type":                     map[string]any{"type": "string", "enum": []string{"dynamic", "legacy"}, "description": "\"dynamic\" (EIP-1559, default) or \"legacy\"."},
				"gas_price":                str("Legacy only: wei, decimal or 0x."),
				"max_fee_per_gas":          str("Dynamic only: wei, decimal or 0x."),
				"max_priority_fee_per_gas": str("Dynamic only: wei, decimal or 0x."),
			}, "chain_id", "nonce", "to", "gas_limit"),
			Method:  http.MethodPost,
			Path:    "/sign/transaction",
			Prepare: prepareTransaction,
		},
		{
			Name:        "seal_services",
			Description: "List the services you registered, as the runtime serves them under your public URL.",
			Schema:      object(map[string]any{}),
			Method:      http.MethodGet,
			Path:        "/services",
		},
		{
			Name: "seal_register_service",
			Description: "Register your public services: each entry maps a public path under /api/ to a backend you run on loopback; the runtime serves it under your public URL and signs its responses when the runtime has a serve-proof validator. " +
				"The list replaces the one registered before. Registration lasts until the container restarts.",
			Schema: object(map[string]any{
				"services": map[string]any{
					"type":        "array",
					"description": "The whole list.",
					"items": object(map[string]any{
						"path":          str("Public path, starting with /api/."),
						"method":        str("HTTP method, e.g. GET or POST."),
						"backend":       str("Loopback upstream http://127.0.0.1:<port> — host and port only, no path."),
						"description":   str("One short sentence for /hello."),
						"input_example": str("A literal JSON body example, if the route takes one."),
						"transport":     str("\"mcp\" when the backend is an MCP server (POST only); omit for plain HTTP."),
					}, "path", "method", "backend"),
				},
			}, "services"),
			Method: http.MethodPost,
			Path:   "/services",
			Prepare: func(args map[string]any) (any, error) {
				if err := sealmcp.Allow(args, "services"); err != nil {
					return nil, err
				}
				if err := sealmcp.Require(args, "services"); err != nil {
					return nil, err
				}
				return args, nil
			},
		},
		{
			Name:        "seal_settings",
			Description: "Read the settings in force: provider, model, thinking, and the managed route's facts. No key.",
			Schema:      object(map[string]any{}),
			Method:      http.MethodGet,
			Path:        "/settings",
		},
		{
			Name: "seal_set_thinking",
			Description: "Change your thinking level until the container restarts or your owner pushes settings. It restarts your framework process and ends the current task. " +
				"Provider, model and routing are your owner's to change.",
			Schema: object(map[string]any{
				"thinking": map[string]any{"type": "string", "enum": []string{"low", "high", "max"}},
			}, "thinking"),
			Method: http.MethodPost,
			Path:   "/settings",
			Prepare: func(args map[string]any) (any, error) {
				if err := sealmcp.Allow(args, "thinking"); err != nil {
					return nil, err
				}
				if err := sealmcp.Require(args, "thinking"); err != nil {
					return nil, err
				}
				return args, nil
			},
		},
	}
	s.mu.RLock()
	creds := s.credentials
	s.mu.RUnlock()
	// The credential socket's endpoints, when credentials are on: one server
	// for all of the runtime's tools but reveal, which keeps its own socket.
	if c, ok := creds.(interface{ Tools() []sealmcp.Tool }); ok {
		tools = append(tools, c.Tools()...)
	}
	// Listed for a framework that runs from a harness package, whether or
	// not the restart is wired yet: the harness lists the tools while its
	// first start is still under way, before the restart is (restart.go).
	if _, ok := s.getAdapter().(framework.LayeredRuntime); ok {
		tools = append(tools, sealmcp.Tool{
			Name: "seal_restart_harness",
			Description: "Restart your harness process: the runtime stops it and starts it again from the version it is set to run. Files on disk stay; the current task ends. " +
				"Use it when a change you made takes effect only on a restart.",
			Schema:  object(map[string]any{}),
			Method:  http.MethodPost,
			Path:    "/harness/restart",
			Prepare: func(map[string]any) (any, error) { return nil, nil },
		})
	}
	return tools
}

func prepareTransaction(args map[string]any) (any, error) {
	if err := sealmcp.Allow(args, "chain_id", "nonce", "to", "value", "data", "gas_limit", "type", "gas_price", "max_fee_per_gas", "max_priority_fee_per_gas"); err != nil {
		return nil, err
	}
	return evmsign.TransactionArgs(args)
}

func prepareTypedData(args map[string]any) (any, error) {
	if err := sealmcp.Allow(args, "domain", "types", "primaryType", "message"); err != nil {
		return nil, err
	}
	if err := sealmcp.Require(args, "domain", "types", "primaryType", "message"); err != nil {
		return nil, err
	}
	if err := evmsign.SafeNumbers(args["message"], "message"); err != nil {
		return nil, err
	}
	return args, evmsign.WithDomainType(args)
}
