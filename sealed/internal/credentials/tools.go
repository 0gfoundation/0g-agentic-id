package credentials

// The credential sockets' endpoints as MCP tools (internal/sealmcp), for a
// framework that mounts the runtime's tools (framework.RuntimeTools). The
// credential socket's tools are listed by the sign socket's MCP server
// (Tools), so a framework mounts one server for its runtime's tools; the
// reveal socket serves its one tool itself (POST /mcp on that socket), so a
// harness that keeps the socket from its tools keeps the tool from them too.

import (
	"fmt"
	"net/http"

	"seal-verify/internal/evmsign"
	"seal-verify/internal/sealmcp"
)

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func object(props map[string]any, required ...string) map[string]any {
	o := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

// Tools are the credential socket's endpoints as tools, each served by that
// socket's handler.
func (s *Store) Tools() []sealmcp.Tool {
	h := s.HarnessHandler()
	tools := harnessTools()
	for i := range tools {
		tools[i].Handler = h
	}
	return tools
}

// ServeRevealTool turns on the reveal socket's MCP tool.
func (s *Store) ServeRevealTool() { s.revealTool.Store(true) }

func (s *Store) revealMCP(h http.Handler) http.Handler {
	server := &sealmcp.Server{
		Name:         "seal-reveal",
		Version:      "1",
		Instructions: "A credential's value itself, when your owner allows it.",
		Tools:        revealTools,
		Handler:      h,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.revealTool.Load() {
			http.NotFound(w, r)
			return
		}
		server.ServeHTTP(w, r)
	})
}

func harnessTools() []sealmcp.Tool {
	return []sealmcp.Tool{
		{
			Name: "seal_credentials",
			Description: "List your credentials: name, description, hosts, positions, expiry, and for a signing entry its signer — never values. " +
				"Use one by writing [[credential:<name>]] where the key goes ([[credential:derived:<name>]] for an entry a token request made). " +
				"An entry with status awaiting_login is a login your owner has not finished.",
			Schema: object(map[string]any{}),
			Method: http.MethodGet,
			Path:   "/credentials",
		},
		{
			Name:        "seal_credential_token",
			Description: "Run an entry's token request (for example a refresh token for an access token). The result comes back as derived entries, used by placeholder; you never see the token.",
			Schema: object(map[string]any{
				"name":   str("The entry whose token request to run."),
				"params": map[string]any{"type": "object", "description": "Parameters the entry's token request takes, if any, as string values."},
			}, "name"),
			Method: http.MethodPost,
			Path:   "/credentials/token",
			Prepare: func(args map[string]any) (any, error) {
				if err := sealmcp.Allow(args, "name", "params"); err != nil {
					return nil, err
				}
				return args, sealmcp.Require(args, "name")
			},
		},
		{
			Name: "seal_credential_request",
			Description: "Ask your owner for a credential you do not have (op \"add\"), or to log you in to the MCP server at `url` (op \"login\"). " +
				"Returns an auth_req_id; your owner sees the request in their own session (or by email) and answers there. " +
				"Say in a sentence what you asked for and why, then end your turn; you are told once they have answered. `reason` is shown to your owner as your words.",
			Schema: object(map[string]any{
				"op":     map[string]any{"type": "string", "enum": []string{"add", "login"}},
				"name":   str("The name the entry should have."),
				"preset": str("A known service preset, if one fits."),
				"url":    str("For op login: the MCP server's URL."),
				"reason": str("Why you need it, in plain words."),
			}, "op", "name", "reason"),
			Method: http.MethodPost,
			Path:   "/credentials/request",
			Prepare: func(args map[string]any) (any, error) {
				if err := sealmcp.Allow(args, "op", "name", "preset", "url", "reason"); err != nil {
					return nil, err
				}
				return args, sealmcp.Require(args, "op", "name", "reason")
			},
		},
		{
			Name: "seal_credential_sign",
			Description: "Sign with a wallet entry your owner gave you; returns the signature, never the key. Give the entry's `name` and exactly one of " +
				"`personal_sign` ({message} or {message_hex}), `typed_data` ({domain, types, primaryType, message}) or `transaction` (the fields seal_sign_transaction takes). " +
				"Write amounts as decimal or 0x strings.",
			Schema: object(map[string]any{
				"name":          str("The wallet entry."),
				"personal_sign": map[string]any{"type": "object"},
				"typed_data":    map[string]any{"type": "object"},
				"transaction":   map[string]any{"type": "object"},
			}, "name"),
			Method:  http.MethodPost,
			Path:    "/credentials/sign",
			Prepare: prepareWalletSign,
		},
		{
			Name:        "seal_credential_delete",
			Description: "Delete an entry you derived through a token request. Your owner's entries are theirs to change.",
			Schema:      object(map[string]any{"name": str("The derived entry.")}, "name"),
			Method:      http.MethodDelete,
			Path:        "/credentials/{name}",
			Prepare: func(args map[string]any) (any, error) {
				return nil, sealmcp.Allow(args)
			},
		},
	}
}

func revealTools() []sealmcp.Tool {
	return []sealmcp.Tool{{
		Name: "seal_credential_reveal",
		Description: "Get a credential's value itself, for a tool that cannot take a placeholder. Unless your owner allowed it in advance, the answer is 403 authorization_pending with an auth_req_id: " +
			"your owner decides in their own session; end your turn, and when you are told they approved, call again (an approval is used once). 403 access_denied means they refused. " +
			"Pass the value only to the tool that needs it: never print it, log it, write it to a file or to memory, or put it in a reply. `reason` is shown to your owner as your words.",
		Schema: object(map[string]any{
			"name":   str("The entry."),
			"reason": str("Why you need the value itself, in plain words."),
		}, "name", "reason"),
		Method: http.MethodPost,
		Path:   "/credentials/reveal",
		Prepare: func(args map[string]any) (any, error) {
			if err := sealmcp.Allow(args, "name", "reason"); err != nil {
				return nil, err
			}
			return args, sealmcp.Require(args, "name", "reason")
		},
	}}
}

func prepareWalletSign(args map[string]any) (any, error) {
	if err := sealmcp.Allow(args, "name", "personal_sign", "typed_data", "transaction"); err != nil {
		return nil, err
	}
	if err := sealmcp.Require(args, "name"); err != nil {
		return nil, err
	}
	if err := evmsign.SafeNumbers(args["typed_data"], "typed_data"); err != nil {
		return nil, err
	}
	if td, ok := args["typed_data"].(map[string]any); ok {
		if err := evmsign.WithDomainType(td); err != nil {
			return nil, fmt.Errorf("typed_data: %v", err)
		}
	}
	if tx, ok := args["transaction"].(map[string]any); ok {
		body, err := evmsign.TransactionArgs(tx)
		if err != nil {
			return nil, err
		}
		args["transaction"] = body
	}
	return args, nil
}
