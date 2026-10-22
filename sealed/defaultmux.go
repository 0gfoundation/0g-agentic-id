package main

import "net/http"

// The 0G storage SDK linked in for uploads (internal/dataplane) brings in
// net/http/pprof and expvar -- through go-ethereum's node package, which
// the SDK's common/rpc imports -- and their init functions register
// /debug/pprof/* and /debug/vars on http.DefaultServeMux. sealed serves
// only muxes of its own (internal/proxy), so nothing serves those routes
// today. Replacing the default mux drops them anyway, so that a later
// http.Handle, http.ListenAndServe(addr, nil) or fall-through to the
// default mux cannot publish profiles or process variables from the
// process that holds agent_seal_priv. A package's init functions run after
// those of every package it imports, so this runs after theirs.
func init() {
	http.DefaultServeMux = http.NewServeMux()
}
