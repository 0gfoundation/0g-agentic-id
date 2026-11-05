package credentials

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"seal-verify/internal/credproxy"
)

const maxSocketBody = 64 << 10

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, e *credproxy.Error) {
	body := map[string]string{"code": e.Code, "message": e.Message}
	if e.Code == CodePending {
		body = map[string]string{"code": e.Code, "auth_req_id": e.Message, "message": "waiting for the owner to decide; send the same request again once decided"}
	}
	writeJSON(w, e.Status, body)
}

func readJSON(r *http.Request, v any) *credproxy.Error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxSocketBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &credproxy.Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "invalid JSON body: " + err.Error()}
	}
	return nil
}

// HarnessHandler serves /run/seal-cred.sock: list, token requests, wallet
// signatures, requests for the owner, deleting derived entries, and events.
// It never returns a value.
func (s *Store) HarnessHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /credentials", func(w http.ResponseWriter, r *http.Request) {
		list := s.List()
		if list == nil {
			list = []EntryInfo{}
		}
		writeJSON(w, http.StatusOK, list)
	})
	// git's credential helper: the username and the placeholder for host,
	// in git's own key=value form.
	mux.HandleFunc("GET /credentials/git", func(w http.ResponseWriter, r *http.Request) {
		user, name, ok := s.reg.BasicFor(r.URL.Query().Get("host"))
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "username="+user+"\npassword="+credproxy.Placeholder(name)+"\n")
	})
	mux.HandleFunc("POST /credentials/token", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name   string            `json:"name"`
			Params map[string]string `json:"params"`
		}
		if e := readJSON(r, &in); e != nil {
			writeErr(w, e)
			return
		}
		out, e := s.Token(r.Context(), in.Name, in.Params)
		if e != nil {
			writeErr(w, e)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": out})
	})
	mux.HandleFunc("POST /credentials/sign", func(w http.ResponseWriter, r *http.Request) {
		var in SignRequest
		if e := readJSON(r, &in); e != nil {
			writeErr(w, e)
			return
		}
		out, e := s.WalletSign(in)
		if e != nil {
			writeErr(w, e)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /credentials/request", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Op     string `json:"op"`
			Name   string `json:"name"`
			Preset string `json:"preset,omitempty"`
			URL    string `json:"url,omitempty"`
			Reason string `json:"reason"`
		}
		if e := readJSON(r, &in); e != nil {
			writeErr(w, e)
			return
		}
		params := map[string]string{}
		if in.Preset != "" {
			params["preset"] = in.Preset
		}
		if in.URL != "" {
			params["url"] = in.URL
		}
		p, e := s.Request(in.Op, in.Name, params, in.Reason)
		if e != nil {
			writeErr(w, e)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"auth_req_id": p.AuthReqID, "expires_at": p.ExpiresAt})
	})
	mux.HandleFunc("DELETE /credentials/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := s.DeleteDerived(r.PathValue("name")); err != nil {
			var ce *credproxy.Error
			if errors.As(err, &ce) {
				writeErr(w, ce)
				return
			}
			writeErr(w, &credproxy.Error{Status: http.StatusInternalServerError, Code: "internal", Message: "delete failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
		if wait < 0 || wait > 60 {
			wait = 30
		}
		ev := s.Events(r.Context(), after, time.Duration(wait)*time.Second)
		if ev == nil {
			ev = []Event{}
		}
		writeJSON(w, http.StatusOK, ev)
	})
	return mux
}

// RevealHandler serves /run/seal-cred-reveal.sock, the only place a value
// leaves sealed. Its socket can belong to a different system user than the
// one running tools, so a harness can keep revealed values from them.
func (s *Store) RevealHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /credentials/reveal", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		}
		if e := readJSON(r, &in); e != nil {
			writeErr(w, e)
			return
		}
		value, e := s.Reveal(strings.TrimSpace(in.Name), in.Reason)
		if e != nil {
			writeErr(w, e)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"value": string(value)})
	})
	return mux
}
