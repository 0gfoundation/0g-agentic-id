package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	studioapi "seal-verify/internal/studio"
)

const studioBodyLimit = (1 << 20) + (128 << 10)

func (s *Server) requireStudioOwner(w http.ResponseWriter, r *http.Request) bool {
	token, err := s.adapterAuthToken(r.Context())
	if err != nil {
		writeStudioError(w, &studioapi.Error{Status: http.StatusServiceUnavailable, Code: "studio_unavailable", Message: "Studio authentication is unavailable"})
		return false
	}
	if !synthBearerOK(r, token) {
		writeStudioError(w, &studioapi.Error{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "valid owner bearer token required"})
		return false
	}
	_, _, _, bootstrapOwner, _ := s.agent.Snapshot()
	s.mu.RLock()
	resolve := s.ownerResolver
	s.mu.RUnlock()
	if bootstrapOwner == "" || resolve == nil {
		writeStudioError(w, &studioapi.Error{Status: http.StatusServiceUnavailable, Code: "owner_lookup_unavailable", Message: "live owner lookup is unavailable"})
		return false
	}
	liveOwner, err := resolve(r.Context())
	if err != nil || strings.TrimSpace(liveOwner) == "" {
		writeStudioError(w, &studioapi.Error{Status: http.StatusServiceUnavailable, Code: "owner_lookup_failed", Message: "live owner lookup failed"})
		return false
	}
	if !strings.EqualFold(liveOwner, bootstrapOwner) {
		writeStudioError(w, &studioapi.Error{Status: http.StatusConflict, Code: "ownership_changed", Message: "agent ownership changed; restart required"})
		return false
	}
	return true
}

func (s *Server) getStudio() *studioapi.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.studio
}

func (s *Server) handleStudio(w http.ResponseWriter, r *http.Request) {
	if !s.requireStudioOwner(w, r) {
		return
	}
	manager := s.getStudio()
	if manager == nil {
		writeStudioError(w, &studioapi.Error{Status: http.StatusServiceUnavailable, Code: "studio_unavailable", Message: "framework adapter does not expose Studio resources"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/_seal/studio/")
	switch {
	case r.Method == http.MethodGet && path == "state":
		result, err := manager.State()
		writeStudioResult(w, result, err)
	case r.Method == http.MethodPost && path == "state/read":
		var req struct {
			Kind studioapi.Kind `json:"kind"`
			ID   string         `json:"id"`
		}
		if err := decodeStudioJSON(w, r, &req); err != nil {
			writeStudioError(w, err)
			return
		}
		result, err := manager.Read(req.Kind, req.ID)
		writeStudioResult(w, result, err)
	case r.Method == http.MethodPost && path == "state/mutate":
		var req studioapi.MutationRequest
		if err := decodeStudioJSON(w, r, &req); err != nil {
			writeStudioError(w, err)
			return
		}
		result, err := manager.Mutate(r.Context(), req)
		writeStudioResult(w, result, err)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "state/receipts/"):
		id := strings.TrimPrefix(path, "state/receipts/")
		if id == "" || strings.Contains(id, "/") {
			writeStudioError(w, &studioapi.Error{Status: http.StatusNotFound, Code: "receipt_not_found", Message: "mutation receipt not found"})
			return
		}
		result, err := manager.Receipt(id)
		writeStudioResult(w, result, err)
	default:
		writeStudioError(w, &studioapi.Error{Status: http.StatusNotFound, Code: "studio_route_not_found", Message: "Studio route not found"})
	}
}

func decodeStudioJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, studioBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return &studioapi.Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: "invalid JSON request: " + err.Error()}
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return &studioapi.Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: "request body must contain one JSON object"}
	}
	return nil
}

func writeStudioResult(w http.ResponseWriter, result any, err error) {
	if err != nil {
		writeStudioError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func writeStudioError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "studio_error"
	message := "Studio request failed"
	var studioErr *studioapi.Error
	if errors.As(err, &studioErr) {
		status, code, message = studioErr.Status, studioErr.Code, studioErr.Message
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "error": message})
}
