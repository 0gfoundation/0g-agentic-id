package servicehost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const InputHandleHeader = "X-Seal-Input-Handle"

type pendingInput struct {
	service string
	version string
	data    []byte
}

// handoff keeps input only while its originating HTTP request is being
// admitted. The service receives an opaque one-use reference; only its chosen
// worker receives plaintext. Completion/error/disconnect discards unused input.
func (m *Manager) handoff(service string, data []byte) (string, func(), error) {
	return m.handoffForVersion(service, "", data)
}

func (m *Manager) handoffForVersion(service, version string, data []byte) (string, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[service]
	if m.closed || e == nil || !e.Desired || (version != "" && e.Version != version) || len(m.pendingInputs) >= MaxWorkers {
		return "", nil, fmt.Errorf("private input admission unavailable")
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, err
	}
	h := hex.EncodeToString(b[:])
	m.pendingInputs[h] = pendingInput{service: service, version: e.Version, data: bytes.Clone(data)}
	var once sync.Once
	return h, func() { once.Do(func() { m.mu.Lock(); delete(m.pendingInputs, h); m.mu.Unlock() }) }, nil
}

func (m *Manager) spawnWithHandoff(service, key string, input []byte, handle string) (ExecutionStatus, error) {
	return m.spawnExecution(service, key, input, func() ([]byte, error) {
		// spawnExecution holds m.mu and checks duplicate keys before resolving
		// input, so retries can recover the original handle after handoff use.
		if handle == "" {
			return nil, nil
		}
		p, ok := m.pendingInputs[handle]
		e := m.entries[service]
		if !ok || p.service != service || e == nil || p.version != e.Version {
			return nil, fmt.Errorf("private input is unavailable")
		}
		return p.data, nil
	}, func() {
		// Called under the same lock as the new durable reservation, never for
		// a duplicate execution. No competing key can reuse this private input.
		delete(m.pendingInputs, handle)
	})
}

// ExecutionHandler is mounted only on the private socket of one isolated
// service coordinator. The service argument is selected by sealed, never by
// the HTTP caller. Workers do not receive this socket or any owner authority.
func (m *Manager) ExecutionHandler(service string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost || r.URL.Path != "/executions" {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var in struct {
			Action      string `json:"action"`
			Key         string `json:"key,omitempty"`
			Handle      string `json:"handle,omitempty"`
			Input       []byte `json:"input,omitempty"`
			InputHandle string `json:"input_handle,omitempty"`
			Offset      int    `json:"offset,omitempty"`
		}
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if err := d.Decode(&in); err != nil || d.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid process control request", http.StatusBadRequest)
			return
		}
		var status ExecutionStatus
		var output []byte
		var err error
		code := http.StatusOK
		switch in.Action {
		case "spawn":
			status, err = m.spawnWithHandoff(service, in.Key, in.Input, in.InputHandle)
		case "get":
			status, output, err = m.Execution(service, in.Handle, in.Offset)
		case "find":
			status, err = m.FindExecution(service, in.Key)
		case "wait":
			ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			defer cancel()
			status, err = m.WaitExecution(ctx, service, in.Handle)
			if errors.Is(err, context.DeadlineExceeded) {
				status, _, err = m.Execution(service, in.Handle, 0)
				code = http.StatusAccepted
			}
		case "terminate":
			err = m.TerminateExecution(service, in.Handle)
			if err == nil {
				status, _, err = m.Execution(service, in.Handle, 0)
			}
		case "release":
			err = m.ReleaseExecution(service, in.Handle)
			if err == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		default:
			err = fmt.Errorf("unknown process control action")
		}
		if err != nil {
			code = http.StatusBadRequest
			if errors.Is(err, ErrExecutionNotFound) {
				code = http.StatusNotFound
			} else if errors.Is(err, ErrExecutionConflict) {
				code = http.StatusConflict
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		out := map[string]any{"execution": status, "output": output}
		if err != nil {
			out["error"] = err.Error()
		}
		_ = json.NewEncoder(w).Encode(out)
	})
}
