package servicehost

import (
	"context"
	"fmt"
	"golang.org/x/net/netutil"
	"net"
	"net/http"
	"os"
	"time"

	"seal-verify/internal/inferproxy"
	"seal-verify/internal/privsep"
)

type ModelRoute struct {
	Route inferproxy.Route
	API   string
}

func (m *Manager) startModel(ctx context.Context, limits inferproxy.TaskLimits, uid uint32, socket string) (ModelRoute, error) {
	if m.model == nil {
		return ModelRoute{}, fmt.Errorf("task inference is unavailable")
	}
	route, err := m.model(ctx)
	if err != nil {
		return ModelRoute{}, fmt.Errorf("resolve task inference: %w", err)
	}
	transport := &http.Transport{Proxy: nil, DialContext: m.egressDial, TLSHandshakeTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	handler, err := inferproxy.NewTaskHandler(route.Route, limits, client)
	if err != nil {
		return ModelRoute{}, err
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return ModelRoute{}, err
	}
	if err = os.Chown(socket, int(uid), int(uid)); err == nil {
		err = privsep.Chmod(socket, 0600)
	}
	if err != nil {
		ln.Close()
		return ModelRoute{}, err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { _ = server.Serve(netutil.LimitListener(ln, 16)) }()
	go func() { <-ctx.Done(); server.Close(); transport.CloseIdleConnections() }()
	return route, nil
}
