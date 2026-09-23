package prime

import "testing"

func TestFrameworkRoutesDeclareSessionRegistry(t *testing.T) {
	routes := New().FrameworkRoutes()
	for _, route := range routes {
		if route.Prefix == "/v1/sessions" {
			if route.Kind != "sessions" || route.Auth != "bearer" || route.Signed {
				t.Fatalf("session route = %#v, want bearer sessions route", route)
			}
			return
		}
	}
	t.Fatal("/v1/sessions route is not declared")
}
