// Transport parity (R11): the same MCP tool must behave identically through
// both transports — the in-process localAPI (the /mcp HTTP route and the
// built-in assistant) and the REST client (stdio mode, `partout mcp`). The
// two are different code paths (in-process recorder vs. net/http) that the
// control plane must not be able to tell apart: same results, same errors,
// same RBAC refusals.
package mcp_test

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"testing"

	"github.com/blawesom/partout/internal/api"
	"github.com/blawesom/partout/internal/server/mcp"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

func TestTransportParityLocalVsREST(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.UpsertAgent(store.Agent{ID: "ag_par", UUID: "u-par"}); err != nil {
		t.Fatal(err)
	}

	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	apiH := api.New(st, h, sseB, log.New(io.Discard, "api: ", 0))
	// Real RBAC so the refusal path is exercised on BOTH transports.
	apiH.SetAuth("par-admin", "par-op", "par-view")

	srv := httptest.NewServer(apiH)
	t.Cleanup(srv.Close)

	local := mcp.NewLocalAPI(apiH)
	remote := mcp.NewRESTClient(srv.URL, nil)

	tool := func(name string) *mcp.Tool {
		for _, tl := range mcp.DefaultTools() {
			if tl.Name == name {
				return tl
			}
		}
		t.Fatalf("tool %q not in catalog", name)
		return nil
	}

	cases := []struct {
		name  string
		tool  string
		args  map[string]any
		token string
	}{
		{"read success (list_hosts)", "list_hosts", nil, "par-admin"},
		{"read success (list_policies)", "list_policies", nil, "par-view"},
		{"deterministic error (bad selector)", "run_command", map[string]any{"selector": "bogus(", "cmd": "uptime"}, "par-admin"},
		{"RBAC refusal (viewer writes)", "run_command", map[string]any{"selector": "host:ag_par", "cmd": "uptime"}, "par-view"},
		{"RBAC refusal (viewer secret write)", "create_secret", map[string]any{"name": "s", "value": "v"}, "par-view"},
	}
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tl := tool(tc.tool)
			resL, errL := tl.Call(ctx, local, tc.token, tc.args)
			resR, errR := tl.Call(ctx, remote, tc.token, tc.args)

			if (errL == nil) != (errR == nil) {
				t.Fatalf("error divergence: local=%v remote=%v", errL, errR)
			}
			if errL != nil {
				if errL.Error() != errR.Error() {
					t.Fatalf("error text divergence:\n  local: %s\n  remote: %s", errL, errR)
				}
				return
			}
			if resL != resR {
				t.Fatalf("result divergence:\n  local: %s\n  remote: %s", resL, resR)
			}
		})
	}
}
