// Command partout is the single Partout binary, run in one of three modes
// (architecture §1):
//
//	partout --mode=server            # control plane: gRPC + REST + SSE on one listener
//	partout --mode=agent             # host agent: outbound gRPC to the server
//	partout --mode=embedded          # server + co-located local agent (one process)
//
// The server multiplexes gRPC (HTTP/2, application/grpc) and REST/SSE
// (HTTP/1.1 + h2c) on a single TCP listener (PRD §4, architecture §2).
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/blawesom/partout/internal/agent"
	agentfacts "github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/api"
	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/config"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

func main() {
	// `partout ctl` is a subcommand — intercept before normal flag parsing.
	if len(os.Args) > 1 && (os.Args[1] == "ctl" || os.Args[1] == "--ctl") {
		runCtl(os.Args[2:])
		return
	}

	// Config: env vars + defaults (config.Load), CLI flags override
	// (fs.Changed), validated again after overrides.
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "partout:", err)
		os.Exit(2)
	}

	fs := flag.NewFlagSet("partout", flag.ContinueOnError)
	mode := fs.String("mode", cfg.Mode, "server|agent|embedded")
	port := fs.Int("port", cfg.Port, "server: single listener port")
	db := fs.String("db", cfg.DBPath, "server: SQLite path")
	dataDir := fs.String("data-dir", cfg.DataDir, "agent: identity/policy dir (default ~/.partout/agent)")
	server := fs.String("server", cfg.ServerURL, "agent: server host:port")
	token := fs.String("token", cfg.Token, "agent: one-time enrollment token")
	factsEvery := fs.Int("facts-interval", cfg.FactsInterval, "agent: facts refresh seconds")
	adminTok := fs.String("admin-token", cfg.AdminToken, "server: RBAC admin bearer token")
	opTok := fs.String("operator-token", cfg.OperatorToken, "server: RBAC operator bearer token")
	viewerTok := fs.String("viewer-token", cfg.ViewerToken, "server: RBAC viewer bearer token")
	tlsOn := fs.String("tls", tlsDefault(cfg.TLS), "server: TLS mode on|off (generates a local root CA on first run)")
	tlsNames := fs.String("tls-names", cfg.TLSNames, "server: comma-separated SAN names for the server leaf cert (default localhost,127.0.0.1,hostname)")
	caFile := fs.String("ca-file", cfg.TLSCAFile, "agent: path to the server root CA (PEM); enables TLS enrollment + mTLS stream")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "partout:", err)
		os.Exit(2)
	}

	// Apply effective values (flag > env > default: each flag was seeded with
	// the loaded config, so after Parse the pointers hold the effective value).
	cfg.Mode = strings.ToLower(*mode)
	cfg.Port = *port
	cfg.DBPath = *db
	cfg.DataDir = *dataDir
	cfg.ServerURL = *server
	cfg.Token = *token
	cfg.FactsInterval = *factsEvery
	cfg.AdminToken = *adminTok
	cfg.OperatorToken = *opTok
	cfg.ViewerToken = *viewerTok
	cfg.TLSNames = *tlsNames
	cfg.TLSCAFile = *caFile
	switch strings.ToLower(*tlsOn) {
	case "on", "true":
		cfg.TLS = true
	case "off", "false", "":
		cfg.TLS = false
	default:
		fmt.Fprintf(os.Stderr, "partout: invalid --tls %q (want on|off)\n", *tlsOn)
		os.Exit(2)
	}

	// Re-validate (e.g. --mode=agent without --server).
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "partout:", err)
		os.Exit(2)
	}

	// Set reserved fields that are not exposed as flags.
	cfg.Elevate = "none"
	cfg.Root = "/"

	lg := log.New(os.Stderr, fmt.Sprintf("partout[%s]: ", cfg.Mode), log.LstdFlags)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cfg.Mode {
	case "server":
		if err := runServer(ctx, cfg, lg); err != nil {
			lg.Fatal(err)
		}
	case "agent":
		if err := runAgent(ctx, cfg, lg); err != nil {
			if err != context.Canceled {
				lg.Fatal(err)
			}
		}
	case "embedded":
		if err := runEmbedded(ctx, cfg, lg); err != nil {
			if err != context.Canceled {
				lg.Fatal(err)
			}
		}
	default:
		lg.Fatalf("unknown mode %q (want server|agent|embedded)", cfg.Mode)
	}
}

// ---- server -----------------------------------------------------------------

func runServer(ctx context.Context, cfg *config.Config, lg *log.Logger) error {
	st, err := store.New("sqlite:" + cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// A freshly-started server has no live streams: any agent previously
	// recorded as "connected" is, by definition, not connected right now. Mark
	// them disconnected so the host list is truthful until agents reconnect.
	if err := st.MarkAllDisconnected(); err != nil {
		lg.Printf("server: mark all disconnected: %v", err)
	}

	sseB := sse.New()
	h := stream.NewHandler(st, sseB, lg)
	apiH := api.New(st, h, sseB, lg)
	apiH.SetAuth(cfg.AdminToken, cfg.OperatorToken, cfg.ViewerToken)

	// Load or create the server's Ed25519 identity (signs policy decisions
	// and is published in policy bundles so agents can verify them).
	identDir := filepath.Join(filepath.Dir(cfg.DBPath), "identity")
	ident, err := certutil.LoadOrCreateServerIdentity(identDir)
	if err != nil {
		return fmt.Errorf("server identity: %w", err)
	}
	apiH.Control().SetIdentity(ident)
	h.SetServerPubKey(ident.PubB64())

	// gRPC server (served via HTTP/2 demux below).
	gs := grpc.NewServer()
	h.Register(gs)

	// Single listener, demuxed by content-type: application/grpc → gRPC,
	// everything else → REST (incl. SSE).
	var protocols http.Protocols
	protocols.SetHTTP1(true) // REST + SSE

	serveTLS := cfg.TLS

	httpSrv := &http.Server{
		Protocols: &protocols,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
				// In TLS mode, gRPC (the agent stream) requires a verified client
				// certificate (mTLS). REST/SSE do not (they rely on bearer auth).
				if serveTLS && (r.TLS == nil || len(r.TLS.PeerCertificates) == 0) {
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(403)
					return
				}
				gs.ServeHTTP(w, r)
				return
			}
			apiH.ServeHTTP(w, r)
		}),
	}

	if serveTLS {
		// Bootstrap a local root CA (first run) + the server's own leaf cert.
		certDir := filepath.Join(filepath.Dir(cfg.DBPath), "tls")
		ca, err := certutil.LoadOrCreateCA(certDir)
		if err != nil {
			return fmt.Errorf("load/create CA: %w", err)
		}
		names := serverCertNames(cfg.TLSNames)
		serverCert, err := certutil.LoadOrCreateServerCert(certDir, ca, names)
		if err != nil {
			return fmt.Errorf("load/create server cert: %w", err)
		}
		// Build the server TLS config: our leaf cert + client-cert verification.
		// Client certs are REQUIRED for gRPC (mTLS on the agent stream) but
		// optional for REST/SSE, so we verify-what's-given and enforce it at the
		// demux (see below): a grpc request without a valid client cert is 403.
		clientCAs := x509.NewCertPool()
		clientCAs.AppendCertsFromPEM([]byte(ca.CertPEM()))
		httpSrv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    clientCAs,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			MinVersion:   tls.VersionTLS12,
		}
		apiH.SetTLS(ca)
		protocols.SetHTTP2(true) // gRPC over TLS (ALPN h2)
		lg.Printf("TLS enabled (CA in %s, SANs %v)", certDir, names)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		return fmt.Errorf("listen :%d: %w", cfg.Port, err)
	}
	if serveTLS {
		lg.Printf("gRPC + REST + SSE (TLS) on :%d, db %s", cfg.Port, cfg.DBPath)
	} else {
		lg.Printf("gRPC + REST + SSE on :%d, db %s", cfg.Port, cfg.DBPath)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		gs.GracefulStop()
	}()

	var serveErr error
	if serveTLS {
		serveErr = httpSrv.ServeTLS(lis, "", "") // certs from TLSConfig
	} else {
		protocols.SetUnencryptedHTTP2(true) // gRPC (h2c prior-knowledge)
		serveErr = httpSrv.Serve(lis)
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", serveErr)
	}
	lg.Printf("bye")
	return nil
}

// ---- agent ------------------------------------------------------------------

func runAgent(ctx context.Context, cfg *config.Config, lg *log.Logger) error {
	if cfg.DataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("agent: no home dir: %w", err)
		}
		cfg.DataDir = filepath.Join(home, ".partout", "agent")
	}

	identityPath := filepath.Join(cfg.DataDir, "identity.json")
	_, statErr := os.Stat(identityPath)
	fresh := os.IsNotExist(statErr)

	id, err := identity.LoadOrGenerate(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("agent: identity: %w", err)
	}

	// One-time enrollment: fresh identity + token provided.
	if cfg.Token != "" && fresh {
		lg.Printf("agent: enrolling with token %s…", cfg.Token[:10]+"…")
		factMap := agentfacts.Collector(id, cfg.FactsInterval)
		res, err := agent.Enroll(ctx, cfg.ServerURL, cfg.Token, id, factMap, agent.EnrollOptions{CAFile: cfg.TLSCAFile})
		if err != nil {
			return fmt.Errorf("agent: enroll: %w", err)
		}
		lg.Printf("agent: enrolled as %s (uuid %s)", res.AgentID, res.UUID)
		if res.TLS != nil {
			if err := persistTLSMaterial(cfg, res, lg); err != nil {
				return fmt.Errorf("agent: persist TLS: %w", err)
			}
		}
	} else if cfg.Token == "" && fresh {
		lg.Printf("agent: warning: fresh identity and no token; server must already know this agent")
	}

	// Pick up mTLS material from disk if present (survives restarts).
	tlsDir := filepath.Join(cfg.DataDir, "tls")
	if _, err := os.Stat(filepath.Join(tlsDir, "ca.crt")); err == nil {
		cfg.TLSCAFile = filepath.Join(tlsDir, "ca.crt")
		cfg.TLSCertFile = filepath.Join(tlsDir, "agent.crt")
		cfg.TLSKeyFile = filepath.Join(tlsDir, "key.pem")
	}
	ag := agent.New(id, cfg, lg)
	return ag.Run(ctx)
}

// persistTLSMaterial writes the agent's TLS material (CA, leaf, private key)
// under <dataDir>/tls/ with 0600 permissions on the key. The private key
// never leaves the host.
func persistTLSMaterial(cfg *config.Config, res *agent.EnrollResult, lg *log.Logger) error {
	dir := filepath.Join(cfg.DataDir, "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if res.TLS == nil {
		return nil
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte(res.TLS.CACert), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.crt"), []byte(res.TLS.LeafCert), 0o644); err != nil {
		return err
	}
	if res.TLSKey != nil {
		if err := os.WriteFile(filepath.Join(dir, "key.pem"), certutil.PEMKey(res.TLSKey), 0o600); err != nil {
			return err
		}
	}
	lg.Printf("agent: persisted mTLS material in %s", dir)
	return nil
}

// serverCertNames returns the SAN names for the server leaf cert, defaulting
// to localhost, 127.0.0.1 and the local hostname.
func serverCertNames(tlsNames string) []string {
	if strings.TrimSpace(tlsNames) != "" {
		parts := strings.Split(tlsNames, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	return []string{"localhost", "127.0.0.1", host}
}

// ---- embedded ---------------------------------------------------------------

// runEmbedded runs the server and a local agent in the same process.
// The agent is enrolled with the co-located server and connects over
// loopback.  On process shutdown (SIGTERM / SIGINT), both sides shut down
// gracefully.
func runEmbedded(ctx context.Context, cfg *config.Config, lg *log.Logger) error {
	// The embedded agent talks to the co-located server over loopback.
	agentCfg := *cfg
	agentCfg.ServerURL = fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	if cfg.TLS {
		// The server bootstraps its own CA; point the agent at it so mTLS
		// enrollment + gRPC stream will work.
		agentCfg.TLSCAFile = filepath.Join(filepath.Dir(cfg.DBPath), "tls", "ca.crt")
	}

	// Determine whether this is a first boot (identity.json doesn't yet exist).
	// Only then do we need an enrollment token.
	dataDir := agentCfg.DataDir
	if dataDir == "" {
		home, _ := os.UserHomeDir()
		dataDir = filepath.Join(home, ".partout", "agent")
		agentCfg.DataDir = dataDir
	}
	_, statErr := os.Stat(filepath.Join(dataDir, "identity.json"))
	fresh := os.IsNotExist(statErr)

	var wg sync.WaitGroup
	serverErr := make(chan error, 1)
	agentErr := make(chan error, 1)

	// ---- start the server (serves until ctx.Done, then graceful shutdown) ----
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr <- runServer(ctx, cfg, lg)
	}()

	// ---- wait for readiness ------------------------------------------------
	base := "http://127.0.0.1"
	if cfg.TLS {
		base = "https://127.0.0.1"
	}
	if err := waitForReady(ctx, base, cfg.Port, agentCfg.TLSCAFile, lg); err != nil {
		return fmt.Errorf("embedded: server not ready: %w", err)
	}

	// ---- create enrollment token (only for first boot) ----------------------
	if fresh {
		tok, err := createEnrollmentToken(ctx, base, cfg.Port, cfg.AdminToken, agentCfg.TLSCAFile)
		if err != nil {
			return fmt.Errorf("embedded: create enrollment token: %w", err)
		}
		agentCfg.Token = tok
		lg.Printf("embedded: local agent enrolled (token created)")
	} else {
		lg.Printf("embedded: local agent already enrolled; skipping enrollment")
	}

	// ---- run the agent (blocking until ctx or revoke) ----------------------
	wg.Add(1)
	go func() {
		defer wg.Done()
		agentErr <- runAgent(ctx, &agentCfg, lg)
	}()

	// ---- wait for shutdown --------------------------------------------------
	<-ctx.Done()
	wg.Wait()

	// Return the first non-nil, non-canceled error.
	if e := <-serverErr; e != nil && !errors.Is(e, context.Canceled) {
		return e
	}
	if e := <-agentErr; e != nil && !errors.Is(e, context.Canceled) {
		return e
	}
	return ctx.Err()
}

// waitForReady polls /healthz until it returns 200 or the context is done.
// When TLS is on it uses caFile as the root CA for verification.
func waitForReady(ctx context.Context, base string, port int, caFile string, lg *log.Logger) error {
	url := fmt.Sprintf("%s:%d/healthz", base, port)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for server at %s", url)
		}
		client := &http.Client{Timeout: 2 * time.Second}
		if caFile != "" {
			if c, err := tlsHTTPClient(caFile); err == nil {
				client.Transport = c.Transport
			}
		}
		resp, err := client.Get(url)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				lg.Printf("embedded: server ready at %s", url)
				return nil
			}
		}
		if lg != nil {
			lg.Printf("embedded: waiting for server (%s) ...", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// createEnrollmentToken calls the admin enrollment-token endpoint and returns
// the plaintext token.  In single-user mode (no admin token) no bearer is sent.
func createEnrollmentToken(ctx context.Context, base string, port int, adminToken, caFile string) (string, error) {
	url := fmt.Sprintf("%s:%d/api/v1/agents/enrollment-tokens", base, port)
	client := &http.Client{Timeout: 5 * time.Second}
	if caFile != "" {
		if c, err := tlsHTTPClient(caFile); err == nil {
			client = c
		}
	}
	body, err := json.Marshal(map[string]int{"ttl_s": 300})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server returned %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Token, nil
}

// tlsHTTPClient returns an http.Client that trusts caFile as the root CA.
func tlsHTTPClient(caFile string) (*http.Client, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no valid certificate in %s", caFile)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// ---- flag/env helpers --------------------------------------------------------

// envOr returns the environment variable value for key, or fallback if unset
// (or empty). Used only by `partout ctl`.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// tlsDefault renders the TLS bool as the --tls flag default.
func tlsDefault(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
