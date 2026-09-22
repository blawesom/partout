// Command partout is the single Partout binary, run in one of three modes
// (architecture §1):
//
//	partout --mode=server            # control plane: gRPC + REST + SSE on one listener
//	partout --mode=agent             # host agent: outbound gRPC to the server
//	partout --mode=embedded          # server + (M1) local agent; M0: server only
//
// The server multiplexes gRPC (HTTP/2, application/grpc) and REST/SSE
// (HTTP/1.1 + h2c) on a single TCP listener (PRD §4, architecture §2).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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

	var (
		mode       = flag.String("mode", envOr("PARTOUT_MODE", "server"), "server|agent|embedded")
		port       = flag.Int("port", envIntOr("PARTOUT_PORT", 8443), "server: single listener port")
		db         = flag.String("db", envOr("PARTOUT_DB_PATH", "./partout.db"), "server: SQLite path")
		dataDir    = flag.String("data-dir", envOr("PARTOUT_DATA_DIR", ""), "agent: identity/policy dir (default ~/.partout/agent)")
		server     = flag.String("server", envOr("PARTOUT_SERVER", ""), "agent: server host:port")
		token      = flag.String("token", envOr("PARTOUT_TOKEN", ""), "agent: one-time enrollment token")
		factsEvery = flag.Int("facts-interval", envIntOr("PARTOUT_FACTS_INTERVAL", 3600), "agent: facts refresh seconds")
		adminTok   = flag.String("admin-token", envOr("PARTOUT_TOKEN_ADMIN", ""), "server: RBAC admin bearer token")
		opTok      = flag.String("operator-token", envOr("PARTOUT_TOKEN_OPERATOR", ""), "server: RBAC operator bearer token")
		viewerTok  = flag.String("viewer-token", envOr("PARTOUT_TOKEN_VIEWER", ""), "server: RBAC viewer bearer token")
		tlsOn      = flag.String("tls", envOr("PARTOUT_TLS", "off"), "server: TLS mode on|off (generates a local root CA on first run)")
		tlsNames   = flag.String("tls-names", envOr("PARTOUT_TLS_SERVER_NAMES", ""), "server: comma-separated SAN names for the server leaf cert (default localhost,127.0.0.1,hostname)")
		caFile     = flag.String("ca-file", envOr("PARTOUT_TLS_CA", ""), "agent: path to the server root CA (PEM); enables TLS enrollment + mTLS stream")
	)
	flag.Parse()

	lg := log.New(os.Stderr, fmt.Sprintf("partout[%s]: ", *mode), log.LstdFlags)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch strings.ToLower(*mode) {
	case "server", "":
		if err := runServer(ctx, *port, *db, *tlsOn, *tlsNames, *adminTok, *opTok, *viewerTok, lg); err != nil {
			lg.Fatal(err)
		}
	case "agent":
		if *server == "" {
			lg.Fatal("agent mode requires --server=host:port (or PARTOUT_SERVER)")
		}
		if err := runAgent(ctx, *server, *token, *dataDir, *caFile, *factsEvery, lg); err != nil {
			if err != context.Canceled {
				lg.Fatal(err)
			}
		}
	case "embedded":
		// M0: embedded runs the server only; the co-located local agent is M1.
		lg.Printf("embedded mode: running server (local agent is M1)")
		if err := runServer(ctx, *port, *db, *tlsOn, *tlsNames, *adminTok, *opTok, *viewerTok, lg); err != nil {
			lg.Fatal(err)
		}
	default:
		lg.Fatalf("unknown mode %q (want server|agent|embedded)", *mode)
	}
}

// ---- server -----------------------------------------------------------------

func runServer(ctx context.Context, port int, dbPath, tlsMode, tlsNames string, adminTok, opTok, viewerTok string, lg *log.Logger) error {
	st, err := store.New("sqlite:" + dbPath)
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
	apiH.SetAuth(adminTok, opTok, viewerTok)

	// gRPC server (served via HTTP/2 demux below).
	gs := grpc.NewServer()
	h.Register(gs)

	// Single listener, demuxed by content-type: application/grpc → gRPC,
	// everything else → REST (incl. SSE).
	var protocols http.Protocols
	protocols.SetHTTP1(true) // REST + SSE

	serveTLS := strings.EqualFold(tlsMode, "on") || strings.EqualFold(tlsMode, "true")

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
		certDir := filepath.Join(filepath.Dir(dbPath), "tls")
		ca, err := certutil.LoadOrCreateCA(certDir)
		if err != nil {
			return fmt.Errorf("load/create CA: %w", err)
		}
		names := serverCertNames(tlsNames)
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

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("listen :%d: %w", port, err)
	}
	if serveTLS {
		lg.Printf("gRPC + REST + SSE (TLS) on :%d, db %s", port, dbPath)
	} else {
		lg.Printf("gRPC + REST + SSE on :%d, db %s", port, dbPath)
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

func runAgent(ctx context.Context, server, token, dataDir, caFile string, factsInterval int, lg *log.Logger) error {
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("agent: no home dir: %w", err)
		}
		dataDir = home + "/.partout/agent"
	}

	identityPath := dataDir + "/identity.json"
	_, statErr := os.Stat(identityPath)
	fresh := os.IsNotExist(statErr)

	id, err := identity.LoadOrGenerate(dataDir)
	if err != nil {
		return fmt.Errorf("agent: identity: %w", err)
	}

	// One-time enrollment: fresh identity + token provided.
	if token != "" && fresh {
		lg.Printf("agent: enrolling with token %s…", token[:10]+"…")
		factMap := agentfacts.Collector(id, factsInterval)
		res, err := agent.Enroll(ctx, server, token, id, factMap, agent.EnrollOptions{CAFile: caFile})
		if err != nil {
			return fmt.Errorf("agent: enroll: %w", err)
		}
		lg.Printf("agent: enrolled as %s (uuid %s)", res.AgentID, res.UUID)
		if res.TLS != nil {
			if err := persistTLSMaterial(dataDir, res, lg); err != nil {
				return fmt.Errorf("agent: persist TLS: %w", err)
			}
		}
	} else if token == "" && fresh {
		lg.Printf("agent: warning: fresh identity and no token; server must already know this agent")
	}

	agentCfg := &config.Config{
		Mode:          "agent",
		ServerURL:     server,
		DataDir:       dataDir,
		FactsInterval: factsInterval,
		Elevate:       "none",
		Root:          "/",
	}
	// Pick up mTLS material from disk if present (survives restarts).
	tlsDir := filepath.Join(dataDir, "tls")
	if stat, err := os.Stat(filepath.Join(tlsDir, "ca.crt")); err == nil && stat != nil {
		agentCfg.TLSCAFile = filepath.Join(tlsDir, "ca.crt")
		agentCfg.TLSCertFile = filepath.Join(tlsDir, "agent.crt")
		agentCfg.TLSKeyFile = filepath.Join(tlsDir, "key.pem")
	}
	ag := agent.New(id, agentCfg, lg)
	return ag.Run(ctx)
}

// persistTLSMaterial writes the agent's TLS material (CA, leaf, private key)
// under <dataDir>/tls/ with 0600 permissions on the key. The private key
// never leaves the host.
func persistTLSMaterial(dataDir string, res *agent.EnrollResult, lg *log.Logger) error {
	dir := filepath.Join(dataDir, "tls")
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

// ---- flag/env helpers ---------------------------------------------------------

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}
