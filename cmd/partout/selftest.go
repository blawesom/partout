// Command partout — `selftest` subcommand (M8.1 step 4).
//
// `partout selftest` is the pre-install gate for a supervised server update:
// the new binary runs its own embedded in-process suite ON the target host,
// before it is ever installed. No Go toolchain, no network, no live DB:
// everything runs against throwaway temp files. The update script refuses
// to install a binary whose selftest fails.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/api"
	"github.com/blawesom/partout/internal/config"
	"github.com/blawesom/partout/internal/cryptoutil"
	"github.com/blawesom/partout/internal/release"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

type selftestCheck struct {
	name string
	err  error
}

func runSelfTest(ctx context.Context) error {
	var checks []selftestCheck
	add := func(name string, fn func() error) {
		start := time.Now()
		err := fn()
		if err == nil {
			fmt.Printf("  ok   %-28s (%s)\n", name, time.Since(start).Round(time.Millisecond))
		} else {
			checks = append(checks, selftestCheck{name, err})
			fmt.Printf("  FAIL %s: %v\n", name, err)
		}
	}

	fmt.Printf("partout selftest (%s)\n", facts.Version)

	// 1. Config loads with defaults (no env required).
	add("config defaults", func() error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if cfg.Mode == "" || cfg.Port <= 0 {
			return fmt.Errorf("config: bad defaults (mode=%q port=%d)", cfg.Mode, cfg.Port)
		}
		return nil
	})

	// 2. Store: fresh DB migrates to the current schema and is internally
	//    consistent. This is the check that catches a binary whose schema
	//    DDL does not run on the host's SQLite version.
	add("store migrate + integrity", func() error {
		dir, err := os.MkdirTemp("", "partout-selftest-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		st, err := store.New("sqlite:" + filepath.Join(dir, "p.db"))
		if err != nil {
			return err
		}
		defer st.Close()
		var v int
		if err := st.DB().QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_version`).Scan(&v); err != nil {
			return fmt.Errorf("schema_version: %w", err)
		}
		var ok string
		if err := st.DB().QueryRow(`PRAGMA integrity_check`).Scan(&ok); err != nil || ok != "ok" {
			return fmt.Errorf("integrity_check = %q: %v", ok, err)
		}
		if v < store.CurrentSchemaVersion() {
			return fmt.Errorf("schema version %d < current %d", v, store.CurrentSchemaVersion())
		}
		return nil
	})

	// 3. Crypto: identity keypair + release signing round-trip.
	add("crypto + release signature", func() error {
		kp, err := cryptoutil.NewKeyPairEd25519()
		if err != nil {
			return err
		}
		msg := []byte("selftest")
		sig := cryptoutil.SignEd25519(kp.Priv, msg)
		if !cryptoutil.VerifyEd25519(kp.Pub, msg, sig) {
			return fmt.Errorf("ed25519 sign/verify failed")
		}
		// Release key round-trip (the exact path update-server.sh verifies).
		pub := release.PubKeyB64(kp.Pub)
		priv := release.PrivKeyB64(kp.Priv)
		gotPub, err := release.PubKeyFromB64(pub)
		if err != nil || !bytes.Equal(gotPub, kp.Pub) {
			return fmt.Errorf("pubkey b64 round-trip: %v", err)
		}
		gotPriv, err := release.PrivKeyFromB64(priv)
		if err != nil {
			return fmt.Errorf("privkey b64: %w", err)
		}
		m := release.Manifest{Version: "v9", Arch: "linux-amd64", Kind: "agent", SHA256: sha256hex(msg)}
		relSig := release.Sign(gotPriv, m)
		if !release.Verify(gotPub, m, relSig) {
			return fmt.Errorf("release Sign/Verify failed")
		}
		return nil
	})

	// 4. API round-trip: the real HTTP stack serves an authenticated
	//    request end-to-end (router, auth, store, JSON).
	add("api round-trip", func() error {
		st, err := store.New("sqlite::memory:")
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.UpsertAgent(store.Agent{ID: "ag_selftest", UUID: "selftest"}); err != nil {
			return err
		}
		sseB := sse.New()
		sh := stream.NewHandler(st, sseB, log.New(io.Discard, "", 0))
		h := api.New(st, sh, sseB, log.New(io.Discard, "", 0))
		h.SetAuth("selftest-admin", "", "")
		srv := httptest.NewServer(h)
		defer srv.Close()

		c := srv.Client()
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/healthz", nil)
		res, err := c.Do(req)
		if err != nil {
			return err
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("/healthz = %d", res.StatusCode)
		}
		req2, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/hosts", nil)
		req2.Header.Set("Authorization", "Bearer selftest-admin")
		res2, err := c.Do(req2)
		if err != nil {
			return err
		}
		defer res2.Body.Close()
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if res2.StatusCode != 200 {
			return fmt.Errorf("/api/v1/hosts = %d", res2.StatusCode)
		}
		if err := json.NewDecoder(res2.Body).Decode(&page); err != nil {
			return err
		}
		if len(page.Items) != 1 {
			return fmt.Errorf("hosts count = %d, want 1", len(page.Items))
		}
		return nil
	})

	if len(checks) > 0 {
		return fmt.Errorf("selftest: %d check(s) failed", len(checks))
	}
	fmt.Println("selftest OK")
	return nil
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
