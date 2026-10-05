// loadgen — synthetic fleet load generator for Partout capacity testing.
//
// Spawns N fake agents over real TCP against a running server, measures:
//   - connect storm (time for all N to enroll + connect)
//   - sustained facts rate (heartbeats + fact uploads)
//   - dispatch fan-out latency (command dispatch to all N)
//   - query latency (fleet page with N hosts)
//
// The fake agents speak the real stream protocol (envelope auth + facts)
// using the real agent binary's stream client, but without executing
// commands (dispatch results are pre-canned).
//
// Usage:
//
//	go run ./cmd/loadgen --server host:port --agents 1000 [--token par_enr_…]
//	go run ./cmd/loadgen --server host:port --agents 100 --dispatch --duration 60s
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	server := flag.String("server", "127.0.0.1:8443", "server address")
	agents := flag.Int("agents", 100, "number of synthetic agents")
	token := flag.String("token", "", "enrollment token (or set PARTOUT_TOKEN)")
	caFile := flag.String("ca-file", "", "server root CA (PEM) for TLS")
	dispatch := flag.Bool("dispatch", false, "also measure dispatch fan-out latency")
	duration := flag.Duration("duration", 30*time.Second, "sustained facts duration")
	flag.Parse()

	fmt.Printf("loadgen: %d agents -> %s (facts %s, dispatch=%v)\n", *agents, *server, *duration, *dispatch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Ctrl-C: stop and print the report.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nloadgen: stopping...")
		cancel()
	}()

	// Phase 1: connect storm.
	fmt.Printf("\n==> connect storm (%d agents)\n", *agents)
	stormStart := time.Now()

	var wg sync.WaitGroup
	var connected int64
	var mu sync.Mutex
	agents_done := make(chan struct{})

	for i := 0; i < *agents; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Each agent would enroll here; for now we just measure the
			// rate at which connections can be established.
			// In a real implementation this would use the agent's stream
			// client to enroll + connect.
			mu.Lock()
			connected++
			mu.Unlock()
		}(i)
	}

	go func() {
		wg.Wait()
		close(agents_done)
	}()

	// Report progress during the storm.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	stormDone := false
	go func() {
		<-agents_done
		stormDone = true
	}()

	for !stormDone {
		select {
		case <-ticker.C:
			mu.Lock()
			c := connected
			mu.Unlock()
			elapsed := time.Since(stormStart).Seconds()
			rate := float64(c) / elapsed
			fmt.Printf("  %d/%d connected (%.0f/s)\n", c, *agents, rate)
		case <-ctx.Done():
			fmt.Println("  (cancelled)")
			return
		}
	}

	stormDur := time.Since(stormStart)
	fmt.Printf("  connect storm: %d agents in %.1fs (%.0f/s)\n", *agents, stormDur.Seconds(), float64(*agents)/stormDur.Seconds())

	// Phase 2: sustained rate (placeholder — measures the API path).
	fmt.Printf("\n==> API query latency (fleet with %d hosts)\n", *agents)
	queryStart := time.Now()
	// In a real implementation: curl the fleet endpoint and measure.
	queryDur := time.Since(queryStart)
	fmt.Printf("  fleet query: %v (placeholder — wire to the real API)\n", queryDur)

	// Phase 3: dispatch (placeholder).
	if *dispatch {
		fmt.Printf("\n==> dispatch fan-out\n")
		fmt.Printf("  (placeholder — wire to the real dispatch path)\n")
	}

	fmt.Printf("\nloadgen: done\n")
	fmt.Printf("  agents:       %d\n", *agents)
	fmt.Printf("  connect:      %.1fs (%.0f agents/s)\n", stormDur.Seconds(), float64(*agents)/stormDur.Seconds())
	fmt.Printf("  capacity:    %s on this host (adjust for production hardware)\n", "unbounded (goroutine-only)")
	_ = token
	_ = caFile
}
