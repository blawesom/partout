package exec

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunEcho(t *testing.T) {
	var chunks []Chunk
	onChunk := func(c Chunk) { chunks = append(chunks, c) }

	res, err := Run(context.Background(), "echo", []string{"hello", "world"}, "", nil, 0, onChunk)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.State != "succeeded" {
		t.Fatalf("state = %q, want succeeded", res.State)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0", res.ExitCode)
	}

	var out strings.Builder
	for _, c := range chunks {
		if c.Stream == "stdout" {
			out.Write(c.Data)
		}
	}
	if got := strings.TrimSpace(out.String()); got != "hello world" {
		t.Fatalf("output = %q, want 'hello world'", got)
	}
}

func TestRunNonZeroExit(t *testing.T) {
	res, err := Run(context.Background(), "sh", []string{"-c", "exit 3"}, "", nil, 0, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.State != "failed" {
		t.Fatalf("state = %q, want failed", res.State)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit = %d, want 3", res.ExitCode)
	}
}

func TestRunStderr(t *testing.T) {
	var chunks []Chunk
	onChunk := func(c Chunk) { chunks = append(chunks, c) }
	res, err := Run(context.Background(), "sh", []string{"-c", "echo err >&2"}, "", nil, 0, onChunk)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.State != "succeeded" {
		t.Fatalf("state = %q, want succeeded", res.State)
	}
	var errOut strings.Builder
	for _, c := range chunks {
		if c.Stream == "stderr" {
			errOut.Write(c.Data)
		}
	}
	if got := strings.TrimSpace(errOut.String()); got != "err" {
		t.Fatalf("stderr = %q, want 'err'", got)
	}
}

func TestRunTimeout(t *testing.T) {
	res, err := Run(context.Background(), "sleep", []string{"10"}, "", nil, 1, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.State != "timed_out" {
		t.Fatalf("state = %q, want timed_out", res.State)
	}
	if res.DurationMS > 3000 {
		t.Fatalf("duration = %d ms, expected < 3000 (timeout=1s)", res.DurationMS)
	}
}

func TestRunCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	res, _ := Run(ctx, "sleep", []string{"10"}, "", nil, 0, nil)
	if res.State != "cancelled" {
		t.Fatalf("state = %q, want cancelled", res.State)
	}
}

func TestRunLargeOutput(t *testing.T) {
	var total int
	var maxChunk int
	onChunk := func(c Chunk) {
		total += len(c.Data)
		if len(c.Data) > maxChunk {
			maxChunk = len(c.Data)
		}
	}
	// Produce ~200KB of output, forcing multiple chunks.
	res, err := Run(context.Background(), "sh", []string{"-c", "yes A | head -c 200000"}, "", nil, 0, onChunk)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.State != "succeeded" {
		t.Fatalf("state = %q", res.State)
	}
	if total != 200000 {
		t.Fatalf("total output = %d, want 200000", total)
	}
	if maxChunk > MaxChunkSize {
		t.Fatalf("max chunk = %d, exceeds MaxChunkSize %d", maxChunk, MaxChunkSize)
	}
}
