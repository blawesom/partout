package spool

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	pb "github.com/blawesom/partout/internal/proto"
)

func makeTestSpool(t *testing.T, cfg Config) *Spool {
	t.Helper()
	cfg.Dir = t.TempDir()
	s, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func makeOutput(runID string, seq uint64, data []byte) *pb.Envelope {
	return &pb.Envelope{
		Kind: pb.EnvelopeKind_COMMAND_OUTPUT,
		Payload: &pb.Envelope_Output{Output: &pb.CommandOutput{
			RunId: runID, ChunkSeq: seq, Data: data,
		}},
	}
}

func makeResult(runID string, code int32, state string) *pb.Envelope {
	return &pb.Envelope{
		Kind: pb.EnvelopeKind_COMMAND_RESULT,
		Payload: &pb.Envelope_Result{Result: &pb.CommandResult{
			RunId: runID, ExitCode: code, State: state,
		}},
	}
}

type fakeSend struct {
	mu   sync.Mutex
	envs []*pb.Envelope
	fail int // start failing at this count (0-based)
	nf   int // fail for this many calls
	cur  int
}

func (f *fakeSend) send(ctx context.Context, env *pb.Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.envs = append(f.envs, env)
	if f.fail > 0 && f.cur >= f.fail && f.cur < f.fail+f.nf {
		return os.ErrInvalid
	}
	f.cur++
	return nil
}

func (f *fakeSend) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.envs)
}

// ---- 1. Append + Drain In Order ----

func TestAppendDrainInOrder(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 1 << 20, DiskCap: 1 << 20})
	defer s.Close()

	s.Append("run_1", makeOutput("run_1", 0, []byte("hello ")))
	s.Append("run_1", makeOutput("run_1", 1, []byte("world")))
	s.Append("run_2", makeOutput("run_2", 0, []byte("other")))
	s.Append("run_2", makeResult("run_2", 0, "succeeded"))
	s.Append("run_1", makeResult("run_1", 0, "succeeded"))

	sent, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(drained) != 2 || drained[0] != "run_1" || drained[1] != "run_2" {
		t.Fatalf("drained = %v, want [run_1 run_2] (oldest first)", drained)
	}
	if sent != 5 { // run_1: 2 output + result, run_2: 1 output + result
		t.Fatalf("sent = %d, want 5", sent)
	}
}

// ---- 2. Spill to Disk ----

func TestSpillToDisk(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 64, DiskCap: 1 << 20})
	defer s.Close()

	for i := 0; i < 200; i++ {
		data := make([]byte, 32)
		for j := range data {
			data[j] = byte((i + j) & 0xff)
		}
		s.Append("run_big", makeOutput("run_big", uint64(i), data))
	}
	s.Append("run_big", makeResult("run_big", 0, "succeeded"))

	sent, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(drained) != 1 || drained[0] != "run_big" {
		t.Fatalf("drained = %v, want [run_big]", drained)
	}
	if sent != 201 {
		t.Fatalf("sent = %d, want 201", sent)
	}

	files, _ := os.ReadDir(s.cfg.Dir)
	if len(files) != 0 {
		t.Errorf("expected no spool files after drain, got %d", len(files))
	}
}

// ---- 3. Drop Oldest On Disk Cap ----

func TestDropOldestOnDiskCap(t *testing.T) {
	// Tiny MemCap forces every run to spill to disk; tiny DiskCap evicts oldest.
	s := makeTestSpool(t, Config{MemCap: 32, DiskCap: 60})
	defer s.Close()

	s.Append("run_old", makeOutput("run_old", 0, []byte("oldest data here ")))
	s.Append("run_old", makeResult("run_old", 0, "succeeded"))

	s.Append("run_new", makeOutput("run_new", 0, []byte("new")))
	s.Append("run_new", makeResult("run_new", 0, "succeeded"))

	if len(s.Runs()) != 1 || s.Runs()[0] != "run_new" {
		t.Fatalf("runs = %v, want [run_new]", s.Runs())
	}
}

// ---- 4. TTL Expiration ----

func TestTTL(t *testing.T) {
	now := time.Now()
	s := makeTestSpool(t, Config{
		MemCap: 1 << 20, DiskCap: 1 << 20, TTL: 500 * time.Millisecond,
		Now: func() time.Time { return now },
	})
	defer s.Close()

	s.Append("run_old", makeOutput("run_old", 0, []byte("old")))
	s.Append("run_old", makeResult("run_old", 0, "succeeded"))

	now = now.Add(500 * time.Millisecond)

	s.Append("run_new", makeOutput("run_new", 0, []byte("new")))
	s.Append("run_new", makeResult("run_new", 0, "succeeded"))

	now = now.Add(500 * time.Millisecond) // run_old expired, run_new fresh

	sent, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(drained) != 1 || drained[0] != "run_new" {
		t.Fatalf("drained = %v, want [run_new]", drained)
	}
	if sent != 2 {
		t.Fatalf("sent = %d, want 2", sent)
	}
}

// ---- 5. Durability Across Reopen ----

func TestDurabilityAcrossReopen(t *testing.T) {
	// Small MemCap forces the records to spill to disk before Close.
	s := makeTestSpool(t, Config{MemCap: 40, DiskCap: 1 << 20})
	s.Append("run_1", makeOutput("run_1", 0, []byte("hello ")))
	s.Append("run_1", makeOutput("run_1", 1, []byte("world")))
	s.Append("run_1", makeResult("run_1", 0, "succeeded"))
	s.Close()

	s2, err := Open(Config{Dir: s.cfg.Dir, Now: time.Now})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	if len(s2.Runs()) != 1 || s2.Runs()[0] != "run_1" {
		t.Fatalf("runs = %v, want [run_1]", s2.Runs())
	}

	sent, drained, err := s2.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(drained) != 1 || drained[0] != "run_1" {
		t.Fatalf("drained = %v", drained)
	}
	if sent != 3 {
		t.Fatalf("sent = %d, want 3", sent)
	}
}

// ---- 6. Partial Drain Keeps Run ----

func TestPartialDrainKeepsRun(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 1 << 20, DiskCap: 1 << 20})
	defer s.Close()

	for i := 0; i < 10; i++ {
		s.Append("run_fail", makeOutput("run_fail", uint64(i), []byte{byte(i)}))
	}
	s.Append("run_fail", makeResult("run_fail", -1, "failed"))

	fake := &fakeSend{fail: 5, nf: 3}
	_, _, err := s.Drain(context.Background(), fake.send)
	if err == nil {
		t.Fatal("expected error")
	}
	if len(s.Runs()) != 1 {
		t.Fatalf("runs = %v, want 1", s.Runs())
	}
	if fake.n() != 6 { // 5 successful + 1 failed (appended before check)
		t.Fatalf("captured = %d, want 6", fake.n())
	}

	sent, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("second Drain: %v", err)
	}
	if len(drained) != 1 {
		t.Fatalf("drained = %d, want 1", len(drained))
	}
	if sent != 11 {
		t.Fatalf("second sent = %d, want 11", sent)
	}
}

// ---- 7. Incomplete Runs Skipped ----

func TestIncompleteRunsSkipped(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 1 << 20, DiskCap: 1 << 20})
	defer s.Close()

	s.Append("run_a", makeOutput("run_a", 0, []byte("a0")))
	s.Append("run_a", makeResult("run_a", 0, "succeeded"))

	s.Append("run_b", makeOutput("run_b", 0, []byte("b0")))
	s.Append("run_b", makeOutput("run_b", 1, []byte("b1")))

	s.Append("run_c", makeOutput("run_c", 0, []byte("c0")))
	s.Append("run_c", makeResult("run_c", 1, "failed"))

	sent, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(drained) != 2 {
		t.Fatalf("drained = %d, want 2", len(drained))
	}
	if sent != 4 { // a:2 + c:2, b:0
		t.Fatalf("sent = %d, want 4", sent)
	}
	if len(s.Runs()) != 1 || s.Runs()[0] != "run_b" {
		t.Fatalf("runs = %v, want [run_b]", s.Runs())
	}
}

// ---- 8. Usage ----

func TestUsage(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 1 << 20, DiskCap: 1 << 20})
	defer s.Close()

	if m, d := s.Usage(); m != 0 || d != 0 {
		t.Fatalf("initial usage = (%d, %d), want (0, 0)", m, d)
	}

	s.Append("run_u", makeOutput("run_u", 0, []byte("hello world")))
	s.Append("run_u", makeResult("run_u", 0, "succeeded"))
	m, d := s.Usage()
	if m == 0 {
		t.Fatal("mem should be > 0")
	}
	if d != 0 {
		t.Fatal("disk should be 0 (no spill)")
	}
}

// ---- 9. Empty Spool ----

func TestEmptySpool(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 1 << 20, DiskCap: 1 << 20})
	defer s.Close()

	sent, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error {
		t.Fatal("should not be called")
		return nil
	})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if sent != 0 {
		t.Fatalf("sent = %d, want 0", sent)
	}
	if len(drained) != 0 {
		t.Fatalf("drained = %v, want empty", drained)
	}
}

// ---- 10. Usage after Spill ----

func TestUsageAfterSpill(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 40, DiskCap: 1 << 20})
	defer s.Close()

	s.Append("run_u", makeOutput("run_u", 0, []byte("hello world")))
	s.Append("run_u", makeResult("run_u", 0, "succeeded"))

	m, d := s.Usage()
	if d == 0 {
		t.Fatalf("disk should be > 0 after MemCap overflow and spill (mem=%d disk=%d)", m, d)
	}
	if m == 0 {
		// After spill, mem is 0 (all data moved to disk).
	}
}

// ---- 11. Drop-oldest on MemCap overflow (single run spill) ----

func TestMemOverflowSpill(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 40, DiskCap: 1 << 20})
	defer s.Close()

	s.Append("run_spill", makeOutput("run_spill", 0, []byte("hello world")))
	s.Append("run_spill", makeResult("run_spill", 0, "succeeded"))
	// MemCap 128 means the first record fits; adding result exceeds → spill to disk.

	if _, d := s.Usage(); d == 0 {
		t.Fatal("disk should be > 0 after spill")
	}

	sent, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(drained) != 1 || drained[0] != "run_spill" {
		t.Fatalf("drained = %v, want [run_spill]", drained)
	}
	if sent != 2 {
		t.Fatalf("sent = %d, want 2", sent)
	}
}

// ---- 12. Concurrent Append ----

func TestConcurrentAppend(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 1 << 20, DiskCap: 1 << 20})
	defer s.Close()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				s.Append("run_conc", makeOutput("run_conc", uint64(i*20+j), []byte{byte(i), byte(j)}))
			}
		}(i)
	}
	wg.Wait()

	s.Append("run_conc", makeResult("run_conc", 0, "succeeded"))

	sent, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(drained) != 1 {
		t.Fatalf("drained = %d, want 1", len(drained))
	}
	if sent != 201 {
		t.Fatalf("sent = %d, want 201", sent)
	}
}

// TestDrainPreservesRecordsAppendedDuringSend verifies that a record appended
// to a run while its snapshot is being sent is NOT dropped with the drained
// prefix — the run stays queued until everything it holds has been sent.
func TestDrainPreservesRecordsAppendedDuringSend(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 1 << 20, DiskCap: 1 << 20})
	defer s.Close()

	s.Append("run_x", makeOutput("run_x", 0, []byte("a")))
	s.Append("run_x", makeResult("run_x", 0, "succeeded"))

	// Append a trailing chunk from inside the send callback: it lands after
	// the drain's snapshot was taken.
	appended := false
	sent, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error {
		if !appended {
			appended = true
			s.Append("run_x", makeOutput("run_x", 1, []byte("late")))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(drained) != 0 {
		t.Fatalf("run reported fully drained with a late record pending: %v", drained)
	}
	if sent != 2 {
		t.Fatalf("sent = %d, want 2", sent)
	}
	if runs := s.Runs(); len(runs) != 1 || runs[0] != "run_x" {
		t.Fatalf("Runs() = %v, want [run_x]", runs)
	}

	// The late record must still be spooled. Note it is a bare output chunk,
	// so the run is no longer "complete"; re-append a result and drain again.
	s.Append("run_x", makeResult("run_x", 0, "succeeded"))
	sent, drained, err = s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("second Drain: %v", err)
	}
	if sent != 2 || len(drained) != 1 {
		t.Fatalf("second drain: sent=%d drained=%v, want 2/[run_x]", sent, drained)
	}
}

// TestDrainPreservesLateRecordsOnDisk exercises the same guarantee for the
// disk tier, where the drained prefix is removed by rewriting the log.
func TestDrainPreservesLateRecordsOnDisk(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 1, DiskCap: 1 << 20}) // force spill
	defer s.Close()

	s.Append("run_d", makeOutput("run_d", 0, []byte("a")))
	s.Append("run_d", makeResult("run_d", 0, "succeeded"))

	appended := false
	sent, _, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error {
		if !appended {
			appended = true
			s.Append("run_d", makeOutput("run_d", 1, []byte("late")))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if sent != 2 {
		t.Fatalf("sent = %d, want 2", sent)
	}
	// The late chunk must survive the log rewrite.
	if runs := s.Runs(); len(runs) != 1 || runs[0] != "run_d" {
		t.Fatalf("Runs() = %v, want [run_d]", runs)
	}
}

// TestPartialSendKeepsRunAndUsage documents the retry contract: when a send
// fails mid-run, the drain stops and NOTHING is removed from the run, so the
// already-sent prefix is re-sent on the next attempt (at-least-once; the
// server dedupes by (run_id, chunk_seq)). Usage must therefore be unchanged.
func TestPartialSendKeepsRunAndUsage(t *testing.T) {
	s := makeTestSpool(t, Config{MemCap: 1, DiskCap: 1 << 20}) // force spill
	defer s.Close()

	s.Append("run_u", makeOutput("run_u", 0, []byte("aaaa")))
	s.Append("run_u", makeOutput("run_u", 1, []byte("bbbb")))
	s.Append("run_u", makeResult("run_u", 0, "succeeded"))

	_, diskBefore := s.Usage()

	calls := 0
	_, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error {
		calls++
		if calls == 3 {
			return errStop
		}
		return nil
	})
	if err != errStop {
		t.Fatalf("Drain err = %v, want errStop", err)
	}
	if len(drained) != 0 {
		t.Fatalf("drained = %v, want none (send failed mid-run)", drained)
	}

	memAfter, diskAfter := s.Usage()
	if diskAfter != diskBefore {
		t.Fatalf("disk usage changed on a failed drain: before=%d after=%d", diskBefore, diskAfter)
	}
	if memAfter != 0 {
		t.Fatalf("mem usage = %d, want 0", memAfter)
	}

	// The whole run is retried and then fully drained.
	sent, drained, err := s.Drain(context.Background(), func(ctx context.Context, env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("second Drain: %v", err)
	}
	if sent != 3 || len(drained) != 1 {
		t.Fatalf("second drain: sent=%d drained=%v, want 3/[run_u]", sent, drained)
	}
	if m, d := s.Usage(); m != 0 || d != 0 {
		t.Fatalf("usage after full drain = (%d,%d), want (0,0)", m, d)
	}
}

var errStop = errors.New("stop")
