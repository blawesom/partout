// Package spool is the agent's bounded local buffer for up-messages
// (command output chunks and results) that could not be delivered to the
// server (architecture §3.1.4, §3.4: 16 MB mem → 128 MB disk → drop-oldest,
// 24 h TTL, replay on reconnect).
//
// Model:
//
//   - One spool entry per run. Entries are the full up-Envelopes
//     (COMMAND_OUTPUT / COMMAND_RESULT) the server has not durably
//     confirmed, in per-run order.
//   - New records are held in memory. When total memory exceeds MemCap, the
//     oldest in-memory run is spilled wholesale to its disk log
//     (<dir>/<run_id>.sp, append-only records: [4-byte BE length][proto
//     Envelope], fsync'd). Disk is the durable tier: records survive agent
//     restarts (orphaned runs replay what they captured before the process
//     died; the server marks such runs interrupted and shows the partial
//     output).
//   - When total disk exceeds DiskCap, the oldest run (any tier) is dropped
//     wholesale. Runs older than TTL are dropped on append/drain/open.
//   - Drain sends complete runs (a run whose records include the
//     CommandResult) oldest first. A run is removed only after every record
//     sent without error; a failed send keeps the run for the next attempt.
//     Re-sends are safe: the server stores output chunks keyed by
//     (run_id, chunk_seq) and re-applies results idempotently
//     (at-least-once, arch §3.3).
//
// The spool is only written while the stream is down, so it never affects
// the steady-state hot path.
package spool

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/blawesom/partout/internal/proto"
)

// Proposed defaults (architecture §15), now implemented.
const (
	DefaultMemCap  = 16 << 20  // 16 MiB
	DefaultDiskCap = 128 << 20 // 128 MiB
	DefaultTTL     = 24 * time.Hour
)

// Config tunes a Spool. Zero MemCap/DiskCap/TTL select the defaults.
type Config struct {
	Dir     string        // spool directory (created 0700)
	MemCap  int64         // total in-memory bytes before spill (default 16 MiB)
	DiskCap int64         // total on-disk bytes before drop-oldest (default 128 MiB)
	TTL     time.Duration // per-run lifetime before drop (default 24h)
	Now     func() time.Time
}

func (c Config) fill() Config {
	if c.MemCap <= 0 {
		c.MemCap = DefaultMemCap
	}
	if c.DiskCap <= 0 {
		c.DiskCap = DefaultDiskCap
	}
	if c.TTL <= 0 {
		c.TTL = DefaultTTL
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// record is one unconfirmed up-message.
type record struct {
	env  *pb.Envelope
	size int64
}

// run is the spool state for one run: records in RAM and/or a disk log.
// Invariant: a run is either in the RAM tier (recs != nil, no file) or the
// disk tier (recs == nil, file on disk). Spill moves the whole run.
type run struct {
	id        string
	since     time.Time
	recs      []*record
	memBytes  int64
	diskBytes int64
	file      *os.File // open append handle (disk tier, lazy)
	hasResult bool
}

// Spool is a bounded, durable, per-run spool. All methods are safe for
// concurrent use.
type Spool struct {
	cfg    Config
	mu     sync.Mutex
	runs   map[string]*run
	order  []string // run ids, oldest first
	mem    int64    // total bytes in RAM tier
	disk   int64    // total bytes on disk
	closed bool
}

// Open creates (or reopens) the spool at cfg.Dir. Existing *.sp files are
// adopted as disk-tier runs (orphaned by a previous agent process); their
// records are replayed on the next drain.
func Open(cfg Config) (*Spool, error) {
	cfg = cfg.fill()
	if cfg.Dir == "" {
		return nil, errors.New("spool: dir required")
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("spool: mkdir: %w", err)
	}
	s := &Spool{
		cfg:  cfg,
		runs: make(map[string]*run),
	}
	entries, err := os.ReadDir(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("spool: readdir: %w", err)
	}
	type fileRun struct {
		r   *run
		ord int64
	}
	var adopted []fileRun
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".sp" {
			continue
		}
		id := e.Name()[:len(e.Name())-len(".sp")]
		info, err := e.Info()
		if err != nil {
			continue
		}
		mtime := info.ModTime()
		r := &run{id: id, since: mtime}
		hasRes, size, err := inspectFile(filepath.Join(cfg.Dir, e.Name()))
		if err != nil {
			// Unreadable/corrupt log — drop it rather than wedge the spool.
			_ = os.Remove(filepath.Join(cfg.Dir, e.Name()))
			continue
		}
		r.hasResult = hasRes
		r.diskBytes = size
		s.disk += size
		adopted = append(adopted, fileRun{r: r, ord: mtime.UnixNano()})
	}
	sort.Slice(adopted, func(i, j int) bool { return adopted[i].ord < adopted[j].ord })
	for _, a := range adopted {
		s.runs[a.r.id] = a.r
		s.order = append(s.order, a.r.id)
	}
	return s, nil
}

// Append adds one up-envelope to runID's spool, enforcing the memory cap
// (spill oldest RAM run to disk), the disk cap (drop oldest run), and the
// TTL (drop expired runs). It is safe to call for a run that was adopted
// from disk on open (new records append to the file).
func (s *Spool) Append(runID string, env *pb.Envelope) error {
	if env == nil {
		return errors.New("spool: nil envelope")
	}
	enc, err := encode(env)
	if err != nil {
		return fmt.Errorf("spool: encode: %w", err)
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("spool: closed")
	}
	s.pruneLocked(now)

	r, ok := s.runs[runID]
	if !ok {
		r = &run{id: runID, since: now, recs: []*record{}}
		s.runs[runID] = r
		s.order = append(s.order, runID)
	}
	if r.recs != nil { // RAM tier
		r.recs = append(r.recs, &record{env: env, size: int64(len(enc))})
		r.memBytes += int64(len(enc))
		s.mem += int64(len(enc))
	} else { // disk tier (incl. runs adopted from disk on open)
		if err := s.appendDiskLocked(r, enc); err != nil {
			return fmt.Errorf("spool: append disk: %w", err)
		}
		r.diskBytes += int64(len(enc))
		s.disk += int64(len(enc))
	}
	if env.Kind == pb.EnvelopeKind_COMMAND_RESULT {
		r.hasResult = true
	}

	// Memory cap: spill the oldest RAM-tier run until under the cap.
	for s.mem > s.cfg.MemCap {
		target := s.oldestRAMLocked()
		if target == nil {
			break
		}
		if err := s.spillLocked(target); err != nil {
			return fmt.Errorf("spool: spill: %w", err)
		}
	}
	// Disk cap: drop the oldest run until under the cap.
	for s.disk > s.cfg.DiskCap {
		if len(s.order) == 0 {
			break
		}
		s.dropLocked(s.order[0])
	}
	return nil
}

// Drain sends complete spooled runs (those with a CommandResult) to send,
// oldest first. A run is removed only after all its records are sent
// without error; on the first failed send the drain stops and the run (and
// younger ones) are kept for the next attempt. Returns the number of
// envelopes sent and the ids of fully drained runs.
func (s *Spool) Drain(ctx context.Context, send func(ctx context.Context, env *pb.Envelope) error) (int, []string, error) {
	sent := 0
	var drained []string
	for {
		if ctx.Err() != nil {
			return sent, drained, ctx.Err()
		}
		s.mu.Lock()
		s.pruneLocked(s.cfg.Now())
		var recs []*record
		id := ""
		for _, oid := range s.order {
			r := s.runs[oid]
			if !r.hasResult {
				continue
			}
			var err error
			recs, err = s.snapshotLocked(r)
			if err != nil {
				s.mu.Unlock()
				return sent, drained, fmt.Errorf("spool: snapshot: %w", err)
			}
			id = oid
			break
		}
		s.mu.Unlock()
		if id == "" {
			return sent, drained, nil
		}
		if len(recs) == 0 { // empty run with a result — cannot exist; drop
			s.dropRun(id)
			drained = append(drained, id)
			continue
		}
		for _, rec := range recs {
			if err := send(ctx, rec.env); err != nil {
				return sent, drained, err
			}
			sent++
		}
		s.dropRun(id)
		drained = append(drained, id)
	}
}

// Usage returns current spool usage: (memBytes, diskBytes), for heartbeats.
func (s *Spool) Usage() (int64, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mem, s.disk
}

// Runs returns the spooled run ids, oldest first (for tests/ops).
func (s *Spool) Runs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// Close closes open file handles. Records already written (and fsync'd)
// remain on disk for the next agent start.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	var first error
	for _, r := range s.runs {
		if r.file != nil {
			if err := r.file.Close(); err != nil && first == nil {
				first = err
			}
			r.file = nil
		}
	}
	return first
}

// ---- internals (callers hold s.mu unless noted) ----------------------------

// oldestRAMLocked returns the oldest run in the RAM tier, if any.
func (s *Spool) oldestRAMLocked() *run {
	for _, id := range s.order {
		if r := s.runs[id]; r != nil && r.recs != nil {
			return r
		}
	}
	return nil
}

// spillLocked moves a RAM-tier run wholesale to its disk log.
func (s *Spool) spillLocked(r *run) error {
	var buf []byte
	for _, rec := range r.recs {
		enc, err := encode(rec.env)
		if err != nil {
			return err
		}
		buf = append(buf, enc...)
	}
	if len(buf) > 0 {
		f, err := s.openFileLocked(r)
		if err != nil {
			return err
		}
		if _, err := f.Write(buf); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
	}
	r.diskBytes += int64(len(buf))
	s.disk += int64(len(buf))
	s.mem -= r.memBytes
	r.memBytes = 0
	r.recs = nil
	return nil
}

// appendDiskLocked appends encoded bytes to the run's disk log (fsync'd).
func (s *Spool) appendDiskLocked(r *run, enc []byte) error {
	f, err := s.openFileLocked(r)
	if err != nil {
		return err
	}
	if _, err := f.Write(enc); err != nil {
		return err
	}
	return f.Sync()
}

// openFileLocked opens the run's disk log for appending (lazy).
func (s *Spool) openFileLocked(r *run) (*os.File, error) {
	if r.file != nil {
		return r.file, nil
	}
	f, err := os.OpenFile(filepath.Join(s.cfg.Dir, r.id+".sp"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	r.file = f
	return f, nil
}

// snapshotLocked returns an ordered copy of a run's records (RAM tier:
// copies of the in-memory records; disk tier: records read from the file).
func (s *Spool) snapshotLocked(r *run) ([]*record, error) {
	if r.recs != nil {
		out := make([]*record, len(r.recs))
		copy(out, r.recs)
		return out, nil
	}
	return readSpoolFile(filepath.Join(s.cfg.Dir, r.id+".sp"))
}

// dropRun releases a run from the spool (file + memory). Lock-free entry:
// takes the lock itself; safe to call concurrently.
func (s *Spool) dropRun(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLocked(id)
}

// dropLocked removes a run and its file. No-op if the run is gone.
func (s *Spool) dropLocked(id string) {
	r, ok := s.runs[id]
	if !ok {
		return
	}
	delete(s.runs, id)
	for i, oid := range s.order {
		if oid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
	s.mem -= r.memBytes
	s.disk -= r.diskBytes
	_ = os.Remove(filepath.Join(s.cfg.Dir, id+".sp"))
}

// pruneLocked drops runs older than the TTL.
// pruneLocked drops runs older than the TTL, from the front (oldest first).
func (s *Spool) pruneLocked(now time.Time) {
	for len(s.order) > 0 {
		id := s.order[0]
		r := s.runs[id]
		if r == nil || now.Sub(r.since) > s.cfg.TTL {
			s.dropLocked(id)
			continue
		}
		break
	}
}

// encode serializes an envelope to the on-disk record form:
// [4-byte BE length][proto bytes].
func encode(env *pb.Envelope) ([]byte, error) {
	b, err := proto.Marshal(env)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out, nil
}

// readSpoolFile reads a spool file into records. A truncated trailing
// record (crash mid-write) is ignored; the next drain retries it.
func readSpoolFile(path string) ([]*record, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var out []*record
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return out, nil
			}
			return out, err
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > 1<<24 {
			return out, fmt.Errorf("spool: bad record length %d in %s", n, path)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			if err == io.ErrUnexpectedEOF {
				return out, nil // truncated tail
			}
			return out, err
		}
		env := &pb.Envelope{}
		if err := proto.Unmarshal(buf, env); err != nil {
			return nil, fmt.Errorf("spool: bad record in %s: %w", path, err)
		}
		out = append(out, &record{env: env, size: int64(4 + n)})
	}
}

// inspectFile parses a spool file to find whether its last record is a
// CommandResult, and returns the valid (whole-record) byte size.
func inspectFile(path string) (hasResult bool, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, 0, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var total int64
	lastKind := pb.EnvelopeKind_ENVELOPE_KIND_UNSPECIFIED
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return lastKind == pb.EnvelopeKind_COMMAND_RESULT, total, nil
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > 1<<24 {
			return lastKind == pb.EnvelopeKind_COMMAND_RESULT, total, nil
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return lastKind == pb.EnvelopeKind_COMMAND_RESULT, total, nil
		}
		env := &pb.Envelope{}
		if err := proto.Unmarshal(buf, env); err != nil {
			return false, 0, err
		}
		lastKind = env.Kind
		total += int64(4 + n)
	}
}
