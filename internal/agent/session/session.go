// Package session manages interactive PTY sessions on the agent host
// (PRD §5.2.2, arch §3.2).
//
// Manager owns the live sessions. Each Session runs a process on a PTY:
// a read loop drains PTY output to a data callback and reaps the process;
// input/resize/close are dispatched through the Manager.
//
// Lifecycle (D2):
//
//   - Close (user-initiated): the master is closed, the process gets SIGHUP
//     from the line discipline, and is SIGKILLed if it survives 1 s. The
//     exit is reported via onResult (succeeded/failed by exit code).
//   - KillAll (stream disconnect): processes are SIGKILLed immediately and
//     reported as "interrupted". The agent cannot deliver that result over a
//     dead stream; the server marks sessions interrupted on disconnect.
package session

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/creack/pty"
)

// MaxChunkSize is the max PTY output chunk streamed up (64 KiB, A3).
const MaxChunkSize = 64 * 1024

// ResultFunc reports a session's terminal state.
type ResultFunc func(sessionID string, exitCode int32, state string, durationMs int64)

// Manager owns active PTY sessions.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	onResult ResultFunc
}

// NewManager creates a Manager; onResult is invoked on each session exit.
func NewManager(onResult ResultFunc) *Manager {
	return &Manager{sessions: make(map[string]*Session), onResult: onResult}
}

// Open starts a PTY session running name+args with the given window size.
// onData is invoked for each PTY output chunk (≤ 64 KiB, copied). The
// environment is a clean base (TERM, PATH, HOME, …) plus the declared env.
func (m *Manager) Open(sessionID, name string, args []string,
	env map[string]string, cols, rows int32,
	onData func(sessionID string, data []byte),
) error {
	cmd := exec.Command(name, args...)
	cmd.Env = cleanEnv(env, cols, rows)

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: uint16(rows), Cols: uint16(cols),
	})
	if err != nil {
		return fmt.Errorf("session: start %q: %w", name, err)
	}

	s := &Session{
		ID:       sessionID,
		cmd:      cmd,
		ptmx:     ptmx,
		start:    time.Now(),
		onData:   onData,
		onResult: m.onResult,
	}
	m.mu.Lock()
	if m.sessions[sessionID] != nil {
		m.mu.Unlock()
		ptmx.Close()
		return fmt.Errorf("session: %s: already open", sessionID)
	}
	m.sessions[sessionID] = s
	m.mu.Unlock()

	go s.readLoop()
	return nil
}

// Input writes data to the session's PTY stdin.
func (m *Manager) Input(sessionID string, data []byte) error {
	s := m.get(sessionID)
	if s == nil {
		return fmt.Errorf("session: %s: not found", sessionID)
	}
	return s.input(data)
}

// Resize changes the PTY window size.
func (m *Manager) Resize(sessionID string, cols, rows int32) error {
	s := m.get(sessionID)
	if s == nil {
		return fmt.Errorf("session: %s: not found", sessionID)
	}
	return pty.Setsize(s.ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
}

// Close ends a user-initiated session (SIGHUP, escalate to SIGKILL).
func (m *Manager) Close(sessionID string) error {
	m.mu.Lock()
	s := m.sessions[sessionID]
	delete(m.sessions, sessionID)
	m.mu.Unlock()
	if s == nil {
		return fmt.Errorf("session: %s: not found", sessionID)
	}
	s.closeGraceful()
	return nil
}

// KillAll forcibly terminates all active sessions (D2: stream disconnect).
// Returns the number killed.
func (m *Manager) KillAll() int {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.sessions = make(map[string]*Session)
	m.mu.Unlock()
	for _, s := range sessions {
		s.kill()
	}
	return len(sessions)
}

// Active returns the number of live sessions.
func (m *Manager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

func (m *Manager) get(id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

func (s *Session) input(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("session: %s: empty input", s.ID)
	}
	s.mu.Lock()
	closed := s.closed
	ptmx := s.ptmx
	s.mu.Unlock()
	if closed {
		return fmt.Errorf("session: %s: closed", s.ID)
	}
	_, err := ptmx.Write(data)
	return err
}

// closeGraceful ends a user-initiated session: close the master (the line
// discipline sends SIGHUP to the foreground group), escalate to SIGKILL if
// the process survives the grace period.
func (s *Session) closeGraceful() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.userClosed.Store(true)

	s.ptmx.Close()
	pro := s.cmd.Process
	go func() {
		time.Sleep(time.Second)
		if !s.reaped.Load() && pro != nil {
			_ = pro.Kill()
		}
	}()
}

// kill terminates the session immediately (D2: stream disconnect).
func (s *Session) kill() {
	s.killed.Store(true)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.ptmx.Close()
	if pro := s.cmd.Process; pro != nil {
		_ = pro.Kill()
	}
}

// Session is one PTY session. Managed by Manager; the read loop is the only
// goroutine that reaps the process.
type Session struct {
	ID   string
	cmd  *exec.Cmd
	ptmx *os.File
	mu   sync.Mutex
	// closed is set by Close/KillAll exactly once; guards double-close.
	closed bool
	start  time.Time

	killed     atomic.Bool // set by kill() before the process is killed
	userClosed atomic.Bool // user-initiated Close
	reaped     atomic.Bool // set by readLoop once cmd.Wait returns
	resulted   atomic.Bool

	onData   func(sessionID string, data []byte)
	onResult ResultFunc
}

// readLoop drains PTY output until the master is closed or the process
// exits, then reaps the process and reports the result exactly once.
func (s *Session) readLoop() {
	buf := make([]byte, MaxChunkSize)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			if s.onData != nil {
				s.onData(s.ID, data)
			}
		}
		if err != nil {
			break
		}
	}
	// Master is gone: the line discipline sent SIGHUP. Wait blocks until the
	// process actually exits; closeGraceful/kill escalate to SIGKILL so this
	// cannot hang indefinitely.
	err := s.cmd.Wait()
	s.reaped.Store(true)

	var exit int32
	state := "succeeded"
	if s.killed.Load() {
		state = "interrupted"
		exit = -1
	} else if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = int32(ee.ExitCode())
		} else {
			exit = -1
		}
		if s.userClosed.Load() {
			// A user close sends SIGHUP; the process exits by signal. This is a
			// deliberate termination, not an interruption, so report "closed".
			state = "closed"
		} else if exit != 0 {
			state = "failed"
		}
	}

	s.mu.Lock()
	start := s.start
	s.mu.Unlock()
	if s.onResult != nil && s.resulted.CompareAndSwap(false, true) {
		s.onResult(s.ID, exit, state, time.Since(start).Milliseconds())
	}
}

// cleanEnv builds the session environment: a small clean base plus the
// explicitly declared env (declared values win), per PRD §5.2 semantics.
func cleanEnv(declared map[string]string, cols, rows int32) []string {
	env := map[string]string{
		"TERM":    "xterm-256color",
		"PATH":    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"COLUMNS": fmt.Sprintf("%d", cols),
		"LINES":   fmt.Sprintf("%d", rows),
	}
	for _, keep := range []string{"HOME", "USER", "LOGNAME", "SHELL", "LANG"} {
		if v := os.Getenv(keep); v != "" {
			env[keep] = v
		}
	}
	for k, v := range declared {
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}
