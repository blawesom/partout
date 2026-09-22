// Package exec runs a command on the agent host, streaming stdout/stderr in
// bounded chunks, with timeout and cancellation (PRD C1, arch §6.1).
package exec

import (
	"context"
	"io"
	"os/exec"
	"sync"
	"time"
)

// MaxChunkSize is the max bytes per streamed output chunk (A3: 64 KiB).
const MaxChunkSize = 64 * 1024

// Chunk is a piece of command output.
type Chunk struct {
	Stream string // "stdout" | "stderr"
	Data   []byte
}

// Callback is invoked for each output chunk as it is produced.
type Callback func(c Chunk)

// Result is the terminal outcome of a run.
type Result struct {
	ExitCode   int32
	State      string // succeeded|failed|timed_out|cancelled|interrupted
	DurationMS int64
}

// Run executes the command, streaming output via onChunk, and returns the
// terminal result. The returned error is non-nil only for launch/startup
// failures (not for non-zero exit codes).
func Run(ctx context.Context, cmdName string, args []string, cwd string, env map[string]string, timeoutS int32, onChunk Callback) (*Result, error) {
	var cancel context.CancelFunc
	if timeoutS > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutS)*time.Second)
		defer cancel()
	}

	c := exec.CommandContext(ctx, cmdName, args...)
	if cwd != "" {
		c.Dir = cwd
	}
	if len(env) > 0 {
		c.Env = make([]string, 0, len(env))
		for k, v := range env {
			c.Env = append(c.Env, k+"="+v)
		}
	}

	stdout, err := c.StdoutPipe()
	if err != nil {
		return &Result{State: "failed"}, err
	}
	stderr, err := c.StderrPipe()
	if err != nil {
		return &Result{State: "failed"}, err
	}

	start := time.Now()
	if err := c.Start(); err != nil {
		return &Result{State: "failed", DurationMS: time.Since(start).Milliseconds()}, err
	}

	var wg sync.WaitGroup
	pump := func(r io.Reader, streamName string) {
		defer wg.Done()
		buf := make([]byte, MaxChunkSize)
		for {
			n, rerr := r.Read(buf)
			if n > 0 && onChunk != nil {
				data := make([]byte, n)
				copy(data, buf[:n])
				onChunk(Chunk{Stream: streamName, Data: data})
			}
			if rerr != nil {
				return
			}
		}
	}
	wg.Add(2)
	go pump(stdout, "stdout")
	go pump(stderr, "stderr")

	// Drain the pipes to completion BEFORE c.Wait(). The exec package docs are
	// explicit: StdoutPipe/StderrPipe say "Cmd.Wait will close the pipe after
	// seeing the command exit" and "it is incorrect to call Wait before all
	// reads from the pipe have completed." Calling Wait() first closes the
	// read-ends; a pump goroutine that hasn't yet read the data still buffered
	// in the OS pipe loses it (silent output loss). The pumps run concurrently
	// so the child never blocks on a full pipe, and EOF on a pipe only happens
	// once the child has exited, so this cannot deadlock.
	wg.Wait()
	waitErr := c.Wait()

	dur := time.Since(start).Milliseconds()
	res := &Result{DurationMS: dur}

	// Distinguish timeout/cancel from a normal non-zero exit.
	if ctx.Err() == context.DeadlineExceeded {
		res.State = "timed_out"
		res.ExitCode = -1
		return res, nil
	}
	if ctx.Err() == context.Canceled {
		res.State = "cancelled"
		res.ExitCode = -1
		return res, nil
	}
	if waitErr != nil {
		res.State = "failed"
		if ee, ok := waitErr.(*exec.ExitError); ok {
			res.ExitCode = int32(ee.ExitCode())
		} else {
			res.ExitCode = -1
		}
		return res, nil
	}
	res.State = "succeeded"
	res.ExitCode = 0
	return res, nil
}
