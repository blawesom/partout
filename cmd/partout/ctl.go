// Command partout ctl — a minimal operator CLI over the REST v1 surface.
//
// It gives a human the full simplest-use-case loop without raw curl:
//
//	partout ctl --server 10.0.0.5:8443 --token $ADMIN_TOKEN enroll-token
//	partout ctl --server 10.0.0.5:8443 --token $ADMIN_TOKEN hosts
//	partout ctl --server 10.0.0.5:8443 --token $OPER_TOKEN run --selector all -- echo hello
//	partout ctl --server 10.0.0.5:8443 --token $VIEW_TOKEN exec exec_123
//	partout ctl --server 10.0.0.5:8443 --token $VIEW_TOKEN audit --kind exec.dispatch
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

type ctl struct {
	base   string // http://host:port
	token  string
	client *http.Client
}

func runCtl(args []string) {
	fs := flag.NewFlagSet("partout ctl", flag.ExitOnError)
	server := fs.String("server", envOr("PARTOUT_SERVER", ""), "server host:port")
	token := fs.String("token", envOr("PARTOUT_CTL_TOKEN", ""), "bearer token (admin|operator|viewer)")
	caFile := fs.String("ca-file", envOr("PARTOUT_TLS_CA", ""), "path to the server root CA (PEM); enables HTTPS")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: partout ctl --server host:port --token TOKEN [--ca-file ca.crt] <command>

commands:
  enroll-token [--ttl S]   create a one-time agent enrollment token
  hosts                    list hosts (id, state, version, last seen, tags)
  run --selector S -- CMD [ARGS...]  dispatch a command, wait, show per-run output
  exec EXEC_ID             show execution detail + output
  audit [--kind K] [--actor A] [--limit N]   show audit log
  ca                       fetch the server root CA (PEM) for agent TLS enrollment
`)
	}
	fs.Parse(args)

	if *server == "" {
		fmt.Fprintln(os.Stderr, "ctl: --server (or PARTOUT_SERVER) is required")
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}

	scheme := "http"
	client := &http.Client{Timeout: 30 * time.Second}
	if *caFile != "" {
		scheme = "https"
		caPEM, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ctl: read CA: %v\n", err)
			os.Exit(2)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			fmt.Fprintf(os.Stderr, "ctl: no valid certificate in %s\n", *caFile)
			os.Exit(2)
		}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}
	}

	c := &ctl{
		base:   scheme + "://" + *server,
		token:  *token,
		client: client,
	}
	sub, rest := fs.Arg(0), fs.Args()[1:]

	switch sub {
	case "enroll-token":
		c.cmdEnrollToken(rest)
	case "hosts":
		c.cmdHosts(rest)
	case "run":
		c.cmdRun(rest)
	case "exec":
		c.cmdExec(rest)
	case "audit":
		c.cmdAudit(rest)
	case "ca":
		c.cmdCA()
	case "help", "-h", "--help":
		fs.Usage()
	default:
		fmt.Fprintf(os.Stderr, "ctl: unknown command %q\n", sub)
		fs.Usage()
		os.Exit(2)
	}
}

func (c *ctl) cmdCA() {
	var res struct {
		Cert string `json:"cert"`
	}
	if err := c.do("GET", "/api/v1/tls/ca", nil, &res); err != nil {
		fatal(err)
	}
	fmt.Print(res.Cert)
}

// ---- HTTP helpers -----------------------------------------------------------

func (c *ctl) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("connect to server: %w (is it running, reachable, and the port right?)", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var eb struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &eb) == nil && eb.Message != "" {
			return fmt.Errorf("server: %s (%s)", eb.Message, eb.Code)
		}
		return fmt.Errorf("server: %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// ---- commands -----------------------------------------------------------------

func (c *ctl) cmdEnrollToken(args []string) {
	fs := flag.NewFlagSet("enroll-token", flag.ExitOnError)
	ttl := fs.Int("ttl", 900, "token TTL seconds")
	fs.Parse(args)

	var res struct {
		Token   string `json:"token"`
		Mask    string `json:"mask"`
		Expires int64  `json:"expires"`
	}
	if err := c.do("POST", "/api/v1/agents/enrollment-tokens", map[string]int{"ttl_s": *ttl}, &res); err != nil {
		fatal(err)
	}
	fmt.Printf("token:     %s\n", res.Token)
	fmt.Printf("expires:   %s (ttl %ds)\n", unixTime(res.Expires), *ttl)
	fmt.Println()
	fmt.Println("install on the target host:")
	fmt.Printf("  PARTOUT_SERVER=%s PARTOUT_TOKEN=%s partout --mode=agent\n",
		strings.TrimPrefix(c.base, "http://"), res.Token)
}

func (c *ctl) cmdHosts(args []string) {
	var page map[string]any
	if err := c.do("GET", "/api/v1/hosts", nil, &page); err != nil {
		fatal(err)
	}
	items, _ := page["items"].([]any)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTATE\tVERSION\tLAST SEEN\tTAGS\tROLES")
	for _, it := range items {
		h, _ := it.(map[string]any)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			strval(h["id"]), strval(h["state"]), strval(h["version"]),
			unixTime(int64(num(h["last_seen"]))),
			joinKVs(h["tags"]), strings.Join(strs(h["roles"]), ","))
	}
	w.Flush()
	fmt.Printf("\n%d host(s)\n", len(items))
}

func (c *ctl) cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	selector := fs.String("selector", "", "target selector (required)")
	timeout := fs.Int("timeout", 120, "per-host command timeout seconds")
	by := fs.String("by", "ctl", "created_by value")
	noWait := fs.Bool("no-wait", false, "don't wait for completion")
	var envs []string
	fs.Func("env", "env var K=V (repeatable)", func(v string) error { envs = append(envs, v); return nil })
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if *selector == "" || len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: partout ctl run --selector S -- CMD [ARGS...] [--timeout N] [--env K=V]")
		os.Exit(2)
	}
	cmd, cmdArgs := rest[0], rest[1:]

	env := map[string]string{}
	for _, e := range envs {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			fatal(fmt.Errorf("--env expects K=V, got %q", e))
		}
		env[k] = v
	}

	var dispatch map[string]any
	req := map[string]any{"selector": *selector, "cmd": cmd, "timeout_s": *timeout, "created_by": *by}
	if len(cmdArgs) > 0 {
		req["args"] = cmdArgs
	}
	if len(env) > 0 {
		req["env"] = env
	}
	if err := c.do("POST", "/api/v1/executions", req, &dispatch); err != nil {
		fatal(err)
	}
	execID, _ := dispatch["execution_id"].(string)
	fmt.Printf("execution %s dispatched\n", execID)
	if *noWait {
		return
	}

	state, err := c.waitForTerminal(execID, 5*time.Minute)
	if err != nil {
		fatal(err)
	}
	c.showExecution(execID, state)
}

func (c *ctl) cmdExec(args []string) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: partout ctl exec EXEC_ID")
		os.Exit(2)
	}
	execID := fs.Arg(0)
	var detail map[string]any
	if err := c.do("GET", "/api/v1/executions/"+execID, nil, &detail); err != nil {
		fatal(err)
	}
	c.showExecution(execID, detail)
}

func (c *ctl) cmdAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	kind := fs.String("kind", "", "filter by kind")
	actor := fs.String("actor", "", "filter by actor")
	limit := fs.Int("limit", 50, "max events")
	fs.Parse(args)

	q := fmt.Sprintf("/api/v1/audit?limit=%d", *limit)
	if *kind != "" {
		q += "&kind=" + *kind
	}
	if *actor != "" {
		q += "&actor=" + *actor
	}
	var page map[string]any
	if err := c.do("GET", q, nil, &page); err != nil {
		fatal(err)
	}
	items, _ := page["items"].([]any)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tKIND\tACTOR\tAGENT\t")
	for _, it := range items {
		e, _ := it.(map[string]any)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n",
			unixTime(int64(num(e["ts"]))), strval(e["kind"]), strval(e["actor"]), strval(e["agent_id"]))
	}
	w.Flush()
	fmt.Printf("\n%d event(s)\n", len(items))
}

// ---- shared display -----------------------------------------------------------

// showExecution prints execution detail + per-run output.
func (c *ctl) showExecution(execID string, detail map[string]any) {
	fmt.Printf("\nexecution %s  [%s]\n", execID, strval(detail["state"]))
	fmt.Printf("  selector:  %s\n", strval(detail["selector"]))
	cmdline := strval(detail["cmd"])
	if args, ok := detail["args"].([]any); ok && len(args) > 0 {
		cmdline += " " + joinStrings(args)
	}
	fmt.Printf("  command:   %s\n", cmdline)
	fmt.Printf("  created:   %s  by %s\n", unixTime(int64(num(detail["created"]))), strval(detail["created_by"]))

	runs, _ := detail["runs"].([]any)
	if len(runs) == 0 {
		return
	}
	fmt.Println("\n  runs:")
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "    RUN\tHOST\tSTATE\tEXIT\tDURATION")
	for _, r := range runs {
		run, _ := r.(map[string]any)
		fmt.Fprintf(w, "    %s\t%s\t%s\t%s\t%sms\n",
			strval(run["run_id"]), strval(run["agent_id"]), strval(run["state"]),
			strconv.Itoa(int(num(run["exit_code"]))), strconv.FormatInt(int64(num(run["duration_ms"])), 10))
	}
	w.Flush()

	// Fetch output.
	type outItem struct {
		RunID   string `json:"run_id"`
		AgentID string `json:"agent_id"`
		Stdout  string `json:"stdout"`
		Stderr  string `json:"stderr"`
	}
	var items []outItem
	if err := c.do("GET", "/api/v1/executions/"+execID+"/output", nil, &items); err != nil {
		return
	}
	for _, o := range items {
		if o.Stdout == "" && o.Stderr == "" {
			continue
		}
		fmt.Printf("\n  output [%s @ %s]:\n", o.RunID, o.AgentID)
		printIndented(o.Stdout)
		if o.Stderr != "" {
			printIndented("stderr: " + o.Stderr)
		}
	}
}

func (c *ctl) waitForTerminal(execID string, maxWait time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(maxWait)
	for {
		var detail map[string]any
		if err := c.do("GET", "/api/v1/executions/"+execID, nil, &detail); err != nil {
			return nil, err
		}
		switch strval(detail["state"]) {
		case "succeeded", "failed", "partial", "cancelled":
			return detail, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s (state=%s)", execID, strval(detail["state"]))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// ---- small helpers --------------------------------------------------------------

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ctl:", err)
	os.Exit(1)
}

func printIndented(s string) {
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		fmt.Println("    " + line)
	}
}

func unixTime(ts int64) string {
	if ts <= 0 {
		return "-"
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

func num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	}
	return 0
}

func strval(v any) string {
	s, _ := v.(string)
	return s
}

func joinStrings(items []any) string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = strval(it)
	}
	return strings.Join(out, " ")
}

func joinKVs(v any) string {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok && s != "" {
			parts = append(parts, k+"="+s)
		} else {
			parts = append(parts, k)
		}
	}
	return strings.Join(parts, ",")
}

func strs(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(arr))
	for i, it := range arr {
		out[i] = strval(it)
	}
	return out
}
