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
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
  policy <list|create|delete>                manage policy deny rules
  provision <new|list|get|key|cancel>        host provisioning (admin)
  ca                       fetch the server root CA (PEM) for agent TLS enrollment
  files stat  --agent A --path P             show file metadata
  files list  --agent A --dir D              directory listing
  files upload --agent A --path P --file F  upload a local file (base64) to agent
  files edit  --agent A --path P --file F   compare-and-swap rewrite (needs sha)
  files perm  --agent A --path P --mode M   change file mode/ownership
  sessions open --agent A --cmd CMD         start an interactive PTY session
  sessions close <id>                       end a PTY session
  sessions list --agent A                   recent sessions
  sessions replay <id>                      replay recorded PTY chunks
  auth login --username U [--password P]    log in; stores the session token
`)
	}
	fs.Parse(reorderGlobalFlags(args))

	// Token resolution: --token flag > PARTOUT_CTL_TOKEN env > saved session
	// token from `ctl auth login` (~/.config/partout/token).
	if *token == "" {
		if tf, err := ctlTokenFile(); err == nil {
			if b, err := os.ReadFile(tf); err == nil {
				*token = strings.TrimSpace(string(b))
			}
		}
	}

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

	base := *server
	if !strings.Contains(base, "://") {
		base = scheme + "://" + base
	}

	c := &ctl{
		base:   base,
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
	case "policy":
		c.cmdPolicy(rest)
	case "provision":
		c.cmdProvision(rest)
	case "ca":
		c.cmdCA()
	case "files":
		c.cmdFiles(rest)
	case "sessions":
		c.cmdSessions(rest)
	case "secrets":
		c.cmdSecrets(rest)
	case "packages":
		c.cmdPackages(rest)
	case "tasks":
		c.cmdTasks(rest)
	case "playbooks":
		c.cmdPlaybooks(rest)
	case "jobs":
		c.cmdJobs(rest)
	case "external-data":
		c.cmdExternalData(rest)
	case "auth":
		c.cmdAuth(rest)
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

// ctlTokenFile is where `ctl auth login` persists the session token
// (~/.config/partout/token, 0600).
func ctlTokenFile() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "partout", "token"), nil
}

// cmdAuth handles `ctl auth login` (PRD Decision 6).
func (c *ctl) cmdAuth(args []string) {
	if len(args) < 1 || args[0] != "login" {
		fmt.Fprintln(os.Stderr, "usage: partout ctl auth login --username U [--password P]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("partout ctl auth login", flag.ExitOnError)
	username := fs.String("username", "", "username (required)")
	password := fs.String("password", envOr("PARTOUT_PASSWORD", ""), "password (or set PARTOUT_PASSWORD)")
	fs.Parse(args[1:])
	if *username == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "auth login: --username and --password (or PARTOUT_PASSWORD) are required")
		os.Exit(2)
	}
	var res struct {
		Token  string `json:"token"`
		Role   string `json:"role"`
		Expire int64  `json:"expires_unix"`
	}
	if err := c.do("POST", "/api/v1/auth/login",
		map[string]string{"username": *username, "password": *password}, &res); err != nil {
		fatal(err)
	}
	if tf, err := ctlTokenFile(); err == nil {
		if err := os.MkdirAll(filepath.Dir(tf), 0o700); err == nil {
			if err := os.WriteFile(tf, []byte(res.Token+"\n"), 0o600); err == nil {
				fmt.Fprintf(os.Stderr, "logged in as %s (role %s); token saved to %s\n", *username, res.Role, tf)
				return
			}
		}
	}
	// Could not persist; print the token for manual use.
	fmt.Println(res.Token)
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

// ---- policy ----------------------------------------------------------------

func (c *ctl) cmdPolicy(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: partout ctl policy <list|create|delete>")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		c.policyList()
	case "create":
		c.policyCreate(rest)
	case "delete":
		if len(rest) < 1 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl policy delete POLICY_ID")
			os.Exit(2)
		}
		c.policyDelete(rest[0])
	default:
		fmt.Fprintf(os.Stderr, "ctl: unknown policy command %q\n", sub)
		os.Exit(2)
	}
}

func (c *ctl) policyList() {
	var page map[string]any
	if err := c.do("GET", "/api/v1/policies", nil, &page); err != nil {
		fatal(err)
	}
	items, _ := page["items"].([]any)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tEFFECT\tPRIORITY\tMATCH\t")
	for _, it := range items {
		e, _ := it.(map[string]any)
		match, _ := e["match"].(map[string]any)
		var matchStr string
		if regex, ok := match["command_regex"].(string); ok && regex != "" {
			matchStr = "cmd=~" + regex
		}
		if hosts, ok := match["hosts"].(string); ok && hosts != "" {
			matchStr += " host=" + hosts
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t\n",
			strval(e["id"]), strval(e["name"]), strval(e["effect"]), int(num(e["priority"])), matchStr)
	}
	w.Flush()
	fmt.Printf("\n%d rule(s)\n", len(items))
}

func (c *ctl) policyCreate(args []string) {
	fs := flag.NewFlagSet("policy create", flag.ExitOnError)
	name := fs.String("name", "", "rule name (required)")
	effect := fs.String("effect", "deny", "deny | require_approval | allow")
	hosts := fs.String("hosts", "", "host selector (e.g. role:db, tag:env=lab)")
	actions := fs.String("actions", "", "comma-separated action classes (exec,file)")
	actorRoles := fs.String("actor-roles", "", "comma-separated RBAC roles (admin,operator,viewer)")
	commandRegex := fs.String("command-regex", "", "regex against 'cmd args...'")
	priority := fs.Int("priority", 100, "lower = higher precedence")
	fs.Parse(args)

	if *name == "" {
		fatal(fmt.Errorf("--name is required"))
	}

	req := map[string]any{"name": *name, "effect": *effect, "priority": *priority}
	match := map[string]any{}
	if *hosts != "" {
		match["hosts"] = *hosts
	}
	if *actions != "" {
		match["actions"] = strings.Split(*actions, ",")
	}
	if *actorRoles != "" {
		match["actor_roles"] = strings.Split(*actorRoles, ",")
	}
	if *commandRegex != "" {
		match["command_regex"] = *commandRegex
	}
	if len(match) > 0 {
		req["match"] = match
	}
	var res map[string]string
	if err := c.do("POST", "/api/v1/policies", req, &res); err != nil {
		fatal(err)
	}
	fmt.Printf("policy %s created\n", res["id"])
}

func (c *ctl) policyDelete(id string) {
	var res map[string]string
	if err := c.do("DELETE", "/api/v1/policies/"+id, nil, &res); err != nil {
		fatal(err)
	}
	fmt.Printf("policy %s deleted\n", res["deleted"])
}

// ---- provision -----------------------------------------------------------

func (c *ctl) cmdProvision(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: partout ctl provision <new|list|get|key|cancel>")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "new":
		c.provisionNew(rest)
	case "list":
		c.provisionList()
	case "get":
		if len(rest) < 1 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl provision get RUN_ID")
			os.Exit(2)
		}
		c.provisionGet(rest[0])
	case "key":
		// provision key RUN_ID confirm|deny
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl provision key RUN_ID confirm|deny")
			os.Exit(2)
		}
		c.provisionKey(rest[0], rest[1])
	case "cancel":
		if len(rest) < 1 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl provision cancel RUN_ID")
			os.Exit(2)
		}
		c.provisionCancel(rest[0])
	default:
		fmt.Fprintf(os.Stderr, "ctl: unknown provision command %q\n", sub)
		os.Exit(2)
	}
}

func (c *ctl) provisionNew(args []string) {
	fs := flag.NewFlagSet("provision new", flag.ExitOnError)
	host := fs.String("host", "", "target host (ssh user@host)")
	mode := fs.String("mode", "fresh", "fresh | join")
	fs.Parse(args)
	if *host == "" {
		fatal(fmt.Errorf("--host is required"))
	}
	var res struct {
		ID    string `json:"id"`
		State string `json:"state"`
		Host  string `json:"host"`
	}
	if err := c.do("POST", "/api/v1/provision-runs", map[string]string{"host": *host, "mode": *mode}, &res); err != nil {
		fatal(err)
	}
	fmt.Printf("run %s started for %s (state: %s)\n", res.ID, res.Host, res.State)
	fmt.Println("watch with:  partout ctl provision get", res.ID)
	fmt.Println("confirm a new host key with:  partout ctl provision key", res.ID, "confirm")
}

func (c *ctl) provisionList() {
	var res struct {
		Items []map[string]any `json:"items"`
	}
	if err := c.do("GET", "/api/v1/provision-runs?limit=200", nil, &res); err != nil {
		fatal(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tHOST\tMODE\tSTATE\tSTEP\tAGENT\tERROR\t")
	for _, e := range res.Items {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			strval(e["id"]), strval(e["host"]), strval(e["mode"]), strval(e["state"]),
			strval(e["step"]), strval(e["agent_id"]), strval(e["error"]))
	}
	w.Flush()
	fmt.Printf("\n%d run(s)\n", len(res.Items))
}

func (c *ctl) provisionGet(runID string) {
	var res struct {
		Run   map[string]any   `json:"run"`
		Steps []map[string]any `json:"steps"`
	}
	if err := c.do("GET", "/api/v1/provision-runs/"+runID, nil, &res); err != nil {
		fatal(err)
	}
	r := res.Run
	fmt.Printf("run %s  [%s]\n", strval(r["id"]), strval(r["state"]))
	fmt.Printf("  host:      %s\n", strval(r["host"]))
	fmt.Printf("  mode:      %s\n", strval(r["mode"]))
	if fp := strval(r["fingerprint"]); fp != "" {
		fmt.Printf("  key:       %s\n", fp)
	}
	if agent := strval(r["agent_id"]); agent != "" {
		fmt.Printf("  agent:     %s\n", agent)
	}
	if step := strval(r["step"]); step != "" {
		fmt.Printf("  step:      %s\n", step)
	}
	if e := strval(r["error"]); e != "" {
		fmt.Printf("  error:     %s\n", e)
	}
	if len(res.Steps) > 0 {
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "\n  #\tSTEP\tSTATE\t")
		for _, s := range res.Steps {
			fmt.Fprintf(w, "  %d\t%s\t%s\t\n",
				int(num(s["seq"])), strval(s["name"]), strval(s["state"]))
			if out := strval(s["stdout_excerpt"]); out != "" {
				for _, line := range strings.Split(out, "\n") {
					fmt.Fprintf(w, "  \t\t  %s\t\n", line)
				}
			}
		}
		w.Flush()
	}
}

func (c *ctl) provisionKey(runID, action string) {
	var res map[string]string
	if err := c.do("POST", "/api/v1/provision-runs/"+runID+"/key", map[string]string{"action": action}, &res); err != nil {
		fatal(err)
	}
	fmt.Printf("run %s key %s\n", runID, res["action"])
}

func (c *ctl) provisionCancel(runID string) {
	var res map[string]string
	if err := c.do("POST", "/api/v1/provision-runs/"+runID+"/cancel", nil, &res); err != nil {
		fatal(err)
	}
	fmt.Printf("run %s cancelled\n", runID)
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

var ctlGlobalFlags = map[string]bool{"--server": true, "--token": true, "--ca-file": true}

// reorderGlobalFlags moves the ctl global flags that appear after the
// subcommand to the front, because the Go flag package stops parsing at the
// first positional argument — without this, `ctl hosts --server X` would not
// see --server. Subcommand-specific flags (e.g. --selector for `run`) are
// left where they are.
func reorderGlobalFlags(args []string) []string {
	pre, post := []string{}, []string{}
	subcmd := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") && !subcmd {
			pre = append(pre, a)
			if !strings.Contains(a, "=") && i+1 < len(args) { // space form
				i++
				pre = append(pre, args[i])
			}
			continue
		}
		if !strings.HasPrefix(a, "-") {
			subcmd = true
		}
		name, isGlobal := a, false
		if strings.HasPrefix(a, "--") {
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				name = a[:eq]
			}
			isGlobal = ctlGlobalFlags[name]
		}
		if isGlobal {
			pre = append(pre, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				pre = append(pre, args[i]) // space-form value
			}
			continue
		}
		post = append(post, a)
	}
	return append(pre, post...)
}

// ---- M2 CLI: files ----------------------------------------------------------

func (c *ctl) cmdFiles(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "ctl: files subcommand required (stat|list|upload|edit|perm)")
		os.Exit(2)
	}
	switch args[0] {
	case "stat":
		c.cmdFileStat(args[1:])
	case "list":
		c.cmdFileList(args[1:])
	case "upload":
		c.cmdFileUpload(args[1:])
	case "edit":
		c.cmdFileEdit(args[1:])
	case "perm":
		c.cmdFilePerm(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ctl: files: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func (c *ctl) cmdFileStat(args []string) {
	fs := flag.NewFlagSet("files stat", flag.ExitOnError)
	var agent, path string
	fs.StringVar(&agent, "agent", "", "agent host ID")
	fs.StringVar(&path, "path", "", "file path")
	fs.Parse(args)
	if agent == "" || path == "" {
		fmt.Fprintln(os.Stderr, "ctl: files stat: --agent and --path required")
		os.Exit(2)
	}
	var stat map[string]any
	q := "agent_id=" + agent + "&path=" + path
	if err := c.do("GET", "/api/v1/files/stat?"+q, nil, &stat); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: stat: %v\n", err)
		os.Exit(1)
	}
	b, _ := json.MarshalIndent(stat, "", "  ")
	fmt.Println(string(b))
}

func (c *ctl) cmdFileList(args []string) {
	fs := flag.NewFlagSet("files list", flag.ExitOnError)
	var agent, dir string
	fs.StringVar(&agent, "agent", "", "agent host ID")
	fs.StringVar(&dir, "dir", "", "directory to list")
	fs.Parse(args)
	if agent == "" || dir == "" {
		fmt.Fprintln(os.Stderr, "ctl: files list: --agent and --dir required")
		os.Exit(2)
	}
	var result struct {
		Entries   []map[string]any `json:"entries"`
		Truncated bool             `json:"truncated"`
	}
	q := "agent_id=" + agent + "&path=" + dir
	if err := c.do("GET", "/api/v1/files/list?"+q, nil, &result); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: list: %v\n", err)
		os.Exit(1)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tIS_DIR\tSIZE\tMODE\tMTIME")
	for _, e := range result.Entries {
		fmt.Fprintf(w, "%s\t%v\t%s\t%s\t%s\n",
			e["name"], e["is_dir"], numStr(e["size"]), e["mode"], numStr(e["mtime_unix"]))
	}
	w.Flush()
	if result.Truncated {
		fmt.Fprintln(os.Stderr, "(list truncated — more entries in directory)")
	}
}

func (c *ctl) cmdFileUpload(args []string) {
	fs := flag.NewFlagSet("files upload", flag.ExitOnError)
	var agent, path, file, mode string
	fs.StringVar(&agent, "agent", "", "agent host ID")
	fs.StringVar(&path, "path", "", "remote file path")
	fs.StringVar(&file, "file", "", "local file to upload")
	fs.StringVar(&mode, "mode", "0644", "octal file mode")
	fs.Parse(args)
	if agent == "" || path == "" || file == "" {
		fmt.Fprintln(os.Stderr, "ctl: files upload: --agent, --path and --file required")
		os.Exit(2)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctl: read file: %v\n", err)
		os.Exit(2)
	}
	enc := base64.StdEncoding.EncodeToString(b)
	var resp map[string]string
	body := map[string]any{"agent_id": agent, "path": path, "content_b64": enc, "mode": mode}
	if err := c.do("POST", "/api/v1/files/upload", body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: upload: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("uploaded sha256: %s\n", resp["sha256"])
}

func (c *ctl) cmdFileEdit(args []string) {
	fs := flag.NewFlagSet("files edit", flag.ExitOnError)
	var agent, path, file, sha string
	fs.StringVar(&agent, "agent", "", "agent host ID")
	fs.StringVar(&path, "path", "", "file path to edit")
	fs.StringVar(&file, "file", "", "local file with new content")
	fs.StringVar(&sha, "sha", "", "expected sha256 (compare-and-swap)")
	fs.Parse(args)
	if agent == "" || path == "" || file == "" || sha == "" {
		fmt.Fprintln(os.Stderr, "ctl: files edit: --agent, --path, --file and --sha required")
		os.Exit(2)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctl: read file: %v\n", err)
		os.Exit(2)
	}
	enc := base64.StdEncoding.EncodeToString(b)
	var resp map[string]string
	body := map[string]any{
		"agent_id": agent, "path": path, "expected_sha256": sha,
		"content_b64": enc,
	}
	if err := c.do("POST", "/api/v1/files/edit", body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: edit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("edited sha256: %s\n", resp["sha256"])
}

func (c *ctl) cmdFilePerm(args []string) {
	fs := flag.NewFlagSet("files perm", flag.ExitOnError)
	var agent, path, mode, owner, group string
	fs.StringVar(&agent, "agent", "", "agent host ID")
	fs.StringVar(&path, "path", "", "file path")
	fs.StringVar(&mode, "mode", "", "octal mode, e.g. 0644")
	fs.StringVar(&owner, "owner", "", "new owner name")
	fs.StringVar(&group, "group", "", "new group name")
	fs.Parse(args)
	if agent == "" || path == "" {
		fmt.Fprintln(os.Stderr, "ctl: files perm: --agent and --path required")
		os.Exit(2)
	}
	body := map[string]any{"agent_id": agent, "path": path}
	if mode != "" {
		body["mode"] = mode
	}
	if owner != "" {
		body["owner"] = owner
	}
	if group != "" {
		body["group"] = group
	}
	if body["mode"] == nil && body["owner"] == nil && body["group"] == nil {
		fmt.Fprintln(os.Stderr, "ctl: files perm: --mode, --owner or --group required")
		os.Exit(2)
	}
	var resp map[string]string
	if err := c.do("POST", "/api/v1/files/perm", body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: perm: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("permission changed")
}

// numStr renders a JSON-decoded number (float64) as an integer string.
func numStr(v any) string {
	if f, ok := v.(float64); ok {
		return strconv.FormatInt(int64(f), 10)
	}
	return fmt.Sprintf("%v", v)
}

// ---- M2 CLI: sessions ------------------------------------------------------

func (c *ctl) cmdSessions(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "ctl: sessions subcommand required (open|close|list|replay)")
		os.Exit(2)
	}
	switch args[0] {
	case "open":
		c.cmdSessionOpen(args[1:])
	case "close":
		c.cmdSessionClose(args[1:])
	case "list":
		c.cmdSessionList(args[1:])
	case "replay":
		c.cmdSessionReplay(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ctl: sessions: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func (c *ctl) cmdSessionOpen(args []string) {
	fs := flag.NewFlagSet("sessions open", flag.ExitOnError)
	var agent, cmd string
	var cols, rows int
	var record bool
	fs.StringVar(&agent, "agent", "", "agent host ID")
	fs.StringVar(&cmd, "cmd", "", "command to execute")
	fs.IntVar(&cols, "cols", 80, "terminal columns")
	fs.IntVar(&rows, "rows", 24, "terminal rows")
	fs.BoolVar(&record, "record", false, "record PTY output for replay")
	fs.Parse(args)
	if agent == "" || cmd == "" {
		fmt.Fprintln(os.Stderr, "ctl: sessions open: --agent and --cmd required")
		os.Exit(2)
	}
	var resp map[string]any
	body := map[string]any{
		"agent_id": agent, "cmd": cmd,
		"cols": cols, "rows": rows, "record": record,
	}
	if err := c.do("POST", "/api/v1/sessions", body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: open: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("session opened: id=%s agent=%s cmd=%s state=%s\n",
		resp["session_id"], resp["agent_id"], resp["cmd"], resp["state"])
}

func (c *ctl) cmdSessionClose(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "ctl: sessions close: <session_id> required")
		os.Exit(2)
	}
	sid := args[0]
	var resp map[string]string
	if err := c.do("POST", "/api/v1/sessions/"+url.PathEscape(sid)+"/close", nil, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: close: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("session closed")
}

func (c *ctl) cmdSessionList(args []string) {
	fs := flag.NewFlagSet("sessions list", flag.ExitOnError)
	var agent string
	fs.StringVar(&agent, "agent", "", "filter by agent ID")
	fs.Parse(args)
	q := "agent_id=" + agent
	var result struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := c.do("GET", "/api/v1/sessions?"+q, nil, &result); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: list sessions: %v\n", err)
		os.Exit(1)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAGENT\tCMD\tSTATE\tEXIT\tOPENED")
	for _, s := range result.Sessions {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\t%s\n",
			s["session_id"], s["agent_id"], s["cmd"], s["state"],
			s["exit_code"], numStr(s["opened_unix"]))
	}
	w.Flush()
}

func (c *ctl) cmdSessionReplay(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "ctl: sessions replay: <session_id> required")
		os.Exit(2)
	}
	sid := args[0]
	var result struct {
		Frames []map[string]any `json:"frames"`
	}
	if err := c.do("GET", "/api/v1/sessions/"+url.PathEscape(sid)+"/replay", nil, &result); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: replay: %v\n", err)
		os.Exit(1)
	}
	for _, f := range result.Frames {
		enc, _ := f["data_b64"].(string)
		b, _ := base64.StdEncoding.DecodeString(enc)
		fmt.Printf("[seq %s] %s\n", numStr(f["seq"]), strings.TrimRight(string(b), "\n"))
	}
}

// ---- URL escape for session IDs in REST paths --------------------------------

// ---- secrets (M3, PRD §5.7) -------------------------------------------------

func (c *ctl) cmdSecrets(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: ctl secrets <list|create|rotate|revoke|delete> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		c.secretList()
	case "create":
		c.secretCreate(args[1:])
	case "rotate":
		c.secretRotate(args[1:])
	case "revoke":
		c.secretRevoke(args[1:])
	case "delete":
		c.secretDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ctl: secrets: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func (c *ctl) secretList() {
	var out struct {
		Secrets []map[string]any `json:"secrets"`
	}
	if err := c.do("GET", "/api/v1/secrets", nil, &out); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: secrets list: %v\n", err)
		os.Exit(1)
	}
	if len(out.Secrets) == 0 {
		fmt.Println("(no secrets)")
		return
	}
	fmt.Printf("%-24s %-16s %-6s %-8s\n", "NAME", "SELECTOR", "VER", "AGENTS")
	for _, s := range out.Secrets {
		fmt.Printf("%-24s %-16s %-6s %-8s\n",
			numStr(s["name"]), numStr(s["selector"]), numStr(s["version"]), numStr(s["agent_count"]))
	}
}

func (c *ctl) secretCreate(args []string) {
	fs := flag.NewFlagSet("secrets create", flag.ExitOnError)
	value := fs.String("value", "", "secret value (required)")
	valueFile := fs.String("value-file", "", "read value from file (mutually exclusive with -value)")
	selector := fs.String("selector", "", "selector expression (empty = all hosts)")
	ttl := fs.Int64("offline-ttl", 0, "agent-side encrypted cache window in seconds (0 = never)")
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: ctl secrets create <name> [-value=... | -value-file=...] [-selector=...] [-offline-ttl=N]")
		os.Exit(2)
	}
	name := fs.Arg(0)
	v := *value
	if *valueFile != "" {
		b, err := os.ReadFile(*valueFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ctl: read -value-file: %v\n", err)
			os.Exit(1)
		}
		v = string(bytes.TrimSpace(b))
	}
	if v == "" {
		fmt.Fprintln(os.Stderr, "ctl: -value or -value-file required")
		os.Exit(2)
	}
	body := map[string]any{"name": name, "value": v, "selector": *selector, "offline_ttl_s": *ttl}
	if err := c.do("POST", "/api/v1/secrets", body, nil); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: create: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("created secret %q (version 1)\n", name)
}

func (c *ctl) secretRotate(args []string) {
	fs := flag.NewFlagSet("secrets rotate", flag.ExitOnError)
	value := fs.String("value", "", "new value (required)")
	valueFile := fs.String("value-file", "", "read new value from file")
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: ctl secrets rotate <name> [-value=... | -value-file=...]")
		os.Exit(2)
	}
	name := fs.Arg(0)
	v := *value
	if *valueFile != "" {
		b, err := os.ReadFile(*valueFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ctl: read -value-file: %v\n", err)
			os.Exit(1)
		}
		v = string(bytes.TrimSpace(b))
	}
	if v == "" {
		fmt.Fprintln(os.Stderr, "ctl: -value or -value-file required")
		os.Exit(2)
	}
	var out struct {
		Version int64 `json:"version"`
	}
	if err := c.do("POST", "/api/v1/secrets/"+url.PathEscape(name)+"/rotate", map[string]string{"value": v}, &out); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: rotate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("rotated %q to version %d (prior versions revoked)\n", name, out.Version)
}

func (c *ctl) secretRevoke(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: ctl secrets revoke <name>")
		os.Exit(2)
	}
	if err := c.do("POST", "/api/v1/secrets/"+url.PathEscape(args[0])+"/revoke", map[string]string{}, nil); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: revoke: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("revoked %q (current version no longer materializable)\n", args[0])
}

func (c *ctl) secretDelete(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: ctl secrets delete <name>")
		os.Exit(2)
	}
	if err := c.do("DELETE", "/api/v1/secrets/"+url.PathEscape(args[0]), nil, nil); err != nil {
		fmt.Fprintf(os.Stderr, "ctl: delete: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("deleted %q\n", args[0])
}

// ---- external data (M3, PRD §6.3) -------------------------------------------

func (c *ctl) cmdExternalData(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: ctl external-data <status|refresh|host-eol> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "status":
		var out map[string]any
		if err := c.do("GET", "/api/v1/external-data/status", nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "ctl: status: %v\n", err)
			os.Exit(1)
		}
		for _, k := range []string{"air_gapped", "last_at", "last_error", "eol_count", "vuln_cached"} {
			if v, ok := out[k]; ok {
				fmt.Printf("%-12s %v\n", k+":", v)
			}
		}
	case "refresh":
		var out map[string]any
		if err := c.do("POST", "/api/v1/external-data/refresh", map[string]string{}, &out); err != nil {
			fmt.Fprintf(os.Stderr, "ctl: refresh: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("refresh: %v rows\n", out["rows"])
	case "host-eol":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ctl external-data host-eol <agent_id>")
			os.Exit(2)
		}
		var out map[string]any
		if err := c.do("GET", "/api/v1/hosts/"+url.PathEscape(args[1])+"/eol", nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "ctl: host-eol: %v\n", err)
			os.Exit(1)
		}
		for _, k := range []string{"state", "distro", "cycle", "eol_date", "extended_support", "cache_age_days"} {
			if v, ok := out[k]; ok {
				fmt.Printf("%-18s %v\n", k+":", v)
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "ctl: external-data: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

// ---- packages (M3, PRD §5.6) -----------------------------------------------

func (c *ctl) cmdPackages(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: ctl packages <updates|apply|actions> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "updates":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ctl packages updates <agent_id>")
			os.Exit(2)
		}
		agentID := args[1]
		var ups []map[string]any
		if err := c.do("GET", "/api/v1/packages/updates?agent_id="+url.PathEscape(agentID), nil, &ups); err != nil {
			fmt.Fprintf(os.Stderr, "ctl: updates: %v\n", err)
			os.Exit(1)
		}
		if len(ups) == 0 {
			fmt.Println("no updates available")
			return
		}
		fmt.Printf("%-30s %-25s %-25s %-8s %s\n", "NAME", "INSTALLED", "AVAILABLE", "CVEs", "SEVERITY")
		for _, u := range ups {
			fmt.Printf("%-30s %-25s %-25s %-8s %s\n",
				u["name"], u["installed"], u["available"],
				u["vuln_count"], u["max_severity"])
		}

	case "apply":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ctl packages apply <agent_id> [--dry-run] [--packages pkg1 pkg2]")
			os.Exit(2)
		}
		agentID := args[1]
		var pkgs []string
		dry := false
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--dry-run":
				dry = true
			case "--packages":
				i++
				if i < len(args) {
					pkgs = append(pkgs, args[i])
				}
			}
		}
		body := map[string]any{"agent_id": agentID, "dry_run": dry}
		if len(pkgs) > 0 {
			body["packages"] = pkgs
		}
		var out map[string]any
		if err := c.do("POST", "/api/v1/packages/apply", body, &out); err != nil {
			fmt.Fprintf(os.Stderr, "ctl: apply: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("status: %s  applied: %d  dry_run: %v\n", out["status"], out["applied_count"], dry)
		if out["error"] != "" {
			fmt.Fprintf(os.Stderr, "error: %v\n", out["error"])
		}
		if sum, ok := out["dry_summary"].(string); ok && sum != "" {
			lines := strings.Split(sum, "\n")
			for _, l := range lines {
				fmt.Println("  " + l)
			}
		}

	case "actions":
		var out []map[string]any
		if err := c.do("GET", "/api/v1/packages/actions", nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "ctl: actions: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%-18s %-10s %-12s %-6s %s\n", "ID", "KIND", "STATUS", "APPLIED", "ERROR")
		for _, a := range out {
			fmt.Printf("%-18s %-10s %-12s %-6d %s\n",
				a["id"], a["kind"], a["status"], a["applied_count"],
				a["error"])
		}

	default:
		fmt.Fprintf(os.Stderr, "ctl: packages: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func (c *ctl) cmdTasks(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: partout ctl tasks <list|create|show|run|runs|run-show>")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		var list []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := c.do("GET", "/api/v1/tasks", nil, &list); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		for _, t := range list {
			fmt.Printf("%s  %-30s  %s\n", t.ID, t.Name, t.Description)
		}

	case "create":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl tasks create <file.json>")
			os.Exit(2)
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		var body any
		if err := json.Unmarshal(data, &body); err != nil {
			fmt.Fprintln(os.Stderr, "error: bad JSON:", err)
			os.Exit(1)
		}
		var out map[string]any
		if err := c.do("POST", "/api/v1/tasks", body, &out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))

	case "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl tasks show <id>")
			os.Exit(2)
		}
		var out map[string]any
		if err := c.do("GET", "/api/v1/tasks/"+args[1], nil, &out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))

	case "run":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl tasks run <id> <agent_id>")
			os.Exit(2)
		}
		body := map[string]string{"agent_id": args[2]}
		var out map[string]any
		if err := c.do("POST", "/api/v1/tasks/"+args[1]+"/run", body, &out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))

	case "runs":
		var list []map[string]any
		if err := c.do("GET", "/api/v1/tasks/runs", nil, &list); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(list, "", "  ")
		fmt.Println(string(b))

	case "run-show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl tasks run-show <run_id>")
			os.Exit(2)
		}
		var out map[string]any
		if err := c.do("GET", "/api/v1/tasks/runs/"+args[1], nil, &out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))

	default:
		fmt.Fprintf(os.Stderr, "ctl: tasks: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func (c *ctl) cmdPlaybooks(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: partout ctl playbooks <list|create>")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		var list []map[string]any
		if err := c.do("GET", "/api/v1/playbooks", nil, &list); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(list, "", "  ")
		fmt.Println(string(b))

	case "create":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl playbooks create <file.json>")
			os.Exit(2)
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		var body any
		if err := json.Unmarshal(data, &body); err != nil {
			fmt.Fprintln(os.Stderr, "error: bad JSON:", err)
			os.Exit(1)
		}
		var out map[string]any
		if err := c.do("POST", "/api/v1/playbooks", body, &out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))

	default:
		fmt.Fprintf(os.Stderr, "ctl: playbooks: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func (c *ctl) cmdJobs(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: partout ctl jobs <list|create|show|update|delete|run|runs|list-runs>")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		var list []map[string]any
		if err := c.do("GET", "/api/v1/jobs", nil, &list); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		for _, j := range list {
			fmt.Printf("%s  %-30s  cron=%s  enabled=%v\n", j["id"], j["name"], j["cron"], j["enabled"])
		}

	case "create":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl jobs create <file.json>")
			os.Exit(2)
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		var body any
		if err := json.Unmarshal(data, &body); err != nil {
			fmt.Fprintln(os.Stderr, "error: bad JSON:", err)
			os.Exit(1)
		}
		var out map[string]any
		if err := c.do("POST", "/api/v1/jobs", body, &out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Println(string(data))

	case "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl jobs show <id>")
			os.Exit(2)
		}
		var out map[string]any
		if err := c.do("GET", "/api/v1/jobs/"+args[1], nil, &out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))

	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl jobs delete <id>")
			os.Exit(2)
		}
		if err := c.do("DELETE", "/api/v1/jobs/"+args[1], nil, nil); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Println("deleted", args[1])

	case "run":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl jobs run <id> <agent_id>")
			os.Exit(2)
		}
		body := map[string]string{"agent_id": args[2]}
		var out map[string]any
		if err := c.do("POST", "/api/v1/jobs/"+args[1]+"/run", body, &out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))

	case "runs":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: partout ctl jobs runs <job_id>")
			os.Exit(2)
		}
		var list []map[string]any
		if err := c.do("GET", "/api/v1/jobs/"+args[1]+"/runs", nil, &list); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(list, "", "  ")
		fmt.Println(string(b))

	case "list-runs":
		var list []map[string]any
		if err := c.do("GET", "/api/v1/jobs/runs", nil, &list); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(list, "", "  ")
		fmt.Println(string(b))

	default:
		fmt.Fprintf(os.Stderr, "ctl: jobs: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}
