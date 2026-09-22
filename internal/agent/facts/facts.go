// Package facts collects host-level information that the agent reports to the
// server as FactsBatch envelopes (architecture §4.2).
package facts

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/blawesom/partout/internal/identity"
)

// Version is injected at build time: go build -ldflags "-X .../facts.Version=1.2.3".
var Version = "0.0.0-dev"

// Collector returns the host's fact set (key → value) to send as a full
// FactsBatch.
func Collector(id *identity.Identity, factsInterval int) map[string]string {
	m := make(map[string]string)
	if id != nil {
		m["partout.agent_uuid"] = id.UUID
	}
	m["partout.version"] = Version
	m["partout.facts_interval_s"] = strconv.Itoa(factsInterval)

	if h, err := os.Hostname(); err == nil {
		m["host.hostname"] = h
	}
	m["host.os"] = runtime.GOOS
	m["host.arch"] = runtime.GOARCH
	m["host.cpu_count"] = strconv.Itoa(runtime.NumCPU())
	m["runtime.go_version"] = runtime.Version()

	if kr := kernelRelease(); kr != "" {
		m["host.kernel"] = kr
	}
	if mem, ok := memTotalBytes(); ok {
		m["host.mem_total_bytes"] = strconv.FormatUint(mem, 10)
	}
	if u, ok := uptimeS(); ok {
		m["host.uptime_s"] = strconv.FormatInt(u, 10)
	}
	if ip := localIP(); ip != "" {
		m["host.local_ip"] = ip
	}
	return m
}

// kernelRelease returns the kernel release (e.g. "5.15.0-100-generic").
func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// memTotalBytes reads MemTotal (bytes) from /proc/meminfo.
func memTotalBytes() (uint64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

// uptimeS reads the system uptime (seconds) from /proc/uptime.
func uptimeS() (int64, bool) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(b))
	if len(f) < 1 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, false
	}
	return int64(v), true
}

// localIP returns the first non-loopback unicast IPv4 address (best effort).
func localIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ip4 := ipnet.IP.To4(); ip4 != nil {
			return fmt.Sprint(ip4)
		}
	}
	return ""
}
