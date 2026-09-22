package facts_test

import (
	"strconv"
	"testing"

	"github.com/blawesom/partout/internal/agent/facts"
)

func TestCollectorBasic(t *testing.T) {
	m := facts.Collector(nil, 3600)

	if m["host.hostname"] == "" {
		t.Error("host.hostname empty")
	}
	if m["host.os"] == "" {
		t.Error("host.os empty")
	}
	if m["host.arch"] == "" {
		t.Error("host.arch empty")
	}
	if m["partout.version"] == "" {
		t.Error("partout.version empty")
	}
	if m["partout.facts_interval_s"] != "3600" {
		t.Errorf("facts_interval_s = %q, want 3600", m["partout.facts_interval_s"])
	}
}

func TestCollectorCPUAndMem(t *testing.T) {
	m := facts.Collector(nil, 3600)

	if cpu, ok := m["host.cpu_count"]; ok {
		n, err := strconv.Atoi(cpu)
		if err != nil || n <= 0 {
			t.Errorf("host.cpu_count = %q (err=%v), want positive int", cpu, err)
		}
	}

	if mem, ok := m["host.mem_total_bytes"]; ok {
		n, err := strconv.ParseUint(mem, 10, 64)
		if err != nil || n == 0 {
			t.Errorf("host.mem_total_bytes = %q (err=%v), want positive", mem, err)
		}
	}
}

func TestCollectorNoNilIdentity(t *testing.T) {
	m := facts.Collector(nil, 60)
	if _, ok := m["partout.agent_uuid"]; ok {
		t.Error("partout.agent_uuid should be absent for nil identity")
	}
}
