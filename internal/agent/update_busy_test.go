package agent

import "testing"

// TestUpdateBusyGuard: the process runs at most one update at a time. A
// duplicate directive while the first is in flight must be rejected (the
// server's drain logic is the primary dedup; this is defense in depth —
// two concurrent swaps of the same binary path would corrupt N-1 retention).
func TestUpdateBusyGuard(t *testing.T) {
	a := &Agent{}
	if !a.beginUpdate() {
		t.Fatal("first beginUpdate must succeed")
	}
	if a.beginUpdate() {
		t.Fatal("second beginUpdate while in flight must fail")
	}
	a.endUpdate()
	if !a.beginUpdate() {
		t.Fatal("beginUpdate after endUpdate must succeed")
	}
}
