package hsauth

import (
	"testing"
	"time"
)

func TestBuildMsgDeterministic(t *testing.T) {
	nonce := []byte{1, 2, 3, 4, 5}
	m1 := BuildMsg(nonce, "uuid-1", 1000)
	m2 := BuildMsg(nonce, "uuid-1", 1000)
	if string(m1) != string(m2) {
		t.Fatal("BuildMsg not deterministic")
	}
	// Length: len(nonce) + len(uuid) + 8
	want := len(nonce) + len("uuid-1") + 8
	if len(m1) != want {
		t.Fatalf("len = %d, want %d", len(m1), want)
	}
}

func TestBuildMsgDiffersOnInput(t *testing.T) {
	m1 := BuildMsg([]byte{1}, "uuid-1", 1000)
	m2 := BuildMsg([]byte{2}, "uuid-1", 1000)
	if string(m1) == string(m2) {
		t.Fatal("different nonce should produce different msg")
	}
	m3 := BuildMsg([]byte{1}, "uuid-2", 1000)
	if string(m1) == string(m3) {
		t.Fatal("different uuid should produce different msg")
	}
	m4 := BuildMsg([]byte{1}, "uuid-1", 1001)
	if string(m1) == string(m4) {
		t.Fatal("different ts should produce different msg")
	}
}

func TestCheckSkew(t *testing.T) {
	now := time.Now()
	// Current time is fine.
	if err := CheckSkew(now.Unix(), now); err != nil {
		t.Fatalf("current time: %v", err)
	}
	// 100s ago is fine (within 300s).
	if err := CheckSkew(now.Unix()-100, now); err != nil {
		t.Fatalf("100s ago: %v", err)
	}
	// 400s ago is NOT fine (exceeds 300s).
	if err := CheckSkew(now.Unix()-400, now); err == nil {
		t.Fatal("400s ago should fail skew check")
	}
	// 400s in the future is also NOT fine.
	if err := CheckSkew(now.Unix()+400, now); err == nil {
		t.Fatal("400s in future should fail skew check")
	}
}
