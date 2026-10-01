package update

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/cryptoutil"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/release"
)

func testDirective(t *testing.T, version, arch, kind, sha, sig string) *pb.UpdateDirective {
	t.Helper()
	return &pb.UpdateDirective{
		ReleaseId: "rel_test", Version: version, Arch: arch, Kind: kind,
		Sha256: sha, Signature: sig, Grant: "g",
	}
}

func TestVerify(t *testing.T) {
	kp, err := cryptoutil.NewKeyPairEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub := release.PubKeyB64(kp.Pub)
	arch := runtime.GOOS + "-" + runtime.GOARCH
	sha := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Valid.
	m := release.Manifest{Version: "v0.9.0", Arch: arch, Kind: "agent", SHA256: sha}
	sig := base64.StdEncoding.EncodeToString(release.Sign(kp.Priv, m))
	if err := Verify(testDirective(t, "v0.9.0", arch, "agent", sha, sig), pub); err != nil {
		t.Fatalf("valid directive rejected: %v", err)
	}

	// No key → fail closed.
	if err := Verify(testDirective(t, "v0.9.0", arch, "agent", sha, sig), ""); err == nil {
		t.Error("no release key: want refusal")
	}
	// Garbage key.
	if err := Verify(testDirective(t, "v0.9.0", arch, "agent", sha, sig), "!!bad!!"); err == nil {
		t.Error("garbage key: want error")
	}
	// Wrong kind.
	if err := Verify(testDirective(t, "v0.9.0", arch, "server", sha, sig), pub); err == nil {
		t.Error("kind=server: want refusal on an agent")
	}
	// Arch mismatch.
	if err := Verify(testDirective(t, "v0.9.0", "linux-sparc", "agent", sha, sig), pub); err == nil {
		t.Error("arch mismatch: want refusal")
	}
	// Tampered version.
	if err := Verify(testDirective(t, "v0.9.1", arch, "agent", sha, sig), pub); err == nil {
		t.Error("tampered version: want refusal")
	}
	// Tampered sha.
	if err := Verify(testDirective(t, "v0.9.0", arch, "agent", "0"+sha[1:], sig), pub); err == nil {
		t.Error("tampered sha: want refusal")
	}
}

// TestVerifyUnsignedBetaMatrix: M8.1 beta — an unsigned directive is accepted
// only by a keyless agent; a provisioned key means strict-signed mode.
func TestVerifyUnsignedBetaMatrix(t *testing.T) {
	kp, err := cryptoutil.NewKeyPairEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub := release.PubKeyB64(kp.Pub)
	arch := runtime.GOOS + "-" + runtime.GOARCH
	sha := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	unsigned := func() *pb.UpdateDirective {
		d := testDirective(t, "v0.9.0", arch, "agent", sha, "")
		d.Unsigned = true
		return d
	}

	// Keyless agent + unsigned (server-authorised) → accepted.
	if err := Verify(unsigned(), ""); err != nil {
		t.Errorf("keyless agent should accept a server-authorised unsigned release: %v", err)
	}
	// Provisioned key + unsigned → refused (strict-signed mode).
	if err := Verify(unsigned(), pub); err == nil {
		t.Error("provisioned key + unsigned release: want refusal")
	}
	// Unsigned flag is not enough to skip kind/arch checks.
	bad := unsigned()
	bad.Arch = "linux-sparc"
	if err := Verify(bad, ""); err == nil {
		t.Error("unsigned + arch mismatch: want refusal")
	}
	// A signed directive is unaffected by the unsigned flag being false.
	m := release.Manifest{Version: "v0.9.0", Arch: arch, Kind: "agent", SHA256: sha}
	sig := base64.StdEncoding.EncodeToString(release.Sign(kp.Priv, m))
	if err := Verify(testDirective(t, "v0.9.0", arch, "agent", sha, sig), pub); err != nil {
		t.Errorf("signed directive with key still verifies: %v", err)
	}
}

func TestMarkerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := MarkerPath(dir)
	m := Marker{TargetVersion: "v0.9.0", ReleaseID: "rel_1", PrevBinary: "/x/partout.old", StartedAt: 1790000000}
	if err := WriteMarker(p, m); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, ok, err := ReadMarker(p)
	if err != nil || !ok {
		t.Fatalf("read: ok=%v err=%v", ok, err)
	}
	if got.TargetVersion != m.TargetVersion || got.ReleaseID != m.ReleaseID ||
		got.PrevBinary != m.PrevBinary || got.StartedAt != m.StartedAt {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	// Absent.
	if _, ok, _ := ReadMarker(filepath.Join(dir, "nope")); ok {
		t.Error("absent marker reported present")
	}
	// Corrupt → treated as absent.
	corrupt := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("garbage no equals\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ReadMarker(corrupt); ok {
		t.Error("corrupt marker reported present")
	}
	// Remove.
	if err := RemoveMarker(p); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ReadMarker(p); ok {
		t.Error("marker present after remove")
	}
	if err := RemoveMarker(p); err != nil {
		t.Error("remove of absent marker should be nil")
	}
}

// fakeBinary builds a dir with a standing "current" binary and returns it.
func fakeBinary(t *testing.T) (binPath string, dir string) {
	t.Helper()
	dir = t.TempDir()
	binPath = filepath.Join(dir, "partout")
	if err := os.WriteFile(binPath, []byte("current binary N"), 0o755); err != nil {
		t.Fatal(err)
	}
	return binPath, dir
}

func TestSwapAndRestore(t *testing.T) {
	binPath, dir := fakeBinary(t)
	artifact := []byte("new binary N+1")

	prevPath, prevSize, err := Swap(binPath, artifact)
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	if prevSize != int64(len("current binary N")) {
		t.Errorf("prevSize = %d, want %d", prevSize, len("current binary N"))
	}
	got, _ := os.ReadFile(binPath)
	if string(got) != string(artifact) {
		t.Errorf("binary after swap = %q, want the new artifact", got)
	}
	prev, _ := os.ReadFile(prevPath)
	if string(prev) != "current binary N" {
		t.Errorf("N-1 retention = %q, want the old binary", prev)
	}
	if _, err := os.Stat(filepath.Join(dir, "partout.new")); !os.IsNotExist(err) {
		t.Error("staging file left behind")
	}

	// Second consecutive update (v1 -> v2 -> v3): N-1 must be refreshed to
	// the binary that was CURRENTLY running (N+1), not the stale N left
	// over from the first swap — a failed v3 rolls back to v2, not v1.
	_, _, err = Swap(binPath, []byte("new binary N+1 again"))
	if err != nil {
		t.Fatalf("re-swap: %v", err)
	}
	prev, _ = os.ReadFile(prevPath)
	if string(prev) != "new binary N+1" {
		t.Errorf("N-1 after second swap = %q, want the previously running binary", prev)
	}

	// Restore N-1.
	if err := RestoreN1(binPath, prevPath); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, _ = os.ReadFile(binPath)
	if string(got) != "new binary N+1" {
		t.Errorf("binary after restore = %q, want the N-1", got)
	}

	// Idempotent re-swap with N-1 identical to the current binary must not
	// clobber N-1 (the guard-already-rolled-back case).
	_, _, err = Swap(binPath, []byte("attempt N+2"))
	if err != nil {
		t.Fatalf("third swap: %v", err)
	}
	// (N-1 now correctly = the running "new binary N+1".)
	prev, _ = os.ReadFile(prevPath)
	if string(prev) != "new binary N+1" {
		t.Errorf("N-1 before identical case drifted: %q", prev)
	}
}

func TestPostBootCheck(t *testing.T) {
	binPath, _ := fakeBinary(t)
	dir := t.TempDir()
	markerPath := MarkerPath(dir)
	prev := filepath.Join(filepath.Dir(binPath), "partout.old")
	if err := os.WriteFile(prev, []byte("current binary N"), 0o755); err != nil {
		t.Fatal(err)
	}

	// No marker → nothing.
	if _, ok, err := PostBootCheck(markerPath, "anything"); err != nil || ok {
		t.Errorf("no marker: ok=%v err=%v", ok, err)
	}

	// Matching version → marker returned for the caller to clear on connect.
	_ = WriteMarker(markerPath, Marker{
		TargetVersion: "v9", ReleaseID: "rel_1", PrevBinary: prev, StartedAt: time.Now().Unix(),
	})
	if _, ok, _ := PostBootCheck(markerPath, "v9"); !ok {
		t.Error("matching version: marker not reported")
	}
	if err := RemoveMarker(markerPath); err != nil {
		t.Fatal(err)
	}

	// v-prefix mismatch of placement (registered "v0.9.4", binary stamps
	// "0.9.4") must count as MATCHING — the field case that used to roll
	// back a healthy update.
	_ = WriteMarker(markerPath, Marker{
		TargetVersion: "v0.9.4", ReleaseID: "rel_1", PrevBinary: prev, StartedAt: time.Now().Unix(),
	})
	if _, ok, _ := PostBootCheck(markerPath, "0.9.4"); !ok {
		t.Error("v-prefixed target vs un-prefixed current version: should match")
	}
	if err := RemoveMarker(markerPath); err != nil {
		t.Fatal(err)
	}

	// Mismatched version → N-1 restored, marker cleared, ok=false.
	_ = WriteMarker(markerPath, Marker{
		TargetVersion: "v9", ReleaseID: "rel_1", PrevBinary: prev, StartedAt: time.Now().Unix(),
	})
	if _, ok, err := PostBootCheck(markerPath, "v8"); ok || err != nil {
		t.Errorf("mismatch: ok=%v err=%v (want ok=false, err=nil)", ok, err)
	}
	if _, present := os.Stat(markerPath); !os.IsNotExist(present) {
		t.Error("marker not cleared after mismatch rollback")
	}
}

func TestValidateBinary(t *testing.T) {
	// A stand-in "binary": a shell script answering --version like partout.
	script := func(out string) []byte { return []byte("#!/bin/sh\n" + out + "\n") }

	// Matching stamps (incl. both v-placement directions of the field bug).
	if err := ValidateBinary(script(`echo "partout 0.9.4"`), "0.9.4"); err != nil {
		t.Errorf("exact match: %v", err)
	}
	if err := ValidateBinary(script(`echo "partout 0.9.4"`), "v0.9.4"); err != nil {
		t.Errorf("v-prefixed manifest vs stamped binary: %v", err)
	}
	if err := ValidateBinary(script(`echo "partout v0.9.4"`), "0.9.4"); err != nil {
		t.Errorf("v-prefixed stamp vs stamped manifest: %v", err)
	}
	// Mislabeled build (signed bytes, wrong stamp) must be refused.
	if err := ValidateBinary(script(`echo "partout 0.9.3"`), "0.9.4"); err == nil {
		t.Error("mismatched stamp: want error")
	}
	// Not a partout binary.
	if err := ValidateBinary(script(`echo "hello world"`), "0.9.4"); err == nil {
		t.Error("non-partout --version output: want error")
	}
	// Not executable at all.
	if err := ValidateBinary([]byte("this is not a binary"), "0.9.4"); err == nil {
		t.Error("non-executable artifact: want error")
	}
}
