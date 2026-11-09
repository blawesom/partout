package api

import (
	"strings"
	"testing"

	"github.com/blawesom/partout/internal/agent/facts"
)

// TestIsReleaseVersion: only stamped semver counts as a release build (dev
// builds like "0.0.0-dev" keep the debug hooks in app.js).
func TestIsReleaseVersion(t *testing.T) {
	for _, v := range []string{"0.9.19", "1.0.0", "10.20.30"} {
		if !isReleaseVersion(v) {
			t.Errorf("isReleaseVersion(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "0.0.0-dev", "dev", "v0.9.19", "0.9", "0.9.19-beta", "0.9.x"} {
		if isReleaseVersion(v) {
			t.Errorf("isReleaseVersion(%q) = true, want false", v)
		}
	}
}

// TestIndexHTMLStampedRelease: with a stamped semver version, the served
// index.html carries the release build meta (app.js then keeps
// window.__partout unset). Dev versions keep content="dev".
func TestIndexHTMLStampedRelease(t *testing.T) {
	old := facts.Version
	defer func() { facts.Version = old }()

	facts.Version = "0.9.19"
	h := &Handler{}
	if got := string(h.indexHTML()); !strings.Contains(got, `name="partout-build" content="release"`) {
		t.Error("release build: index.html not stamped with content=\"release\"")
	}

	facts.Version = "0.0.0-dev"
	h = &Handler{}
	if got := string(h.indexHTML()); !strings.Contains(got, `name="partout-build" content="dev"`) {
		t.Error("dev build: index.html lost the dev meta tag")
	}
}
