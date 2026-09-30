package version

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.9.1", "0.9.0", 1},
		{"0.9.0", "0.9.1", -1},
		{"0.9.0", "0.9.0", 0},
		{"0.10.0", "0.9.9", 1}, // numeric, not lexicographic
		{"0.9", "0.9.1", -1},   // shorter prefix is older
		{"0.9.1", "0.9", 1},
		{"v0.9.1", "0.9.1", 0}, // leading v ignored
		{"0.9.1", "v0.9.1", 0},
		{"", "0.9.0", -1}, // empty sorts oldest
		{"0.9.0", "", 1},
		{"", "", 0},
		{"1.0.0", "0.99.99", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsNewer(t *testing.T) {
	if !IsNewer("0.9.1", "0.9.0") {
		t.Error("0.9.1 should be newer than 0.9.0")
	}
	if IsNewer("0.9.0", "0.9.0") {
		t.Error("equal versions are not newer")
	}
	if IsNewer("0.8.0", "0.9.0") {
		t.Error("older version must not be newer")
	}
}
