package main

import "testing"

func TestParseSumsLine(t *testing.T) {
	sums := "aa11  partout_0.9.5_linux_amd64.tar.gz\nbb22  partout_0.9.5_linux_arm64.tar.gz\ncc33  SHA-256SUMS\n"
	got, err := parseSumsLine(sums, "partout_0.9.5_linux_arm64.tar.gz")
	if err != nil || got != "bb22" {
		t.Fatalf("want bb22, got %q err=%v", got, err)
	}
	// Case-insensitive digest, multiple inner spaces (sha256sum output).
	got, err = parseSumsLine("AA11    partout_0.9.5_linux_amd64.tar.gz\n", "partout_0.9.5_linux_amd64.tar.gz")
	if err != nil || got != "aa11" {
		t.Fatalf("want aa11, got %q err=%v", got, err)
	}
	// Missing asset → error (fail closed).
	if _, err := parseSumsLine(sums, "partout_9.9.9_linux_amd64.tar.gz"); err == nil {
		t.Fatal("missing asset: want error")
	}
	// Trailing newline / blank lines are fine.
	if _, err := parseSumsLine("dd44  x.tar.gz\n\n", "x.tar.gz"); err != nil {
		t.Fatalf("blank lines: %v", err)
	}
}

func TestGitHubAssetName(t *testing.T) {
	cases := map[[2]string]string{
		{"0.9.5", "linux-amd64"}: "partout_0.9.5_linux_amd64.tar.gz",
		{"v0.9.5", "linux-arm64"}: "partout_0.9.5_linux_arm64.tar.gz",
		{"1.0.0", "linux-riscv64"}: "partout_1.0.0_linux_riscv64.tar.gz",
	}
	for in, want := range cases {
		if got := githubAssetName(in[0], in[1]); got != want {
			t.Errorf("githubAssetName(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestDefaultGitHubRepo(t *testing.T) {
	if got := defaultGitHubRepo(); got != "blawesom/partout" {
		t.Fatalf("defaultGitHubRepo = %q", got)
	}
}
