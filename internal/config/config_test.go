package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeAndLoad(t *testing.T) {
	root := t.TempDir()
	created, err := Initialize(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) < 8 {
		t.Fatalf("expected starter files, got %d", len(created))
	}
	path := filepath.Join(root, filepath.FromSlash(DefaultPath))
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project.Name != filepath.Base(root) {
		t.Fatalf("unexpected project name %q", cfg.Project.Name)
	}
	cases, sources, err := LoadTestCases(root, cfg.Inputs.TestCases)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 5 || len(sources) != 5 {
		t.Fatalf("expected five cases, got %d", len(cases))
	}
	if _, err := os.Stat(filepath.Join(root, ".infraseal", "evidence", "knowledge-base.md")); err != nil {
		t.Fatal(err)
	}
}

func TestInitializeDoesNotOverwrite(t *testing.T) {
	root := t.TempDir()
	if _, err := Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(root, false); err == nil {
		t.Fatal("expected an overwrite guard error")
	}
}

func TestShouldExcludeSupportsCommonRepoGlobs(t *testing.T) {
	root := t.TempDir()
	excludes := []string{"node_modules/**", ".infraseal/reports/**", "**/*.pdf"}
	cases := map[string]bool{
		filepath.Join(root, "node_modules", "pkg", "index.js"):  true,
		filepath.Join(root, ".infraseal", "reports", "scan.md"): true,
		filepath.Join(root, "docs", "report.pdf"):               true,
		filepath.Join(root, "src", "agent.go"):                  false,
	}
	for path, want := range cases {
		if got := ShouldExclude(root, path, excludes); got != want {
			t.Fatalf("ShouldExclude(%s) = %t, want %t", path, got, want)
		}
	}
}

func TestLoadMergesDefaultExcludes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, filepath.FromSlash(DefaultPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("project:\n  name: custom\ninputs:\n  exclude:\n    - secrets/**\n")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{"secrets/key.txt", ".infraseal/reports/scan.json", ".infraseal/governance/risk-register.md"}
	for _, item := range cases {
		if !ShouldExclude(root, filepath.Join(root, filepath.FromSlash(item)), cfg.Inputs.Exclude) {
			t.Fatalf("expected %s to be excluded after load", item)
		}
	}
}
