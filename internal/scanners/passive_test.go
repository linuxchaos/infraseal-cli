package scanners

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/linuxchaos/infraseal-cli/internal/config"
)

func TestFixtureFindingsRespectTargetedChecks(t *testing.T) {
	input := Input{
		Checks: []string{"hallucination"},
		TestCases: []config.TestCase{
			{Name: "unsupported answer", Category: "grounding", Severity: "high", Pass: false},
			{Name: "PII leak", Category: "pii", Severity: "critical", Pass: false},
		},
	}
	findings := FixtureFindings(input, []string{"grounding", "pii"}, "test", "mocked")
	if len(findings) != 1 || findings[0].Category != "grounding" {
		t.Fatalf("hallucination-only fixture scan returned unrelated findings: %#v", findings)
	}
}

func TestGoPackagePatternsRespectTargetsAndExcludes(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		filepath.Join(root, "app", "main.go"),
		filepath.Join(root, "vendor", "ignored", "main.go"),
		filepath.Join(root, "docs", "readme.md"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	patterns := GoPackagePatterns(root, []string{filepath.Join(root, "app"), filepath.Join(root, "vendor")}, []string{"vendor/**"})
	if len(patterns) != 1 || patterns[0] != "./app/..." {
		t.Fatalf("unexpected package patterns: %#v", patterns)
	}
}
