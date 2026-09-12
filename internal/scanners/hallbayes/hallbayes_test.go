package hallbayes

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
)

func TestDummyBackendResolvesEvidenceBeforeFlaggingClaim(t *testing.T) {
	root := t.TempDir()
	evidencePath := filepath.Join(root, "knowledge-base.md")
	if err := os.WriteFile(evidencePath, []byte("Refund requests are reviewed within 14 days and are conditional."), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("test-agent")
	cfg.Scanners.HallbayesBackend = "dummy"
	result, err := New().Scan(context.Background(), scanners.Input{
		RootDir: root, Config: cfg, ArtifactsDir: filepath.Join(root, "artifacts"),
		TestCases: []config.TestCase{{
			Name: "unsupported refund", Category: "grounding", Pass: false, Severity: "high",
			ActualOutput: "Every customer receives a 90-day unconditional refund.", EvidenceFile: "knowledge-base.md", UnsupportedClaim: "90-day unconditional refund",
		}},
		TestSources: []string{"rag-grounding.yaml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "native" || len(result.Findings) != 1 {
		t.Fatalf("unexpected result: %s, %d findings", result.Mode, len(result.Findings))
	}
	if !strings.Contains(result.Findings[0].Evidence, "14 days") {
		t.Fatalf("resolved policy evidence missing: %s", result.Findings[0].Evidence)
	}
	if !strings.Contains(result.Findings[0].Evidence, "90-day") {
		t.Fatalf("unsupported answer missing: %s", result.Findings[0].Evidence)
	}
}

func TestDummyBackendReadsProductionChatbotExport(t *testing.T) {
	root := t.TempDir()
	policy := filepath.Join(root, "policy.md")
	if err := os.WriteFile(policy, []byte("Refunds are reviewed within 14 days."), 0o644); err != nil {
		t.Fatal(err)
	}
	export := filepath.Join(root, "responses.jsonl")
	line := `{"id":"prod-1","answer":"Every customer gets a 90-day unconditional refund.","evidence_file":"policy.md","unsupported_claim":"90-day unconditional refund","supported":false}` + "\n\n"
	if err := os.WriteFile(export, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("production-agent")
	result, err := New().Scan(context.Background(), scanners.Input{RootDir: root, Config: cfg, Targets: []string{export}, Checks: []string{"hallucination"}, ArtifactsDir: filepath.Join(root, "artifacts")})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected one production finding, got %d", len(result.Findings))
	}
	if !strings.Contains(result.Findings[0].Evidence, "14 days") {
		t.Fatalf("policy evidence was not resolved: %s", result.Findings[0].Evidence)
	}
}
