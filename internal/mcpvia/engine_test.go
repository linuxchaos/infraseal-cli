package mcpvia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/runtime"
	"github.com/linuxchaos/infraseal-cli/internal/runtime/local"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

func TestQuickScanPassesStarterCases(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	engine := New(nil, runtime.Resolver{Providers: map[string]runtime.Provider{"local": local.Provider{Workers: 1}}}, nil)
	result, err := engine.RunScan(context.Background(), schema.ScanRequest{ConfigPath: filepath.Join(root, filepath.FromSlash(config.DefaultPath)), Profile: "quick"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pass" || result.OverallScore != 100 {
		t.Fatalf("unexpected result: %s %d", result.Status, result.OverallScore)
	}
}

func TestGovernanceScanFindsStarterGaps(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	engine := New(nil, runtime.Resolver{Providers: map[string]runtime.Provider{"local": local.Provider{Workers: 1}}}, nil)
	result, err := engine.RunScan(context.Background(), schema.ScanRequest{ConfigPath: filepath.Join(root, filepath.FromSlash(config.DefaultPath)), Profile: "governance"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "fail" {
		t.Fatalf("expected governance failure, got %s", result.Status)
	}
	if len(result.Findings) < 4 {
		t.Fatalf("expected governance gaps, got %d", len(result.Findings))
	}
}

func TestISOReadinessIncludesRequiredCategories(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	engine := New(nil, runtime.Resolver{Providers: map[string]runtime.Provider{"local": local.Provider{Workers: 1}}}, nil)
	result, err := engine.RunCompliancePack(context.Background(), schema.ComplianceRequest{ConfigPath: filepath.Join(root, filepath.FromSlash(config.DefaultPath)), Framework: "iso42001"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Categories) != 7 {
		t.Fatalf("expected seven readiness categories, got %d", len(result.Categories))
	}
	if result.OverallReadiness <= 0 || result.OverallReadiness >= 100 {
		t.Fatalf("unexpected readiness score %d", result.OverallReadiness)
	}
	for _, category := range result.Categories {
		if category.AssessmentSummary == "" || len(category.ExpectedEvidence) == 0 || len(category.ControlReferences) == 0 {
			t.Fatalf("category %s is missing detailed readiness metadata", category.Name)
		}
	}
	names := map[string]bool{}
	for _, category := range result.Categories {
		names[category.Name] = true
	}
	for _, name := range []string{"Clause 4 - Context", "Clause 10 - Improvement"} {
		if !names[name] {
			t.Fatalf("expected non-technical readiness category %s", name)
		}
	}
}

func TestISOReadinessRejectsWeakGovernanceDocumentContent(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	weakModelCard := filepath.Join(root, ".infraseal", "governance", "model-card.md")
	body := "# Model Card\n\nThis record exists in the expected location and has enough words to avoid the short-template check. It repeats general program language about delivery readiness, operating review, team notes, and release paperwork without naming the required technical substance for this evidence item."
	if err := os.WriteFile(weakModelCard, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	engine := New(nil, runtime.Resolver{Providers: map[string]runtime.Provider{"local": local.Provider{Workers: 1}}}, nil)
	result, err := engine.RunCompliancePack(context.Background(), schema.ComplianceRequest{ConfigPath: filepath.Join(root, filepath.FromSlash(config.DefaultPath)), Framework: "iso42001"})
	if err != nil {
		t.Fatal(err)
	}
	for _, category := range result.Categories {
		for _, gap := range category.Gaps {
			if strings.Contains(gap, "Model card is missing expected content") {
				return
			}
		}
	}
	t.Fatalf("expected weak model card content to be rejected, got categories %#v", result.Categories)
}

func TestCompliancePackDoesNotExecuteScanners(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	engine := New([]scanners.Scanner{explodingScanner{}}, runtime.Resolver{Providers: map[string]runtime.Provider{"local": local.Provider{Workers: 1}}}, nil)
	if _, err := engine.RunCompliancePack(context.Background(), schema.ComplianceRequest{ConfigPath: filepath.Join(root, filepath.FromSlash(config.DefaultPath)), Framework: "iso42001"}); err != nil {
		t.Fatal(err)
	}
}

func TestCompliancePacksSupportNISTAndAIUC(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	engine := New(nil, runtime.Resolver{Providers: map[string]runtime.Provider{"local": local.Provider{Workers: 1}}}, nil)
	cases := map[string]int{
		"nist-ai-rmf": 4,
		"aiuc1":       6,
	}
	for framework, wantCategories := range cases {
		result, err := engine.RunCompliancePack(context.Background(), schema.ComplianceRequest{ConfigPath: filepath.Join(root, filepath.FromSlash(config.DefaultPath)), Framework: framework})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Categories) != wantCategories {
			t.Fatalf("%s expected %d categories, got %d", framework, wantCategories, len(result.Categories))
		}
		if len(result.References) == 0 {
			t.Fatalf("%s did not include official framework references", framework)
		}
		if result.Framework == "" || result.Disclaimer == "" {
			t.Fatalf("%s missing report identity metadata", framework)
		}
	}
}

func TestTargetedPIIScanReadsSpecificFile(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "export.txt")
	if err := os.WriteFile(target, []byte("Customer email is customer@example.com"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine := New(nil, runtime.Resolver{Providers: map[string]runtime.Provider{"local": local.Provider{Workers: 1}}}, nil)
	result, err := engine.RunScan(context.Background(), schema.ScanRequest{ConfigPath: filepath.Join(root, filepath.FromSlash(config.DefaultPath)), Profile: "quick", Checks: []string{"pii"}, Targets: []string{"export.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Category != "pii" {
		t.Fatalf("expected a targeted PII finding, got %#v", result.Findings)
	}
}

func TestTargetedScanFiltersAdapterFindings(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	engine := New([]scanners.Scanner{mixedFindingScanner{}}, runtime.Resolver{Providers: map[string]runtime.Provider{"local": local.Provider{Workers: 1}}}, nil)
	result, err := engine.RunScan(context.Background(), schema.ScanRequest{
		ConfigPath: filepath.Join(root, filepath.FromSlash(config.DefaultPath)),
		Profile:    "full",
		Checks:     []string{"pii"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Category != "pii" {
		t.Fatalf("expected only the PII adapter finding, got %#v", result.Findings)
	}
}

func TestTargetedAgentSafetyReadsSpecificFile(t *testing.T) {
	root := t.TempDir()
	if _, err := config.Initialize(root, false); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "agents", "risky-skill.yaml")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("name: export-agent\nnetwork: [\"*\"]\nrequires_human_approval: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine := New(nil, runtime.Resolver{Providers: map[string]runtime.Provider{"local": local.Provider{Workers: 1}}}, nil)
	result, err := engine.RunScan(context.Background(), schema.ScanRequest{
		ConfigPath: filepath.Join(root, filepath.FromSlash(config.DefaultPath)),
		Profile:    "agent",
		Checks:     []string{"agent-safety"},
		Targets:    []string{"agents/risky-skill.yaml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Category != "agent-safety" {
		t.Fatalf("expected targeted agent-safety finding, got %#v", result.Findings)
	}
}

type explodingScanner struct{}

func (explodingScanner) Name() string        { return "exploding" }
func (explodingScanner) DisplayName() string { return "Exploding" }
func (explodingScanner) Profiles() []string  { return []string{"full", "governance"} }
func (explodingScanner) IsAvailable(context.Context, config.Config) schema.ScannerStatus {
	return schema.ScannerStatus{Name: "exploding", Status: scanners.StatusAvailable, Categories: []string{"governance"}}
}
func (explodingScanner) Scan(context.Context, scanners.Input) (schema.ToolResult, error) {
	panic("compliance pack must not execute scanner adapters")
}

type mixedFindingScanner struct{}

func (mixedFindingScanner) Name() string        { return "mixed" }
func (mixedFindingScanner) DisplayName() string { return "Mixed" }
func (mixedFindingScanner) Profiles() []string  { return []string{"full"} }
func (mixedFindingScanner) IsAvailable(context.Context, config.Config) schema.ScannerStatus {
	return schema.ScannerStatus{Name: "mixed", Status: scanners.StatusAvailable, Categories: []string{"pii", "code-security"}}
}
func (mixedFindingScanner) Scan(context.Context, scanners.Input) (schema.ToolResult, error) {
	return schema.ToolResult{
		Name: "mixed", DisplayName: "Mixed", Status: scanners.StatusAvailable, Mode: "real",
		Findings: []schema.Finding{
			{Severity: "high", Category: "pii", Title: "PII"},
			{Severity: "high", Category: "code-security", Title: "Code"},
		},
	}, nil
}
