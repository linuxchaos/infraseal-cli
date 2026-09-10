package mcpvia

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/runtime"
	"github.com/linuxchaos/infraseal-cli/internal/runtime/local"
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
	for _, name := range []string{"Risk & Impact Management", "Transparency & Training"} {
		if !names[name] {
			t.Fatalf("expected non-technical readiness category %s", name)
		}
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
