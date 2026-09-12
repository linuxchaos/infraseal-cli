package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
)

func TestTerraformPlanScannerFindsRuntimeAndGovernanceRisks(t *testing.T) {
	root := t.TempDir()
	plan := filepath.Join(root, "tfplan.json")
	if err := os.WriteFile(plan, []byte(`{
  "format_version": "1.2",
  "resource_changes": [
    {"address":"aws_security_group_rule.ssh","type":"aws_security_group_rule","change":{"actions":["create"],"after":{"type":"ingress","from_port":22,"to_port":22,"cidr_blocks":["0.0.0.0/0"]}}},
    {"address":"aws_db_instance.chat","type":"aws_db_instance","change":{"actions":["create"],"after":{"publicly_accessible":true,"storage_encrypted":false,"password":"demo-password"}}},
    {"address":"aws_iam_policy.agent","type":"aws_iam_policy","change":{"actions":["create"],"after":{"policy":"{\"Statement\":[{\"Action\":\"*\",\"Resource\":\"*\"}]}"} }}
  ]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := New().Scan(context.Background(), scanners.Input{
		RootDir: root,
		Config:  config.Config{Inputs: config.InputsConfig{TerraformPlanJSON: []string{"tfplan.json"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != scanners.StatusAvailable || result.Mode != "real" {
		t.Fatalf("unexpected result mode/status: %#v", result)
	}
	categories := map[string]bool{}
	for _, finding := range result.Findings {
		categories[finding.Category] = true
	}
	for _, category := range []string{"runtime-security", "data-governance", "credential-exposure", "iam-policy"} {
		if !categories[category] {
			t.Fatalf("expected category %s in findings: %#v", category, result.Findings)
		}
	}
}

func TestTerraformPlanScannerPassesCleanPlan(t *testing.T) {
	root := t.TempDir()
	plan := filepath.Join(root, "tfplan.json")
	if err := os.WriteFile(plan, []byte(`{
  "format_version": "1.2",
  "resource_changes": [
    {"address":"aws_security_group_rule.private","type":"aws_security_group_rule","change":{"actions":["create"],"after":{"type":"ingress","from_port":443,"to_port":443,"cidr_blocks":["10.0.0.0/16"]}}},
    {"address":"aws_db_instance.chat","type":"aws_db_instance","change":{"actions":["create"],"after":{"publicly_accessible":false,"storage_encrypted":true}}},
    {"address":"aws_iam_policy.agent","type":"aws_iam_policy","change":{"actions":["create"],"after":{"policy":"{\"Statement\":[{\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::ai-evidence/*\"]}]}"} }}
  ]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := New().Scan(context.Background(), scanners.Input{
		RootDir: root,
		Config:  config.Config{Inputs: config.InputsConfig{TerraformPlanJSON: []string{"tfplan.json"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != scanners.StatusAvailable || result.Mode != "real" {
		t.Fatalf("unexpected result mode/status: %#v", result)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for clean plan, got %#v", result.Findings)
	}
}
