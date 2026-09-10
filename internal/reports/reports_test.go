package reports

import (
	"encoding/csv"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

func TestGenerateAndRegenerateScanReports(t *testing.T) {
	root := t.TempDir()
	result := &schema.ScanResult{SchemaVersion: "1.0", AssessmentID: "scan-test", ProjectName: "test-agent", Profile: "quick", Runtime: "local", OverallScore: 92, Status: "pass", ReportPaths: map[string]string{}, CompletedAt: time.Now().UTC()}
	service := New()
	paths, err := service.GenerateScan(root, result, []string{"json", "markdown", "html", "csv", "pdf"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for format, path := range paths {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("%s report missing or empty: %v", format, err)
		}
	}
	path, err := service.Regenerate(root, "markdown", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestScanCSVWritesOneQuotedRowPerFinding(t *testing.T) {
	root := t.TempDir()
	result := &schema.ScanResult{
		AssessmentID: "scan-csv", ProjectName: "customer-agent", Profile: "rag", Runtime: "local",
		OverallScore: 85, Status: "pass", CompletedAt: time.Now().UTC(),
		Findings: []schema.Finding{{
			ID: "grounding-1", Severity: "high", Domain: "Grounding", Category: "hallucination",
			Title: "Unsupported refund claim", Description: "Answer conflicts with policy.",
			Evidence: "Answer: 90 days\nPolicy: 14 days, conditional", Recommendation: "Correct the answer.",
			FilePath: "exports/responses.csv", Line: 2, ExecutionMode: "mocked", SourceTool: "private-backend",
		}},
	}
	paths, err := New().GenerateScan(root, result, []string{"csv"}, true)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(paths["csv"])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected header and one finding row, got %d rows", len(records))
	}
	if got := records[1][12]; got != result.Findings[0].Evidence {
		t.Fatalf("multiline evidence changed: %q", got)
	}
	for _, value := range records[1] {
		if strings.Contains(value, "private-backend") {
			t.Fatalf("backend identity leaked into CSV row: %v", records[1])
		}
	}
}

func TestJSONReportHidesBackendToolIdentity(t *testing.T) {
	root := t.TempDir()
	result := &schema.ScanResult{SchemaVersion: "1.0", AssessmentID: "scan-private", ProjectName: "test", Profile: "quick", Runtime: "local", OverallScore: 100, Status: "pass", ToolResults: []schema.ToolResult{{Name: "promptfoo", DisplayName: "Prompt & Red-Team Evaluator", Status: "available", Mode: "real", RawPath: "promptfoo-output.json"}}, ReportPaths: map[string]string{}, CompletedAt: time.Now().UTC()}
	paths, err := New().GenerateScan(root, result, []string{"json"}, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths["json"])
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(data))
	if strings.Contains(text, "promptfoo") {
		t.Fatalf("backend identity leaked into JSON: %s", text)
	}
	if !strings.Contains(text, "red-team evaluator") {
		t.Fatalf("public capability label missing: %s", text)
	}
}

func TestTargetPathsUseUniqueAssessmentID(t *testing.T) {
	completed := time.Date(2026, time.July, 2, 15, 22, 38, 0, time.UTC)
	first := targetPaths("reports", "scan", "scan-20260702T152238Z-first", completed, []string{"html"})
	second := targetPaths("reports", "scan", "scan-20260702T152238Z-second", completed, []string{"html"})

	if first["html"] == second["html"] {
		t.Fatalf("distinct assessments reused report path %q", first["html"])
	}
	if !strings.Contains(first["html"], "20260702T152238Z-first") {
		t.Fatalf("assessment ID missing from report path %q", first["html"])
	}
}
