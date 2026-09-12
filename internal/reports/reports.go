package reports

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) GenerateScan(root string, result *schema.ScanResult, formats []string, includeToolDetails bool) (map[string]string, error) {
	dir := filepath.Join(root, ".infraseal", "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	paths := targetPaths(dir, "scan", result.AssessmentID, result.CompletedAt, formats)
	result.ReportPaths = paths
	for format, path := range paths {
		var data []byte
		var err error
		switch format {
		case "json":
			data, err = json.MarshalIndent(result, "", "  ")
		case "markdown", "md":
			data = []byte(scanMarkdown(*result, includeToolDetails))
		case "html":
			data = []byte(scanHTML(*result, includeToolDetails))
		case "csv":
			data, err = scanCSV(*result)
		case "pdf":
			err = writePDF(path, scanLines(*result, includeToolDetails))
			if err == nil {
				continue
			}
		default:
			err = fmt.Errorf("unsupported report format %q", format)
		}
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return nil, err
		}
	}
	if err := writeLatest(dir, "latest.json", schema.StoredResult{Kind: "scan", Scan: result}); err != nil {
		return nil, err
	}
	if err := writeLatest(dir, "latest-scan.json", schema.StoredResult{Kind: "scan", Scan: result}); err != nil {
		return nil, err
	}
	return paths, nil
}

func (s *Service) GenerateCompliance(root string, result *schema.ComplianceResult, formats []string, includeToolDetails bool) (map[string]string, error) {
	dir := filepath.Join(root, ".infraseal", "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	paths := targetPaths(dir, compliancePrefix(result.Framework), result.AssessmentID, result.CompletedAt, formats)
	result.ReportPaths = paths
	for format, path := range paths {
		var data []byte
		var err error
		switch format {
		case "json":
			data, err = json.MarshalIndent(result, "", "  ")
		case "markdown", "md":
			data = []byte(complianceMarkdown(*result, includeToolDetails))
		case "html":
			data = []byte(complianceHTML(*result, includeToolDetails))
		case "csv":
			data, err = complianceCSV(*result)
		case "pdf":
			err = writePDF(path, complianceLines(*result, includeToolDetails))
			if err == nil {
				continue
			}
		default:
			err = fmt.Errorf("unsupported report format %q", format)
		}
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return nil, err
		}
	}
	if err := writeLatest(dir, "latest.json", schema.StoredResult{Kind: "compliance", Compliance: result}); err != nil {
		return nil, err
	}
	if err := writeLatest(dir, "latest-compliance.json", schema.StoredResult{Kind: "compliance", Compliance: result}); err != nil {
		return nil, err
	}
	return paths, nil
}

func (s *Service) Regenerate(root, format string, includeToolDetails bool) (string, error) {
	path := filepath.Join(root, ".infraseal", "reports", "latest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read latest result: %w", err)
	}
	var stored schema.StoredResult
	if err := json.Unmarshal(data, &stored); err != nil {
		return "", err
	}
	if stored.Kind == "scan" && stored.Scan != nil {
		paths, err := s.GenerateScan(root, stored.Scan, []string{format}, includeToolDetails)
		return paths[normalizeFormat(format)], err
	}
	if stored.Kind == "compliance" && stored.Compliance != nil {
		paths, err := s.GenerateCompliance(root, stored.Compliance, []string{format}, includeToolDetails)
		return paths[normalizeFormat(format)], err
	}
	return "", errors.New("latest result is not a recognized InfraSeal assessment")
}

func targetPaths(dir, prefix, assessmentID string, completed time.Time, formats []string) map[string]string {
	stamp := strings.TrimPrefix(assessmentID, prefix+"-")
	if stamp == "" {
		stamp = completed.UTC().Format("20060102T150405Z")
	}
	stamp = regexp.MustCompile(`[^a-zA-Z0-9_-]+`).ReplaceAllString(stamp, "-")
	paths := map[string]string{}
	for _, raw := range formats {
		format := normalizeFormat(raw)
		ext := format
		if format == "markdown" {
			ext = "md"
		}
		paths[format] = filepath.Join(dir, prefix+"-"+stamp+"."+ext)
	}
	return paths
}

func scanCSV(result schema.ScanResult) ([]byte, error) {
	header := []string{
		"assessment_id", "project_name", "profile", "runtime", "overall_score", "decision",
		"finding_id", "severity", "domain", "category", "title", "description", "evidence",
		"recommendation", "benchmarks", "file_path", "line", "execution_mode",
	}
	prefix := []string{
		result.AssessmentID, result.ProjectName, result.Profile, result.Runtime,
		fmt.Sprintf("%d", result.OverallScore), strings.ToUpper(result.Status),
	}
	return findingsCSV(header, prefix, result.Findings)
}

func complianceCSV(result schema.ComplianceResult) ([]byte, error) {
	header := []string{
		"assessment_id", "project_name", "framework", "runtime", "overall_readiness", "status",
		"finding_id", "severity", "domain", "category", "title", "description", "evidence",
		"recommendation", "benchmarks", "file_path", "line", "execution_mode",
	}
	prefix := []string{
		result.AssessmentID, result.ProjectName, result.Framework, result.Runtime,
		fmt.Sprintf("%d", result.OverallReadiness), strings.ToUpper(result.Status),
	}
	return findingsCSV(header, prefix, result.Findings)
}

func findingsCSV(header, prefix []string, findings []schema.Finding) ([]byte, error) {
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	if err := writer.Write(header); err != nil {
		return nil, err
	}
	for _, finding := range findings {
		row := append(append([]string{}, prefix...),
			finding.ID,
			strings.ToUpper(finding.Severity),
			finding.Domain,
			finding.Category,
			finding.Title,
			finding.Description,
			finding.Evidence,
			finding.Recommendation,
			benchmarkCell(finding.Benchmarks),
			finding.FilePath,
			fmt.Sprintf("%d", finding.Line),
			finding.ExecutionMode,
		)
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func normalizeFormat(format string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "md" {
		return "markdown"
	}
	return format
}

func compliancePrefix(framework string) string {
	value := strings.ToLower(framework)
	switch {
	case strings.Contains(value, "nist"):
		return "nist-ai-rmf"
	case strings.Contains(value, "aiuc"):
		return "aiuc1"
	default:
		return "iso42001"
	}
}

func writeLatest(dir, name string, stored schema.StoredResult) error {
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), data, 0o644)
}

func scanMarkdown(result schema.ScanResult, includeTools bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# InfraSeal AI Assurance Report\n\n")
	fmt.Fprintf(&b, "- Project: **%s**\n- Workload: **%s**\n- Profile: **%s**\n- Runtime: **%s**\n- Trust score: **%d/100**\n- Decision: **%s**\n- Timestamp: **%s**\n\n", result.ProjectName, result.WorkloadClass, result.Profile, result.Runtime, result.OverallScore, strings.ToUpper(result.Status), result.CompletedAt.Format(time.RFC3339))
	if len(result.Checks) > 0 {
		fmt.Fprintf(&b, "- Selected checks: **%s**\n", strings.Join(result.Checks, ", "))
	}
	if len(result.Targets) > 0 {
		fmt.Fprintf(&b, "- Selected targets: **%s**\n", strings.Join(result.Targets, ", "))
	}
	b.WriteString("\n")
	b.WriteString("## Executive Summary\n\n")
	fmt.Fprintf(&b, "MCPvia evaluated %d assurance domain(s), correlated %d finding(s), and produced %d prioritized recommendation(s).\n\n", len(result.Domains), len(result.Findings), len(result.Recommendations))
	b.WriteString("## Domains\n\n")
	for _, domain := range result.Domains {
		fmt.Fprintf(&b, "- **%s:** %d/100 (%s) - %s\n", domain.Name, domain.Score, domain.Status, domain.Summary)
	}
	b.WriteString("\n## Findings\n\n")
	writeMarkdownFindings(&b, result.Findings)
	b.WriteString("\n## Recommendations\n\n")
	writeMarkdownRecommendations(&b, result.Recommendations)
	b.WriteString("\n## Evidence Used\n\n")
	for _, path := range result.EvidenceFiles {
		fmt.Fprintf(&b, "- `%s`\n", path)
	}
	if includeTools {
		writeMarkdownToolsWithTitle(&b, result.ToolResults, "Evaluation Provenance", "")
	}
	b.WriteString("\n---\nInfraSeal CLI report. Powered by MCPvia.\n")
	return b.String()
}

func complianceMarkdown(result schema.ComplianceResult, includeTools bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# InfraSeal %s Report\n\n", result.Framework)
	fmt.Fprintf(&b, "- Project: **%s**\n- Overall readiness: **%d%%**\n- Status: **%s**\n- Runtime: **%s**\n- Timestamp: **%s**\n\n", result.ProjectName, result.OverallReadiness, strings.ToUpper(result.Status), result.Runtime, result.CompletedAt.Format(time.RFC3339))
	b.WriteString("## Readiness Categories\n\n")
	for _, category := range result.Categories {
		fmt.Fprintf(&b, "### %s - %d%% %s\n\n", category.Name, category.Score, category.Status)
		fmt.Fprintf(&b, "%s\n\n", category.AssessmentSummary)
		for _, gap := range category.Gaps {
			fmt.Fprintf(&b, "- Gap: %s\n", gap)
		}
		for _, strength := range category.Strengths {
			fmt.Fprintf(&b, "- Strength: %s\n", strength)
		}
		if len(category.Controls) > 0 {
			b.WriteString("\n**Control assessment**\n\n")
			b.WriteString("| Control | Applicability | Status | Review method | Evidence checked | Gaps / next steps |\n|---|---|---|---|---|---|\n")
			for _, control := range category.Controls {
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", cell(control.Name), cell(control.Applicability), cell(control.Status), cell(control.ReviewMethod), cell(strings.Join(control.Evidence, "; ")), cell(controlGapsAndSteps(control)))
			}
		}
		b.WriteString("\n**Expected evidence**\n\n")
		for _, evidence := range category.ExpectedEvidence {
			fmt.Fprintf(&b, "- %s\n", evidence)
		}
		b.WriteString("\n**Benchmark mapping**\n\n")
		for _, reference := range category.ControlReferences {
			fmt.Fprintf(&b, "- [%s](%s): %s\n", referenceLabel(reference), reference.URL, reference.Topic)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Governance Gaps\n\n")
	writeMarkdownFindings(&b, result.Findings)
	b.WriteString("\n## Top Recommendations\n\n")
	writeMarkdownRecommendations(&b, result.Recommendations)
	b.WriteString("\n## Evidence Used\n\n")
	for _, path := range result.EvidenceFiles {
		fmt.Fprintf(&b, "- `%s`\n", path)
	}
	if includeTools {
		writeMarkdownToolsWithTitle(&b, result.ToolResults, "Readiness Evidence Provenance", "This readiness command did not execute scanner adapters. Entries below were loaded from the latest technical scan.")
	}
	b.WriteString("\n## Official References\n\n")
	for _, reference := range result.References {
		fmt.Fprintf(&b, "- [%s](%s): %s\n", referenceLabel(reference), reference.URL, reference.Topic)
	}
	fmt.Fprintf(&b, "\n## Important Limitation\n\n%s\n\n---\nInfraSeal CLI report. Powered by MCPvia.\n", result.Disclaimer)
	return b.String()
}

func writeMarkdownFindings(b *strings.Builder, findings []schema.Finding) {
	if len(findings) == 0 {
		b.WriteString("No open findings were detected.\n")
		return
	}
	b.WriteString("| Severity | Domain | Finding | Evidence | Benchmarks | Recommendation |\n|---|---|---|---|---|---|\n")
	for _, finding := range findings {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s |\n", strings.ToUpper(finding.Severity), cell(finding.Domain), cell(finding.Title), cell(finding.Evidence), cell(benchmarkCell(finding.Benchmarks)), cell(finding.Recommendation))
	}
}

func writeMarkdownRecommendations(b *strings.Builder, items []schema.Recommendation) {
	for _, item := range items {
		fmt.Fprintf(b, "%d. **%s** (%s, owner: %s)\n   - Why: %s\n   - Action: %s\n", item.Priority, item.Title, item.EstimatedEffort, item.OwnerSuggestion, item.WhyItMatters, item.SuggestedAction)
	}
}

func writeMarkdownToolsWithTitle(b *strings.Builder, tools []schema.ToolResult, title, note string) {
	b.WriteString("\n## " + title + "\n\n")
	if strings.TrimSpace(note) != "" {
		fmt.Fprintf(b, "%s\n\n", note)
	}
	b.WriteString("| InfraSeal capability | Status | Mode | Detail |\n|---|---|---|---|\n")
	for _, tool := range tools {
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", cell(tool.DisplayName), tool.Status, tool.Mode, cell(tool.Detail))
	}
}

func scanHTML(result schema.ScanResult, includeTools bool) string {
	return htmlDocument("InfraSeal AI Assurance Report", markdownToHTML(scanMarkdown(result, includeTools)))
}
func complianceHTML(result schema.ComplianceResult, includeTools bool) string {
	return htmlDocument("InfraSeal "+result.Framework, markdownToHTML(complianceMarkdown(result, includeTools)))
}

func htmlDocument(title, body string) string {
	return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>" + html.EscapeString(title) + "</title><style>body{font:15px/1.55 Arial,sans-serif;margin:0;background:#071016;color:#edf6fb}main{max-width:1050px;margin:auto;padding:40px}h1,h2,h3{color:#43fbff}table{width:100%;border-collapse:collapse;margin:16px 0}th,td{border:1px solid #35505f;padding:10px;text-align:left;vertical-align:top}th{background:#10222d}code{color:#8efdff}a{color:#69fcff}.note{padding:14px;border-left:4px solid #f715ab;background:#101923}</style></head><body><main>" + body + "</main></body></html>"
}

func markdownToHTML(markdown string) string {
	var b strings.Builder
	inTable := false
	for _, raw := range strings.Split(markdown, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "|---") {
			continue
		}
		if strings.HasPrefix(line, "|") && strings.HasSuffix(line, "|") {
			cells := strings.Split(strings.Trim(line, "|"), "|")
			if !inTable {
				b.WriteString("<table>")
				inTable = true
			}
			b.WriteString("<tr>")
			for _, value := range cells {
				b.WriteString("<td>" + inlineHTML(strings.TrimSpace(value)) + "</td>")
			}
			b.WriteString("</tr>")
			continue
		}
		if inTable {
			b.WriteString("</table>")
			inTable = false
		}
		switch {
		case strings.HasPrefix(line, "# "):
			b.WriteString("<h1>" + inlineHTML(strings.TrimPrefix(line, "# ")) + "</h1>")
		case strings.HasPrefix(line, "## "):
			b.WriteString("<h2>" + inlineHTML(strings.TrimPrefix(line, "## ")) + "</h2>")
		case strings.HasPrefix(line, "### "):
			b.WriteString("<h3>" + inlineHTML(strings.TrimPrefix(line, "### ")) + "</h3>")
		case strings.HasPrefix(line, "- "):
			b.WriteString("<p>• " + inlineHTML(strings.TrimPrefix(line, "- ")) + "</p>")
		case line == "" || line == "---":
		default:
			b.WriteString("<p>" + inlineHTML(line) + "</p>")
		}
	}
	if inTable {
		b.WriteString("</table>")
	}
	return b.String()
}

var markdownLink = regexp.MustCompile(`\[([^\]]+)\]\((https://[^)]+)\)`)

func inlineHTML(value string) string {
	var b strings.Builder
	last := 0
	for _, match := range markdownLink.FindAllStringSubmatchIndex(value, -1) {
		b.WriteString(cleanInline(value[last:match[0]]))
		label := html.EscapeString(value[match[2]:match[3]])
		url := html.EscapeString(value[match[4]:match[5]])
		b.WriteString(`<a href="` + url + `" target="_blank" rel="noreferrer">` + label + `</a>`)
		last = match[1]
	}
	b.WriteString(cleanInline(value[last:]))
	return b.String()
}

func cleanInline(value string) string {
	value = html.EscapeString(value)
	value = strings.ReplaceAll(value, "**", "")
	value = strings.ReplaceAll(value, "`", "")
	return value
}

func benchmarkCell(refs []schema.ControlReference) string {
	if len(refs) == 0 {
		return ""
	}
	var values []string
	for _, ref := range refs {
		values = append(values, referenceLabel(ref))
	}
	return strings.Join(values, "; ")
}

func referenceLabel(ref schema.ControlReference) string {
	label := strings.TrimSpace(ref.Framework)
	if label == "" {
		return strings.TrimSpace(ref.Reference)
	}
	if ref.Reference != "" {
		label += " " + strings.TrimSpace(ref.Reference)
	}
	return label
}

func controlGapsAndSteps(control schema.ControlAssessment) string {
	var values []string
	values = append(values, control.Gaps...)
	values = append(values, control.NextSteps...)
	return strings.Join(values, "; ")
}

func scanLines(result schema.ScanResult, includeTools bool) []string {
	lines := []string{"InfraSeal AI Assurance Report", "Project: " + result.ProjectName, fmt.Sprintf("Trust score: %d/100", result.OverallScore), "Decision: " + strings.ToUpper(result.Status), "Profile: " + result.Profile, "Runtime: " + result.Runtime, "", "Domains:"}
	for _, domain := range result.Domains {
		lines = append(lines, fmt.Sprintf("- %s: %d/100 (%s)", domain.Name, domain.Score, domain.Status))
	}
	lines = append(lines, "", "Findings:")
	for _, finding := range result.Findings {
		lines = append(lines, fmt.Sprintf("- [%s] %s: %s", strings.ToUpper(finding.Severity), finding.Domain, finding.Title), "  Evidence: "+finding.Evidence, "  Action: "+finding.Recommendation)
		if refs := benchmarkCell(finding.Benchmarks); refs != "" {
			lines = append(lines, "  Benchmarks: "+refs)
		}
	}
	lines = append(lines, "", "Recommendations:")
	for _, item := range result.Recommendations {
		lines = append(lines, fmt.Sprintf("%d. %s (%s)", item.Priority, item.Title, item.EstimatedEffort), "   "+item.SuggestedAction)
	}
	if includeTools {
		for _, tool := range result.ToolResults {
			lines = append(lines, fmt.Sprintf("Capability: %s - %s / %s", tool.DisplayName, tool.Status, tool.Mode))
		}
	}
	lines = append(lines, "", "InfraSeal CLI report. Powered by MCPvia.")
	return lines
}

func complianceLines(result schema.ComplianceResult, includeTools bool) []string {
	lines := []string{"InfraSeal " + result.Framework, "Project: " + result.ProjectName, fmt.Sprintf("Overall readiness: %d%%", result.OverallReadiness), "Status: " + strings.ToUpper(result.Status), ""}
	for _, category := range result.Categories {
		lines = append(lines, fmt.Sprintf("%s: %d%% %s", category.Name, category.Score, category.Status))
		lines = append(lines, "  Assessment: "+category.AssessmentSummary)
		for _, gap := range category.Gaps {
			lines = append(lines, "  Gap: "+gap)
		}
		for _, control := range category.Controls {
			lines = append(lines, fmt.Sprintf("  Control: %s [%s, %s]", control.Name, control.Applicability, control.Status))
			if control.Summary != "" {
				lines = append(lines, "    "+control.Summary)
			}
			if len(control.Evidence) > 0 {
				lines = append(lines, "    Evidence: "+strings.Join(control.Evidence, "; "))
			}
			if text := controlGapsAndSteps(control); text != "" {
				lines = append(lines, "    Gaps/next: "+text)
			}
		}
		for _, evidence := range category.ExpectedEvidence {
			lines = append(lines, "  Expected evidence: "+evidence)
		}
		for _, reference := range category.ControlReferences {
			lines = append(lines, "  Reference: "+referenceLabel(reference)+" - "+reference.URL)
		}
	}
	lines = append(lines, "", "Top Recommendations:")
	for _, item := range result.Recommendations {
		lines = append(lines, fmt.Sprintf("%d. %s (%s)", item.Priority, item.Title, item.EstimatedEffort))
	}
	if includeTools {
		for _, tool := range result.ToolResults {
			lines = append(lines, fmt.Sprintf("Capability: %s - %s / %s", tool.DisplayName, tool.Status, tool.Mode))
		}
	}
	lines = append(lines, "", "Official references:")
	for _, reference := range result.References {
		lines = append(lines, referenceLabel(reference)+": "+reference.URL)
	}
	lines = append(lines, "", result.Disclaimer, "", "InfraSeal CLI report. Powered by MCPvia.")
	return lines
}

func cell(value string) string {
	value = strings.ReplaceAll(value, "|", "/")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func SortedPaths(paths map[string]string) []string {
	keys := make([]string, 0, len(paths))
	for key := range paths {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+": "+paths[key])
	}
	return values
}
