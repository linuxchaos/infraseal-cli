package hallbayes

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
	"gopkg.in/yaml.v3"
)

type Scanner struct{}

func New() Scanner                  { return Scanner{} }
func (Scanner) Name() string        { return "hallbayes" }
func (Scanner) DisplayName() string { return "Hallbayes / Berry" }
func (Scanner) Profiles() []string  { return []string{"rag", "full"} }

func (s Scanner) IsAvailable(_ context.Context, cfg config.Config) schema.ScannerStatus {
	if config.IsDisabled(cfg, s.Name()) {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusDisabled, Detail: "disabled in configuration", Categories: categories()}
	}
	if strings.EqualFold(cfg.Scanners.HallbayesBackend, "dummy") {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusMocked, Detail: "dummy backend enabled for local evidence/answer validation", Categories: categories()}
	}
	if strings.TrimSpace(os.Getenv("HALLBAYES_BACKEND_KEY")) == "" {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: "missing_backend_key", Detail: "HALLBAYES_BACKEND_KEY is not set", InstallHint: "Configure a Berry backend or set scanners.hallbayes_backend: dummy for local fixtures", Categories: categories()}
	}
	if path, ok := scanners.CommandAvailable("berry"); ok {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusAvailable, Detail: path, Categories: categories()}
	}
	return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusMissingDependency, Detail: "berry MCP server command was not found", InstallHint: "Install Hallbayes/Berry and configure its MCP transport", Categories: categories()}
}

func (s Scanner) Scan(ctx context.Context, input scanners.Input) (schema.ToolResult, error) {
	started := time.Now().UTC()
	status := s.IsAvailable(ctx, input.Config)
	if status.Status != scanners.StatusMocked {
		mode := "missing dependency"
		if status.Status == scanners.StatusAvailable {
			mode = "disabled"
			status.Status = scanners.StatusDisabled
			status.Detail = "Berry is available, but the MCP detect_hallucination binding is not enabled in this MVP"
		}
		return scanners.NewResult(s, status.Status, mode, status.Detail, nil, started), nil
	}

	var findings []schema.Finding
	var cases []map[string]any
	for index, tc := range input.TestCases {
		if tc.Category != "grounding" && tc.Category != "hallucination" {
			continue
		}
		evidencePath := config.Resolve(input.RootDir, tc.EvidenceFile)
		evidence, err := os.ReadFile(evidencePath)
		if err != nil {
			findings = append(findings, schema.Finding{
				Severity: "medium", Category: "evidence-coverage", Title: "Grounding evidence is unavailable",
				Description: "The configured grounding case could not resolve its evidence file.", Evidence: err.Error(),
				Recommendation: "Add the evidence file and keep it under version control.", FilePath: filepath.ToSlash(tc.EvidenceFile),
			})
			continue
		}
		claimUnsupported := tc.UnsupportedClaim != "" && strings.Contains(strings.ToLower(tc.ActualOutput), strings.ToLower(tc.UnsupportedClaim)) && !strings.Contains(strings.ToLower(string(evidence)), strings.ToLower(tc.UnsupportedClaim))
		if !tc.Pass || claimUnsupported {
			source := tc.EvidenceFile
			if index < len(input.TestSources) {
				source = input.TestSources[index] + " -> " + tc.EvidenceFile
			}
			findings = append(findings, schema.Finding{
				Severity: scanners.NormalizeSeverity(tc.Severity), Category: "grounding", Title: "Unsupported answer claim detected",
				Description:    "The answer contains a claim that is not supported by the resolved evidence file.",
				Evidence:       "Answer: " + tc.ActualOutput + " | Evidence: " + strings.TrimSpace(string(evidence)),
				Recommendation: "Require cited evidence spans and fail closed when a claim cannot be resolved to approved evidence.", FilePath: filepath.ToSlash(source),
			})
		}
		cases = append(cases, map[string]any{"name": tc.Name, "answer": tc.ActualOutput, "evidence_file": tc.EvidenceFile, "resolved_evidence": strings.TrimSpace(string(evidence)), "supported": tc.Pass && !claimUnsupported})
	}
	productionCases, err := loadProductionCases(input.RootDir, input.Targets)
	if err != nil {
		findings = append(findings, schema.Finding{Severity: "medium", Category: "evidence-coverage", Title: "Production chatbot export could not be parsed", Description: err.Error(), Evidence: err.Error(), Recommendation: "Use the documented JSON, JSONL, or YAML chatbot export schema."})
	}
	for _, item := range productionCases {
		evidence, evidenceSource, readErr := resolveProductionEvidence(input.RootDir, item)
		if readErr != nil {
			findings = append(findings, schema.Finding{Severity: "medium", Category: "evidence-coverage", Title: "Production response evidence is unavailable", Description: readErr.Error(), Evidence: readErr.Error(), Recommendation: "Export the evidence inline or provide a valid evidence_file path.", FilePath: item.Source})
			continue
		}
		unsupported := item.Supported != nil && !*item.Supported
		if item.UnsupportedClaim != "" {
			unsupported = unsupported || strings.Contains(strings.ToLower(item.Answer), strings.ToLower(item.UnsupportedClaim)) && !strings.Contains(strings.ToLower(evidence), strings.ToLower(item.UnsupportedClaim))
		}
		if unsupported {
			severity := item.Severity
			if severity == "" {
				severity = "high"
			}
			title := "Unsupported production chatbot claim detected"
			if item.UnsupportedClaim != "" {
				title += ": " + item.UnsupportedClaim
			}
			findings = append(findings, schema.Finding{
				Severity: scanners.NormalizeSeverity(severity), Category: "hallucination", Title: title,
				Description:    "An exported production response is marked unsupported or contains a declared claim absent from its resolved evidence.",
				Evidence:       "Case " + item.ID + ". Answer: " + item.Answer + " | Evidence from " + evidenceSource + ": " + evidence,
				Recommendation: "Review the response, add a regression case, and use a configured semantic verifier for production gating.", FilePath: item.Source,
			})
		}
		cases = append(cases, map[string]any{"id": item.ID, "source": item.Source, "answer": item.Answer, "resolved_evidence": evidence, "evidence_source": evidenceSource, "supported": !unsupported})
	}
	result := scanners.NewResult(s, scanners.StatusMocked, "mocked", "dummy backend resolved evidence files and evaluated configured answer claims; Berry MCP was not invoked", findings, started)
	result.RawPath = scanners.WriteJSONArtifact(input, s.Name(), map[string]any{"backend": "dummy", "berry_mcp_invoked": false, "cases": cases, "findings": findings})
	return result, nil
}

func categories() []string { return []string{"grounding", "hallucination", "evidence-coverage"} }

type productionCase struct {
	ID               string `json:"id" yaml:"id"`
	Question         string `json:"question" yaml:"question"`
	Answer           string `json:"answer" yaml:"answer"`
	Evidence         string `json:"evidence" yaml:"evidence"`
	EvidenceFile     string `json:"evidence_file" yaml:"evidence_file"`
	UnsupportedClaim string `json:"unsupported_claim" yaml:"unsupported_claim"`
	Supported        *bool  `json:"supported" yaml:"supported"`
	Severity         string `json:"severity" yaml:"severity"`
	Source           string `json:"-" yaml:"-"`
	BaseDir          string `json:"-" yaml:"-"`
}

func loadProductionCases(root string, targets []string) ([]productionCase, error) {
	var cases []productionCase
	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			continue
		}
		var files []string
		if info.IsDir() {
			_ = filepath.WalkDir(target, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr == nil && !entry.IsDir() {
					files = append(files, path)
				}
				return nil
			})
		} else {
			files = []string{target}
		}
		for _, path := range files {
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".json" && ext != ".jsonl" && ext != ".yaml" && ext != ".yml" {
				continue
			}
			decoded, err := decodeProductionFile(path)
			if err != nil {
				return cases, fmt.Errorf("%s: %w", path, err)
			}
			rel, _ := filepath.Rel(root, path)
			for index := range decoded {
				if decoded[index].Answer == "" {
					continue
				}
				if decoded[index].ID == "" {
					decoded[index].ID = fmt.Sprintf("production-%d", index+1)
				}
				decoded[index].Source = filepath.ToSlash(rel)
				decoded[index].BaseDir = filepath.Dir(path)
				cases = append(cases, decoded[index])
			}
		}
	}
	return cases, nil
}

func decodeProductionFile(path string) ([]productionCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(filepath.Ext(path), ".jsonl") {
		var cases []productionCase
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "" {
				continue
			}
			var item productionCase
			if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
				return nil, err
			}
			cases = append(cases, item)
		}
		return cases, scanner.Err()
	}
	var cases []productionCase
	if json.Unmarshal(data, &cases) == nil && len(cases) > 0 {
		return cases, nil
	}
	var jsonEnvelope struct {
		Cases []productionCase `json:"cases"`
	}
	if json.Unmarshal(data, &jsonEnvelope) == nil && len(jsonEnvelope.Cases) > 0 {
		return jsonEnvelope.Cases, nil
	}
	if yaml.Unmarshal(data, &cases) == nil && len(cases) > 0 {
		return cases, nil
	}
	var yamlEnvelope struct {
		Cases []productionCase `yaml:"cases"`
	}
	if err := yaml.Unmarshal(data, &yamlEnvelope); err != nil {
		return nil, err
	}
	return yamlEnvelope.Cases, nil
}

func resolveProductionEvidence(root string, item productionCase) (string, string, error) {
	if strings.TrimSpace(item.Evidence) != "" {
		return strings.TrimSpace(item.Evidence), item.Source + "#inline-evidence", nil
	}
	if item.EvidenceFile == "" {
		return "", item.Source, fmt.Errorf("case %s has no evidence or evidence_file", item.ID)
	}
	path := item.EvidenceFile
	if !filepath.IsAbs(path) {
		rootCandidate := config.Resolve(root, path)
		if _, err := os.Stat(rootCandidate); err == nil {
			path = rootCandidate
		} else {
			path = filepath.Join(item.BaseDir, filepath.FromSlash(path))
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", path, err
	}
	rel, _ := filepath.Rel(root, path)
	return strings.TrimSpace(string(data)), filepath.ToSlash(rel), nil
}
