package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type Scanner struct{}

func New() Scanner                  { return Scanner{} }
func (Scanner) Name() string        { return "govulncheck" }
func (Scanner) DisplayName() string { return "govulncheck" }
func (Scanner) Profiles() []string  { return []string{"full"} }

func (s Scanner) IsAvailable(_ context.Context, cfg config.Config) schema.ScannerStatus {
	if config.IsDisabled(cfg, s.Name()) {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusDisabled, Detail: "disabled in configuration", Categories: categories()}
	}
	if path, ok := scanners.CommandAvailable("govulncheck"); ok {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusAvailable, Detail: path, Categories: categories()}
	}
	return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusMissingDependency, Detail: "govulncheck was not found on PATH", InstallHint: "go install golang.org/x/vuln/cmd/govulncheck@latest", Categories: categories()}
}

func (s Scanner) Scan(ctx context.Context, input scanners.Input) (schema.ToolResult, error) {
	started := time.Now().UTC()
	status := s.IsAvailable(ctx, input.Config)
	if status.Status != scanners.StatusAvailable {
		return scanners.NewResult(s, status.Status, "missing dependency", status.Detail, nil, started), nil
	}
	if _, err := os.Stat(filepath.Join(input.RootDir, "go.mod")); err != nil {
		return scanners.NewResult(s, scanners.StatusDisabled, "disabled", "no go.mod found in workload root", nil, started), nil
	}
	args := []string{"-json"}
	args = append(args, scanners.GoPackagePatterns(input.RootDir, input.Targets, input.Excludes)...)
	output, _, err := scanners.RunCommand(ctx, input.RootDir, "govulncheck", args...)
	raw := scanners.WriteArtifact(input, s.Name(), "output.jsonl", output)
	findings := parse(output)
	statusValue := scanners.StatusAvailable
	detail := "Go dependency vulnerability evaluation completed"
	if err != nil && len(findings) == 0 {
		statusValue = scanners.StatusError
		detail = err.Error()
	}
	result := scanners.NewResult(s, statusValue, "real", detail, findings, started)
	result.RawPath = raw
	return result, nil
}

func parse(data []byte) []schema.Finding {
	var findings []schema.Finding
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	for {
		var message map[string]any
		if err := decoder.Decode(&message); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
		finding, ok := message["finding"].(map[string]any)
		if !ok {
			continue
		}
		var trace []string
		hasSymbol := false
		filePath := ""
		line := 0
		if frames, ok := finding["trace"].([]any); ok {
			for _, frame := range frames {
				if item, ok := frame.(map[string]any); ok {
					if scanners.TextValue(item, "function") != "" {
						hasSymbol = true
					}
					if position, ok := item["position"].(map[string]any); ok {
						if filename := scanners.TextValue(position, "filename"); filename != "" {
							filePath = filename
						}
						if value := scanners.IntValue(position, "line"); value != 0 {
							line = value
						}
					}
					trace = append(trace, strings.TrimSpace(scanners.TextValue(item, "module")+" "+scanners.TextValue(item, "package")+" "+scanners.TextValue(item, "function")))
				}
			}
		}
		if !hasSymbol {
			continue
		}
		findings = append(findings, schema.Finding{
			Severity: "high", Category: "dependency-vulnerability", Title: "Reachable Go vulnerability " + scanners.TextValue(finding, "osv"),
			Description: "A reachable vulnerability is present in the Go dependency graph.", Evidence: strings.Join(trace, " -> "),
			Recommendation: "Upgrade the affected module to a fixed version and rerun the full profile.", FilePath: filePath, Line: line,
		})
	}
	return findings
}

func categories() []string { return []string{"dependency-vulnerability", "code-security"} }
