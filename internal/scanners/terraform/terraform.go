package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type Scanner struct{}

func New() Scanner                  { return Scanner{} }
func (Scanner) Name() string        { return "terraform-plan" }
func (Scanner) DisplayName() string { return "Terraform plan JSON" }
func (Scanner) Profiles() []string  { return []string{"governance", "full"} }

func (s Scanner) IsAvailable(_ context.Context, cfg config.Config) schema.ScannerStatus {
	if config.IsDisabled(cfg, s.Name()) {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusDisabled, Detail: "disabled in configuration", Categories: categories()}
	}
	return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusAvailable, Detail: "reads Terraform plan JSON files from configured inputs or scan targets", Categories: categories()}
}

func (s Scanner) Scan(ctx context.Context, input scanners.Input) (schema.ToolResult, error) {
	started := time.Now().UTC()
	status := s.IsAvailable(ctx, input.Config)
	if status.Status != scanners.StatusAvailable {
		return scanners.NewResult(s, status.Status, "disabled", status.Detail, nil, started), nil
	}
	files := planFiles(input)
	if len(files) == 0 {
		return scanners.NewResult(s, scanners.StatusDisabled, "disabled", "no Terraform plan JSON files were configured or selected", nil, started), nil
	}
	var findings []schema.Finding
	parsed := 0
	parseErrors := map[string]string{}
	for _, path := range files {
		select {
		case <-ctx.Done():
			return scanners.NewResult(s, scanners.StatusError, "error", ctx.Err().Error(), findings, started), nil
		default:
		}
		data, err := os.ReadFile(path)
		if err != nil {
			parseErrors[rel(input.RootDir, path)] = err.Error()
			continue
		}
		doc, err := scanners.DecodeJSON(data)
		if err != nil {
			parseErrors[rel(input.RootDir, path)] = err.Error()
			continue
		}
		root, ok := doc.(map[string]any)
		if !ok || root["resource_changes"] == nil {
			parseErrors[rel(input.RootDir, path)] = "not a Terraform plan JSON document"
			continue
		}
		parsed++
		findings = append(findings, inspectPlan(input.RootDir, path, root)...)
	}
	detail := fmt.Sprintf("evaluated %d Terraform plan JSON file(s)", parsed)
	if len(parseErrors) > 0 {
		detail += fmt.Sprintf("; %d file(s) could not be parsed as plan JSON", len(parseErrors))
	}
	resultStatus := scanners.StatusAvailable
	mode := "real"
	if parsed == 0 {
		resultStatus = scanners.StatusError
		mode = "error"
	}
	result := scanners.NewResult(s, resultStatus, mode, detail, findings, started)
	result.RawPath = scanners.WriteJSONArtifact(input, s.Name(), map[string]any{
		"plan_files": files, "parsed": parsed, "parse_errors": parseErrors, "findings": findings,
	})
	return result, nil
}

func planFiles(input scanners.Input) []string {
	seen := map[string]bool{}
	var files []string
	add := func(path string) {
		path = filepath.Clean(path)
		if path == "" || seen[path] || config.ShouldExclude(input.RootDir, path, input.Excludes) {
			return
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			seen[path] = true
			files = append(files, path)
		}
	}
	for _, path := range config.ExpandWithExcludes(input.RootDir, input.Config.Inputs.TerraformPlanJSON, input.Excludes) {
		add(path)
	}
	for _, target := range input.Targets {
		info, err := os.Stat(target)
		if err != nil || config.ShouldExclude(input.RootDir, target, input.Excludes) {
			continue
		}
		if !info.IsDir() {
			if looksLikePlanPath(target) {
				add(target)
			}
			continue
		}
		_ = filepath.WalkDir(target, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if config.ShouldExclude(input.RootDir, path, input.Excludes) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !entry.IsDir() && looksLikePlanPath(path) {
				add(path)
			}
			return nil
		})
	}
	return files
}

func looksLikePlanPath(path string) bool {
	if !strings.EqualFold(filepath.Ext(path), ".json") {
		return false
	}
	name := strings.ToLower(filepath.Base(path))
	return strings.Contains(name, "tfplan") || strings.Contains(name, "terraform") || strings.Contains(name, "plan")
}

func inspectPlan(rootDir, path string, plan map[string]any) []schema.Finding {
	changes, _ := plan["resource_changes"].([]any)
	var findings []schema.Finding
	for _, raw := range changes {
		change, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		resourceType := scanners.TextValue(change, "type")
		address := scanners.TextValue(change, "address")
		changeBlock, _ := change["change"].(map[string]any)
		if actionNoop(changeBlock["actions"]) {
			continue
		}
		after, _ := changeBlock["after"].(map[string]any)
		if len(after) == 0 {
			continue
		}
		file := rel(rootDir, path)
		findings = append(findings, networkFindings(resourceType, address, after, file)...)
		findings = append(findings, storageFindings(resourceType, address, after, file)...)
		findings = append(findings, databaseFindings(resourceType, address, after, file)...)
		findings = append(findings, iamFindings(resourceType, address, after, file)...)
		findings = append(findings, secretFindings(address, after, file)...)
	}
	return findings
}

func networkFindings(resourceType, address string, after map[string]any, file string) []schema.Finding {
	if !containsAny(resourceType, "security_group", "firewall", "network_security_rule") {
		return nil
	}
	if !isIngress(after) || !hasPublicCIDR(after) {
		return nil
	}
	severity := "high"
	if exposesSensitivePort(after) {
		severity = "critical"
	}
	return []schema.Finding{{
		Severity: severity, Category: "runtime-security",
		Title:          "Terraform plan exposes inbound access to the internet",
		Description:    "The infrastructure plan allows public ingress to an AI workload or supporting service.",
		Evidence:       fmt.Sprintf("%s allows public ingress in planned resource %s", address, resourceType),
		Recommendation: "Restrict ingress CIDRs, use private networking, and require an explicit exception record for public endpoints.",
		FilePath:       file,
	}}
}

func storageFindings(resourceType, address string, after map[string]any, file string) []schema.Finding {
	switch resourceType {
	case "aws_s3_bucket_acl":
		acl := strings.ToLower(stringValue(after["acl"]))
		if strings.Contains(acl, "public") {
			return []schema.Finding{{
				Severity: "high", Category: "data-governance",
				Title:          "Terraform plan sets public object-storage access",
				Description:    "Planned storage permissions may expose AI evidence, prompts, logs, or user data.",
				Evidence:       fmt.Sprintf("%s uses ACL %q", address, acl),
				Recommendation: "Block public access, use least-privilege access policies, and keep evaluation evidence in private storage.",
				FilePath:       file,
			}}
		}
	case "aws_s3_bucket_public_access_block":
		for _, key := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
			if value, ok := boolValue(after[key]); ok && !value {
				return []schema.Finding{{
					Severity: "medium", Category: "data-governance",
					Title:          "Terraform plan weakens storage public-access blocking",
					Description:    "A public-access-block control is disabled for planned object storage.",
					Evidence:       fmt.Sprintf("%s sets %s=false", address, key),
					Recommendation: "Enable public-access-block controls unless an approved, documented exception exists.",
					FilePath:       file,
				}}
			}
		}
	}
	return nil
}

func databaseFindings(resourceType, address string, after map[string]any, file string) []schema.Finding {
	if !containsAny(resourceType, "aws_db_instance", "aws_rds_cluster") {
		return nil
	}
	var findings []schema.Finding
	if value, ok := boolValue(after["publicly_accessible"]); ok && value {
		findings = append(findings, schema.Finding{
			Severity: "high", Category: "runtime-security",
			Title:          "Terraform plan makes a database publicly accessible",
			Description:    "A planned database for the AI workload is reachable from public networks.",
			Evidence:       address + " sets publicly_accessible=true",
			Recommendation: "Place databases in private subnets and use controlled application access paths.",
			FilePath:       file,
		})
	}
	if value, ok := boolValue(after["storage_encrypted"]); ok && !value {
		findings = append(findings, schema.Finding{
			Severity: "high", Category: "data-governance",
			Title:          "Terraform plan disables database storage encryption",
			Description:    "A planned database stores AI workload data without storage encryption.",
			Evidence:       address + " sets storage_encrypted=false",
			Recommendation: "Enable storage encryption and document key ownership for AI workload data stores.",
			FilePath:       file,
		})
	}
	return findings
}

func iamFindings(resourceType, address string, after map[string]any, file string) []schema.Finding {
	if !containsAny(resourceType, "iam_policy", "iam_role_policy", "iam_user_policy") {
		return nil
	}
	policies := policyValues(after)
	for _, policy := range policies {
		if wildcardPolicy.MatchString(policy) {
			return []schema.Finding{{
				Severity: "high", Category: "iam-policy",
				Title:          "Terraform plan includes wildcard IAM policy access",
				Description:    "The planned policy may allow broad tool, data, or infrastructure actions from an AI workflow.",
				Evidence:       address + " contains wildcard Action or Resource policy terms",
				Recommendation: "Replace wildcard actions/resources with the narrow permissions required by the agent or workload.",
				FilePath:       file,
			}}
		}
	}
	return nil
}

func secretFindings(address string, after map[string]any, file string) []schema.Finding {
	var findings []schema.Finding
	walk(after, nil, func(path []string, value any) {
		key := strings.ToLower(strings.Join(path, "."))
		if !secretKey.MatchString(key) {
			return
		}
		text := strings.TrimSpace(stringValue(value))
		if text == "" || strings.Contains(strings.ToLower(text), "sensitive") || strings.Contains(strings.ToLower(text), "known after apply") {
			return
		}
		findings = append(findings, schema.Finding{
			Severity: "high", Category: "credential-exposure",
			Title:          "Terraform plan contains a secret-like literal value",
			Description:    "A planned resource includes a secret-like field value in plan output.",
			Evidence:       fmt.Sprintf("%s has literal value at %s", address, strings.Join(path, ".")),
			Recommendation: "Move secrets to a managed secret store, mark Terraform variables sensitive, and keep plan artifacts out of public logs.",
			FilePath:       file,
		})
	})
	return findings
}

func actionNoop(value any) bool {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return false
	}
	for _, item := range items {
		if strings.ToLower(stringValue(item)) != "no-op" {
			return false
		}
	}
	return true
}

func isIngress(values map[string]any) bool {
	direction := strings.ToLower(stringValue(values["direction"]))
	if direction != "" && !strings.Contains(direction, "ingress") && !strings.Contains(direction, "inbound") {
		return false
	}
	kind := strings.ToLower(stringValue(values["type"]))
	if kind != "" && !strings.Contains(kind, "ingress") && !strings.Contains(kind, "inbound") {
		return false
	}
	access := strings.ToLower(stringValue(values["access"]))
	return access == "" || access == "allow"
}

func hasPublicCIDR(values map[string]any) bool {
	for _, key := range []string{"cidr_blocks", "ipv6_cidr_blocks", "source_address_prefix", "source_address_prefixes"} {
		if containsPublicValue(values[key]) {
			return true
		}
	}
	return false
}

func containsPublicValue(value any) bool {
	switch typed := value.(type) {
	case string:
		v := strings.ToLower(strings.TrimSpace(typed))
		return v == "0.0.0.0/0" || v == "::/0" || v == "*" || v == "internet"
	case []any:
		for _, item := range typed {
			if containsPublicValue(item) {
				return true
			}
		}
	}
	return false
}

func exposesSensitivePort(values map[string]any) bool {
	from := intValue(values["from_port"])
	to := intValue(values["to_port"])
	if from == 0 && to == 0 {
		return true
	}
	for _, port := range []int{22, 3389, 5432, 3306, 6379, 9200, 27017} {
		if from <= port && (to == 0 || port <= to) {
			return true
		}
	}
	destination := strings.ToLower(stringValue(values["destination_port_range"]))
	return destination == "*" || strings.Contains(destination, "22") || strings.Contains(destination, "3389")
}

func policyValues(values map[string]any) []string {
	var policies []string
	walk(values, nil, func(path []string, value any) {
		if len(path) == 0 {
			return
		}
		key := strings.ToLower(path[len(path)-1])
		if strings.Contains(key, "policy") {
			if text := stringValue(value); text != "" {
				policies = append(policies, text)
			}
		}
	})
	return policies
}

func walk(value any, path []string, visit func([]string, any)) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			walk(item, append(append([]string{}, path...), key), visit)
		}
	case []any:
		for index, item := range typed {
			walk(item, append(append([]string{}, path...), fmt.Sprintf("%d", index)), visit)
		}
	default:
		visit(path, value)
	}
}

func boolValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		if strings.EqualFold(typed, "true") {
			return true, true
		}
		if strings.EqualFold(typed, "false") {
			return false, true
		}
	}
	return false, false
}

func intValue(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case string:
		var number int
		_, _ = fmt.Sscanf(typed, "%d", &number)
		return number
	default:
		return scanners.IntValue(map[string]any{"value": value}, "value")
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case float64:
		return fmt.Sprintf("%.0f", typed)
	case bool:
		return fmt.Sprintf("%t", typed)
	default:
		return ""
	}
}

func rel(root, path string) string {
	value, err := filepath.Rel(root, path)
	if err != nil {
		value = path
	}
	return filepath.ToSlash(value)
}

func containsAny(value string, needles ...string) bool {
	value = strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

var (
	secretKey      = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|private[_-]?key|client[_-]?secret)$`)
	wildcardPolicy = regexp.MustCompile(`(?i)"(action|resource)"\s*:\s*(("\*")|\[\s*"\*"\s*\])`)
)

func categories() []string {
	return []string{"runtime-security", "infrastructure-security", "data-governance", "iam-policy", "credential-exposure", "code-security"}
}
