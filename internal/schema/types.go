package schema

import "time"

type Finding struct {
	ID              string             `json:"id" yaml:"id"`
	Severity        string             `json:"severity" yaml:"severity"`
	Domain          string             `json:"domain" yaml:"domain"`
	Category        string             `json:"category" yaml:"category"`
	Title           string             `json:"title" yaml:"title"`
	Description     string             `json:"description" yaml:"description"`
	Evidence        string             `json:"evidence" yaml:"evidence"`
	Recommendation  string             `json:"recommendation" yaml:"recommendation"`
	SourceTool      string             `json:"-" yaml:"-"`
	FilePath        string             `json:"file_path,omitempty" yaml:"file_path,omitempty"`
	Line            int                `json:"line,omitempty" yaml:"line,omitempty"`
	Benchmarks      []ControlReference `json:"benchmarks,omitempty" yaml:"benchmarks,omitempty"`
	HiddenByDefault bool               `json:"hidden_by_default" yaml:"hidden_by_default"`
	ExecutionMode   string             `json:"execution_mode" yaml:"execution_mode"`
}

type Recommendation struct {
	Priority        int      `json:"priority" yaml:"priority"`
	Title           string   `json:"title" yaml:"title"`
	WhyItMatters    string   `json:"why_it_matters" yaml:"why_it_matters"`
	SuggestedAction string   `json:"suggested_action" yaml:"suggested_action"`
	EstimatedEffort string   `json:"estimated_effort" yaml:"estimated_effort"`
	OwnerSuggestion string   `json:"owner_suggestion" yaml:"owner_suggestion"`
	RelatedFindings []string `json:"related_findings" yaml:"related_findings"`
}

type DomainScore struct {
	Name         string `json:"name" yaml:"name"`
	Score        int    `json:"score" yaml:"score"`
	Status       string `json:"status" yaml:"status"`
	Summary      string `json:"summary" yaml:"summary"`
	FindingCount int    `json:"finding_count" yaml:"finding_count"`
}

type ScannerStatus struct {
	Name        string   `json:"name" yaml:"name"`
	DisplayName string   `json:"display_name" yaml:"display_name"`
	Status      string   `json:"status" yaml:"status"`
	Detail      string   `json:"detail" yaml:"detail"`
	InstallHint string   `json:"install_hint,omitempty" yaml:"install_hint,omitempty"`
	Categories  []string `json:"categories" yaml:"categories"`
}

type ToolResult struct {
	Name           string    `json:"-" yaml:"-"`
	DisplayName    string    `json:"display_name" yaml:"display_name"`
	Status         string    `json:"status" yaml:"status"`
	Mode           string    `json:"mode" yaml:"mode"`
	Detail         string    `json:"detail,omitempty" yaml:"detail,omitempty"`
	InternalDetail string    `json:"-" yaml:"-"`
	RawPath        string    `json:"-" yaml:"-"`
	StartedAt      time.Time `json:"started_at" yaml:"started_at"`
	CompletedAt    time.Time `json:"completed_at" yaml:"completed_at"`
	Findings       []Finding `json:"findings,omitempty" yaml:"findings,omitempty"`
}

type ScanRequest struct {
	ProjectRoot        string
	ProjectName        string
	ProjectType        string
	Profile            string
	Runtime            string
	ConfigPath         string
	IncludeToolDetails bool
	Checks             []string
	Targets            []string
	Excludes           []string
	OutputFormats      []string
}

type ScanResult struct {
	SchemaVersion   string            `json:"schema_version" yaml:"schema_version"`
	AssessmentID    string            `json:"assessment_id" yaml:"assessment_id"`
	ProjectName     string            `json:"project_name" yaml:"project_name"`
	ProjectType     string            `json:"project_type" yaml:"project_type"`
	WorkloadClass   string            `json:"workload_class" yaml:"workload_class"`
	Profile         string            `json:"profile" yaml:"profile"`
	Checks          []string          `json:"checks,omitempty" yaml:"checks,omitempty"`
	Targets         []string          `json:"targets,omitempty" yaml:"targets,omitempty"`
	Runtime         string            `json:"runtime" yaml:"runtime"`
	OverallScore    int               `json:"overall_score" yaml:"overall_score"`
	ReadinessScore  int               `json:"readiness_score" yaml:"readiness_score"`
	Status          string            `json:"status" yaml:"status"`
	Domains         []DomainScore     `json:"domains" yaml:"domains"`
	Findings        []Finding         `json:"findings" yaml:"findings"`
	Recommendations []Recommendation  `json:"recommendations" yaml:"recommendations"`
	ToolResults     []ToolResult      `json:"tool_results" yaml:"tool_results"`
	EvidenceFiles   []string          `json:"evidence_files" yaml:"evidence_files"`
	ReportPaths     map[string]string `json:"report_paths" yaml:"report_paths"`
	StartedAt       time.Time         `json:"started_at" yaml:"started_at"`
	CompletedAt     time.Time         `json:"completed_at" yaml:"completed_at"`
}

type ComplianceRequest struct {
	ProjectRoot        string
	ConfigPath         string
	Framework          string
	Runtime            string
	IncludeToolDetails bool
	OutputFormats      []string
}

type ReadinessCategory struct {
	Name              string             `json:"name" yaml:"name"`
	Score             int                `json:"score" yaml:"score"`
	Status            string             `json:"status" yaml:"status"`
	AssessmentSummary string             `json:"assessment_summary" yaml:"assessment_summary"`
	Strengths         []string           `json:"strengths" yaml:"strengths"`
	Gaps              []string           `json:"gaps" yaml:"gaps"`
	ExpectedEvidence  []string           `json:"expected_evidence" yaml:"expected_evidence"`
	ControlReferences []ControlReference `json:"control_references" yaml:"control_references"`
}

type ControlReference struct {
	Framework string `json:"framework,omitempty" yaml:"framework,omitempty"`
	Reference string `json:"reference" yaml:"reference"`
	Topic     string `json:"topic" yaml:"topic"`
	URL       string `json:"url" yaml:"url"`
}

type ComplianceResult struct {
	SchemaVersion    string              `json:"schema_version" yaml:"schema_version"`
	AssessmentID     string              `json:"assessment_id" yaml:"assessment_id"`
	Framework        string              `json:"framework" yaml:"framework"`
	ProjectName      string              `json:"project_name" yaml:"project_name"`
	Runtime          string              `json:"runtime" yaml:"runtime"`
	OverallReadiness int                 `json:"overall_readiness" yaml:"overall_readiness"`
	Status           string              `json:"status" yaml:"status"`
	Categories       []ReadinessCategory `json:"categories" yaml:"categories"`
	Findings         []Finding           `json:"findings" yaml:"findings"`
	Recommendations  []Recommendation    `json:"recommendations" yaml:"recommendations"`
	EvidenceFiles    []string            `json:"evidence_files" yaml:"evidence_files"`
	ToolResults      []ToolResult        `json:"tool_results,omitempty" yaml:"tool_results,omitempty"`
	References       []ControlReference  `json:"references" yaml:"references"`
	ReportPaths      map[string]string   `json:"report_paths" yaml:"report_paths"`
	Disclaimer       string              `json:"disclaimer" yaml:"disclaimer"`
	StartedAt        time.Time           `json:"started_at" yaml:"started_at"`
	CompletedAt      time.Time           `json:"completed_at" yaml:"completed_at"`
}

type StoredResult struct {
	Kind       string            `json:"kind"`
	Scan       *ScanResult       `json:"scan,omitempty"`
	Compliance *ComplianceResult `json:"compliance,omitempty"`
}
