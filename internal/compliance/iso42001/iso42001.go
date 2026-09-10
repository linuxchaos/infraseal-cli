package iso42001

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/compliance/benchmarks"
	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/recommendations"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

const Disclaimer = "InfraSeal helps organizations prepare for and maintain AI governance programs aligned with ISO/IEC 42001. This readiness assessment is not certification and does not establish compliance."
const standardURL = "https://www.iso.org/standard/42001"
const explainerURL = "https://www.iso.org/home/insights-news/resources/iso-42001-explained-what-it-is.html"
const nistCoreURL = "https://airc.nist.gov/airmf-resources/airmf/5-sec-core/"
const nistPlaybookURL = "https://airc.nist.gov/airmf-resources/playbook/"
const aiucURL = "https://aiuc.com/research/introducing-aiuc-1"

type Input struct {
	AssessmentID string
	RootDir      string
	Runtime      string
	Config       config.Config
	TestCases    []config.TestCase
	TestSources  []string
	Evidence     []string
	ToolResults  []schema.ToolResult
	StartedAt    time.Time
}

func Assess(input Input) schema.ComplianceResult {
	return AssessFramework(input, "iso42001")
}

func AssessFramework(input Input, framework string) schema.ComplianceResult {
	framework = normalizeFramework(framework)
	var findings []schema.Finding
	var categories []schema.ReadinessCategory
	var weights map[string]int
	var references []schema.ControlReference
	title := "ISO/IEC 42001 Readiness"
	disclaimer := Disclaimer
	switch framework {
	case "nist-ai-rmf":
		title = "NIST AI RMF Readiness"
		disclaimer = "InfraSeal maps local evidence and evaluator findings to NIST AI RMF functions for readiness planning. This is not legal advice or a formal assurance attestation."
		categories = []schema.ReadinessCategory{
			nistGovern(input, &findings),
			nistMap(input, &findings),
			nistMeasure(input, &findings),
			nistManage(input, &findings),
		}
		weights = map[string]int{"GOVERN": 25, "MAP": 20, "MEASURE": 35, "MANAGE": 20}
		references = []schema.ControlReference{
			{Framework: "NIST AI RMF", Reference: "AI RMF Core", Topic: "Govern, Map, Measure, and Manage functions", URL: nistCoreURL},
			{Framework: "NIST AI RMF", Reference: "AI RMF Playbook", Topic: "Suggested actions aligned to AI RMF outcomes", URL: nistPlaybookURL},
		}
	case "aiuc1":
		title = "AIUC-1 Principles Readiness"
		disclaimer = "InfraSeal maps local evidence and evaluator findings to public AIUC-1 principle areas for internal readiness planning. This is not AIUC certification."
		categories = []schema.ReadinessCategory{
			aiucDataPrivacy(input, &findings),
			aiucSecurity(input, &findings),
			aiucSafety(input, &findings),
			aiucReliability(input, &findings),
			aiucAccountability(input, &findings),
			aiucSociety(input, &findings),
		}
		weights = map[string]int{"Data & Privacy": 20, "Security": 25, "Safety": 15, "Reliability": 20, "Accountability": 15, "Society": 5}
		references = []schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Public principles", Topic: "Data & Privacy, Security, Safety, Reliability, Accountability, and Society", URL: aiucURL},
		}
	default:
		categories = []schema.ReadinessCategory{
			technical(input, &findings),
			governance(input, &findings),
			riskImpactManagement(input, &findings),
			humanOversight(input, &findings),
			operationalMonitoring(input, &findings),
			evidenceReadiness(input, &findings),
			transparencyTraining(input, &findings),
		}
		weights = map[string]int{"Technical Controls": 20, "Governance": 20, "Risk & Impact Management": 15, "Human Oversight": 15, "Operational Monitoring": 15, "Evidence Readiness": 10, "Transparency & Training": 5}
		references = []schema.ControlReference{
			{Framework: "ISO/IEC 42001", Reference: "ISO/IEC 42001:2023", Topic: "Official standard page and purchasing access", URL: standardURL},
			{Framework: "ISO/IEC 42001", Reference: "ISO 42001 explained", Topic: "Official overview of AI management system requirements", URL: explainerURL},
		}
	}
	findings = append(findings, toolFindings(input.ToolResults)...)
	findings = benchmarks.Annotate(findings)
	overall := 0
	for _, category := range categories {
		overall += category.Score * weights[category.Name]
	}
	overall /= 100
	status := "needs-attention"
	if overall >= input.Config.Settings.MinimumReadinessScore && !hasBlockingFinding(findings) {
		status = "ready"
	}
	assignIDs(findings, framework)
	return schema.ComplianceResult{
		SchemaVersion: "1.0", AssessmentID: input.AssessmentID, Framework: title,
		ProjectName: input.Config.Project.Name, Runtime: input.Runtime, OverallReadiness: overall, Status: status,
		Categories: categories, Findings: findings, Recommendations: recommendations.Build(findings),
		EvidenceFiles: evidenceFiles(input),
		ToolResults:   input.ToolResults,
		References:    references,
		ReportPaths:   map[string]string{}, Disclaimer: disclaimer,
		StartedAt: input.StartedAt, CompletedAt: time.Now().UTC(),
	}
}

func technical(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if len(input.TestCases) > 0 {
		score += 20
		strengths = append(strengths, "Evaluation test cases are defined")
	} else {
		gaps = append(gaps, "No evaluation test cases are configured")
		*findings = append(*findings, gap("high", "output-validation", "No AI evaluation test cases are configured", "Add prompt injection, PII, output safety, grounding, and agent workflow cases."))
	}
	if hasCategory(input.TestCases, "prompt-injection") {
		score += 10
		strengths = append(strengths, "Prompt-injection validation is configured")
	} else {
		gaps = append(gaps, "Prompt-injection validation is missing")
	}
	if hasCategory(input.TestCases, "grounding") || hasCategory(input.TestCases, "hallucination") {
		score += 10
		strengths = append(strengths, "Grounding and hallucination validation are configured")
	} else {
		gaps = append(gaps, "Grounding validation is missing")
		*findings = append(*findings, gap("high", "grounding", "Grounding validation is not configured", "Add RAG evidence and unsupported-claim test cases."))
	}
	if realCoverage(input.ToolResults) > 0 {
		score += 20
		strengths = append(strengths, fmt.Sprintf("%d real evaluator(s) produced technical evidence", realCoverage(input.ToolResults)))
	} else {
		gaps = append(gaps, "No real evaluator produced technical evidence")
	}
	if allPassing(input.TestCases) && len(input.TestCases) > 0 {
		score += 10
		strengths = append(strengths, "Configured technical cases currently pass")
	} else if len(input.TestCases) > 0 {
		gaps = append(gaps, "One or more technical controls are failing")
	}
	if !hasHighRiskFinding(input.ToolResults, "prompt-injection", "pii", "privacy", "credential", "output-safety", "grounding", "hallucination", "agent-safety", "runtime-security", "code-security", "dependency", "iam-policy") {
		score += 30
		strengths = append(strengths, "No high or critical technical findings are open")
	} else {
		gaps = append(gaps, "High or critical technical findings are open")
		*findings = append(*findings, gap("high", "technical-risk", "High or critical technical scan findings are open", "Close high and critical scan findings or record accountable risk acceptance before release."))
	}
	return enrich(category("Technical Controls", score, strengths, gaps),
		"Evaluates whether repeatable technical tests exist for prompt attacks, privacy, unsafe output, grounding, and AI workload behavior.",
		[]string{"Versioned evaluation cases", "Prompt and model configuration", "Grounding evidence", "Evaluation results and regression history"},
		[]schema.ControlReference{
			{Reference: "Clause 8", Topic: "Operational planning and control for the AI management system", URL: standardURL},
			{Reference: "Clause 9", Topic: "Performance evaluation, monitoring, measurement, analysis, and review", URL: standardURL},
			{Reference: "Annex A.6 and A.7 control families", Topic: "AI system lifecycle and data for AI systems", URL: standardURL},
		})
}

func governance(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Name != "" {
		score += 15
		strengths = append(strengths, "AI system is identified")
	}
	if input.Config.Project.Purpose != "" {
		score += 20
		strengths = append(strengths, "System purpose is documented")
	} else {
		gaps = append(gaps, "AI system purpose is not documented")
	}
	if input.Config.Project.Owner != "" {
		score += 25
		strengths = append(strengths, "Accountable AI system owner is defined")
	} else {
		gaps = append(gaps, "Missing AI Ownership Register")
		*findings = append(*findings, gap("high", "ai-ownership", "AI system owner is not defined", "Assign an accountable owner and record the system in an AI inventory."))
	}
	if input.Config.Governance.DataOwner != "" {
		score += 20
		strengths = append(strengths, "Data access ownership is documented")
	} else {
		gaps = append(gaps, "Data access owner is not documented")
		*findings = append(*findings, gap("medium", "data-governance", "Data ownership is not documented", "Identify the owner responsible for source data and access decisions."))
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI policy", input.Config.Governance.PolicyPath, "ai-policy", "high", "Create an approved AI policy covering acceptable use, prohibited use, data handling, security, release criteria, and exceptions.")
	return enrich(category("Governance", score, strengths, gaps),
		"Evaluates whether the AI system, purpose, accountable owner, data ownership, and governing AI policy are explicitly documented.",
		[]string{"AI system inventory", "Approved purpose and scope", "Named accountable owner", "Data ownership and access responsibility", "Approved AI policy"},
		[]schema.ControlReference{
			{Reference: "Clauses 4-6", Topic: "Organizational context, leadership, policy, roles, objectives, risks, and planning", URL: standardURL},
			{Reference: "Annex A.2 and A.3 control families", Topic: "AI-related policy and internal organization", URL: standardURL},
			{Reference: "Annex A.5 control family", Topic: "AI system impact assessment", URL: standardURL},
		})
}

func riskImpactManagement(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	addDoc(input, &score, &strengths, &gaps, findings, 30, "AI risk register", input.Config.Governance.RiskRegister, "risk-register", "high", "Maintain a risk register with owner, likelihood, impact, treatment, due date, residual risk, and acceptance status.")
	addDoc(input, &score, &strengths, &gaps, findings, 30, "AI impact assessment", input.Config.Governance.ImpactAssessment, "impact-assessment", "high", "Document intended users, affected stakeholders, foreseeable misuse, harms, safeguards, and go/no-go decision.")
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Model card", input.Config.Governance.ModelCard, "model-card", "medium", "Document model/provider, version, intended use, limitations, evaluation results, known failure modes, and monitoring triggers.")
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Data lineage record", input.Config.Governance.DataLineage, "data-lineage", "medium", "Document prompts, retrieval sources, logs, personal data, retention rules, access owners, and approved storage locations.")
	return enrich(category("Risk & Impact Management", score, strengths, gaps),
		"Evaluates whether non-technical risk, impact, model, and data-lineage evidence exists before deployment decisions are made.",
		[]string{"Risk register", "Impact assessment", "Model card", "Data lineage and retention record"},
		[]schema.ControlReference{
			{Framework: "ISO/IEC 42001", Reference: "Clauses 6 and 8", Topic: "Risk and opportunity planning plus operational control", URL: standardURL},
			{Framework: "ISO/IEC 42001", Reference: "Annex A.5", Topic: "AI system impact assessment", URL: standardURL},
			{Framework: "NIST AI RMF", Reference: "MAP", Topic: "Context, risks, benefits, and impacts are identified", URL: nistCoreURL},
			{Framework: "AIUC-1", Reference: "Data & Privacy/Accountability", Topic: "Data safeguards, risk ownership, and defensible decision records", URL: aiucURL},
		})
}

func humanOversight(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Governance.ApprovalWorkflow != "" {
		score += 30
		strengths = append(strengths, "Approval workflow is documented")
	} else {
		gaps = append(gaps, "No documented approval process")
		*findings = append(*findings, gap("high", "approval-workflow", "Deployment approval workflow is not defined", "Document who approves AI changes, the evidence required, and blocking conditions."))
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 25
		strengths = append(strengths, "Human review is required for deployment")
	} else {
		gaps = append(gaps, "Human review is not required before deployment")
		*findings = append(*findings, gap("high", "human-oversight", "Human review gate is not required", "Require accountable human review before production deployment or high-impact agent actions."))
	}
	addDoc(input, &score, &strengths, &gaps, findings, 25, "Human oversight plan", input.Config.Governance.HumanOversightPlan, "human-oversight", "high", "Define review checkpoints, escalation criteria, blocked actions, approver role, and exception handling.")
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Decision audit log", input.Config.Governance.AuditLog, "decision-trail", "medium", "Record release decisions, approvers, exceptions, incident links, and risk acceptance decisions.")
	return enrich(category("Human Oversight", score, strengths, gaps),
		"Evaluates whether production deployment and high-impact AI actions require accountable human review and recorded approval.",
		[]string{"Approval workflow", "Named approver or role", "Human review criteria", "Approval and exception records"},
		[]schema.ControlReference{
			{Reference: "Clause 5", Topic: "Leadership, accountability, roles, responsibilities, and authorities", URL: standardURL},
			{Reference: "Annex A.3 and A.9 control families", Topic: "Internal organization and responsible use of AI systems", URL: standardURL},
			{Reference: "Annex A.8 control family", Topic: "Information for interested parties", URL: standardURL},
		})
}

func operationalMonitoring(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Governance.EvaluationCadence != "" {
		score += 25
		strengths = append(strengths, "Evaluation cadence is defined")
	} else {
		gaps = append(gaps, "Evaluation cadence not defined")
		*findings = append(*findings, gap("medium", "evaluation-cadence", "Continuous evaluation cadence is not defined", "Schedule a recurring evaluation and record the owner and evidence retention period."))
	}
	if input.Config.Governance.ReevaluateOnChange {
		score += 20
		strengths = append(strengths, "Re-evaluation is required after material changes")
	} else {
		gaps = append(gaps, "Re-evaluation after model or prompt changes is not required")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 25, "AI incident response runbook", input.Config.Governance.IncidentResponseRunbook, "incident-response", "medium", "Document containment, evidence preservation, notification, remediation, re-approval, and post-incident review.")
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Monitoring plan", input.Config.Governance.MonitoringPlan, "monitoring-plan", "medium", "Define metrics, sampling, alert thresholds, owner, monitoring cadence, and evidence retention.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Change-management plan", input.Config.Governance.ChangeManagement, "change-management", "medium", "Define changes that require re-evaluation, reviewer approval, and release evidence.")
	return enrich(category("Operational Monitoring", score, strengths, gaps),
		"Evaluates recurring assessment, re-evaluation after change, monitoring, change management, and response procedures for unsafe or materially incorrect AI behavior.",
		[]string{"Evaluation schedule", "Change-triggered reassessment policy", "Monitoring plan/results", "AI incident response runbook", "Change-management records", "Corrective action records"},
		[]schema.ControlReference{
			{Reference: "Clauses 9-10", Topic: "Performance evaluation, internal review, nonconformity, corrective action, and continual improvement", URL: standardURL},
			{Reference: "Annex A.6 control family", Topic: "AI system lifecycle management", URL: standardURL},
		})
}

func evidenceReadiness(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	existing := 0
	for _, path := range input.Evidence {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			existing++
		}
	}
	if existing > 0 {
		score += 35
		strengths = append(strengths, fmt.Sprintf("%d evidence source(s) are traceable", existing))
	} else {
		gaps = append(gaps, "No evidence source files are available")
		*findings = append(*findings, gap("high", "evidence-readiness", "Evidence sources are not available", "Add and version the knowledge, policy, or evaluation evidence used by the AI system."))
	}
	if len(input.TestSources) > 0 {
		score += 25
		strengths = append(strengths, "Evaluation cases are traceable to files")
	}
	reportsDir := filepath.Join(input.RootDir, ".infraseal", "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err == nil {
		score += 20
		strengths = append(strengths, "Local evidence report repository is available")
	}
	if input.Config.Governance.RemediationTracking != "" {
		score += 20
		strengths = append(strengths, "Remediation tracking method is documented")
	} else {
		gaps = append(gaps, "Remediation tracking method is not documented")
		*findings = append(*findings, gap("low", "risk-management", "Remediation tracking is not defined", "Document where findings, owners, due dates, and closure evidence are tracked."))
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Decision audit log", input.Config.Governance.AuditLog, "decision-trail", "medium", "Maintain an audit log linking scan outputs, approval records, exceptions, and closure evidence.")
	return enrich(category("Evidence Readiness", score, strengths, gaps),
		"Evaluates whether source evidence, test cases, reports, and remediation records are traceable and available for review.",
		[]string{"Controlled policies and evidence sources", "Traceable test cases", "Assessment reports", "Finding owners and due dates", "Closure evidence"},
		[]schema.ControlReference{
			{Reference: "Clause 7.5", Topic: "Documented information and control of records", URL: standardURL},
			{Reference: "Clause 9.1", Topic: "Monitoring, measurement, analysis, and evaluation evidence", URL: standardURL},
			{Reference: "Annex A.5, A.6, and A.8 control families", Topic: "Impact assessment, lifecycle evidence, and information for interested parties", URL: standardURL},
		})
}

func transparencyTraining(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	addDoc(input, &score, &strengths, &gaps, findings, 35, "User disclosure", input.Config.Governance.UserDisclosure, "transparency", "medium", "Document user-facing AI disclosure, limitations, escalation paths, appeal/redress channel, and provenance language.")
	addDoc(input, &score, &strengths, &gaps, findings, 35, "Training and attestation records", input.Config.Governance.TrainingRecords, "training-attestation", "medium", "Track role-based AI usage/security training, policy attestations, reviewers, and exceptions.")
	addDoc(input, &score, &strengths, &gaps, findings, 30, "Vendor review", input.Config.Governance.VendorReview, "vendor-review", "medium", "Record provider dependencies, data sharing, retention terms, security review, contractual controls, and exit criteria.")
	return enrich(category("Transparency & Training", score, strengths, gaps),
		"Evaluates practical non-technical controls for user transparency, staff readiness, and third-party AI dependencies.",
		[]string{"User disclosure", "Training and policy attestation evidence", "AI vendor/provider review"},
		[]schema.ControlReference{
			{Framework: "ISO/IEC 42001", Reference: "Clause 7; Annex A.8/A.10", Topic: "Awareness, documented information, interested-party information, and third-party controls", URL: standardURL},
			{Framework: "NIST AI RMF", Reference: "GOVERN/MAP", Topic: "Organizational roles, communication, and stakeholder context", URL: nistCoreURL},
			{Framework: "AIUC-1", Reference: "Society/Accountability", Topic: "Responsible deployment, transparency, and auditable control ownership", URL: aiucURL},
		})
}

func category(name string, score int, strengths, gaps []string) schema.ReadinessCategory {
	if score > 100 {
		score = 100
	}
	status := "WARN"
	if score >= 80 {
		status = "PASS"
	} else if score < 50 {
		status = "FAIL"
	}
	return schema.ReadinessCategory{Name: name, Score: score, Status: status, Strengths: strengths, Gaps: gaps}
}

func enrich(category schema.ReadinessCategory, summary string, expected []string, references []schema.ControlReference) schema.ReadinessCategory {
	category.AssessmentSummary = summary
	category.ExpectedEvidence = expected
	category.ControlReferences = references
	return category
}

func gap(severity, categoryName, title, action string) schema.Finding {
	return schema.Finding{Severity: severity, Domain: "Governance", Category: categoryName, Title: title, Description: title, Evidence: "infraseal.yaml readiness control", Recommendation: action, SourceTool: "mcpvia", ExecutionMode: "native"}
}

func gapEvidence(severity, categoryName, title, evidence, action string) schema.Finding {
	return schema.Finding{Severity: severity, Domain: "Governance", Category: categoryName, Title: title, Description: title, Evidence: evidence, Recommendation: action, SourceTool: "mcpvia", ExecutionMode: "native"}
}

func addDoc(input Input, score *int, strengths, gaps *[]string, findings *[]schema.Finding, points int, label, path, categoryName, severity, action string) {
	rel, complete, reason := documentStatus(input, path)
	if complete {
		*score += points
		*strengths = append(*strengths, fmt.Sprintf("%s complete (%s)", label, rel))
		return
	}
	message := fmt.Sprintf("%s is %s", label, reason)
	*gaps = append(*gaps, message)
	evidence := "infraseal.yaml governance field"
	if rel != "" {
		evidence = rel
	}
	*findings = append(*findings, gapEvidence(severity, categoryName, message, evidence, action))
}

func documentStatus(input Input, path string) (string, bool, string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false, "not configured"
	}
	resolved := config.Resolve(input.RootDir, path)
	rel, err := filepath.Rel(input.RootDir, resolved)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() {
		return rel, false, "configured but missing"
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return rel, false, "configured but unreadable"
	}
	text := strings.TrimSpace(string(data))
	lower := strings.ToLower(text)
	if len(text) < 120 || strings.Contains(lower, "todo:") || strings.Contains(lower, "tbd") || strings.Contains(lower, "replace this") {
		return rel, false, "a starter template or incomplete"
	}
	return rel, true, ""
}

func hasCategory(cases []config.TestCase, value string) bool {
	for _, tc := range cases {
		if strings.EqualFold(tc.Category, value) {
			return true
		}
	}
	return false
}

func allPassing(cases []config.TestCase) bool {
	for _, tc := range cases {
		if !tc.Pass {
			return false
		}
	}
	return true
}

func nistGovern(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Owner != "" {
		score += 15
		strengths = append(strengths, "Accountable AI owner is defined")
	} else {
		gaps = append(gaps, "AI ownership is not assigned")
		*findings = append(*findings, gap("high", "ai-ownership", "NIST GOVERN evidence is missing an accountable owner", "Assign an owner with authority over AI risk acceptance and release decisions."))
	}
	if input.Config.Governance.ApprovalWorkflow != "" {
		score += 15
		strengths = append(strengths, "Approval workflow is documented")
	} else {
		gaps = append(gaps, "Approval workflow is not documented")
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 15
		strengths = append(strengths, "Human review is required before release")
	} else {
		gaps = append(gaps, "Human review gate is not required")
	}
	if input.Config.Governance.RemediationTracking != "" {
		score += 15
		strengths = append(strengths, "Remediation tracking is defined")
	} else {
		gaps = append(gaps, "Risk treatment and remediation tracking are not defined")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI policy", input.Config.Governance.PolicyPath, "ai-policy", "high", "Approve and publish an AI policy that defines permitted use, prohibited use, roles, release criteria, and exceptions.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Training and attestation records", input.Config.Governance.TrainingRecords, "training-attestation", "medium", "Track role-based AI usage/security training and policy attestations.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Decision audit log", input.Config.Governance.AuditLog, "decision-trail", "medium", "Link release decisions, risk acceptances, exceptions, and scan reports in a maintained audit log.")
	return enrich(category("GOVERN", score, strengths, gaps),
		"Evaluates organization-level accountability, policies, roles, oversight, risk ownership, and corrective-action tracking.",
		[]string{"AI owner", "Risk acceptance policy", "Human review workflow", "Remediation tracker", "Release approval evidence"},
		[]schema.ControlReference{
			{Framework: "NIST AI RMF", Reference: "GOVERN", Topic: "Policies, processes, procedures, and practices are in place across the AI lifecycle", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clauses 5-6", Topic: "Leadership, roles, responsibilities, objectives, risk and opportunity planning", URL: standardURL},
			{Framework: "AIUC-1", Reference: "Accountability", Topic: "Ownership, oversight, and decision traceability for AI agents", URL: aiucURL},
		})
}

func nistMap(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Purpose != "" {
		score += 15
		strengths = append(strengths, "AI system purpose is documented")
	} else {
		gaps = append(gaps, "AI system purpose is missing")
	}
	if input.Config.Project.Type != "" {
		score += 10
		strengths = append(strengths, "Workload class is declared")
	}
	if input.Config.Governance.DataOwner != "" {
		score += 15
		strengths = append(strengths, "Data owner is identified")
	} else {
		gaps = append(gaps, "Data owner is not identified")
	}
	if len(input.Evidence) > 0 {
		score += 15
		strengths = append(strengths, "Evidence sources are configured")
	} else {
		gaps = append(gaps, "Evidence sources are not configured")
		*findings = append(*findings, gap("high", "evidence-readiness", "NIST MAP evidence sources are missing", "Map the model, prompts, data sources, retrieved context, and expected operating boundary."))
	}
	if len(input.Config.Inputs.Targets) > 0 || len(input.Config.Inputs.Include) > 0 {
		score += 10
		strengths = append(strengths, "Scan scope is declared in configuration")
	} else {
		gaps = append(gaps, "Scan scope is not declared")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 15, "AI impact assessment", input.Config.Governance.ImpactAssessment, "impact-assessment", "high", "Document stakeholders, foreseeable misuse, expected benefits, harms, safeguards, and release decision.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Model card", input.Config.Governance.ModelCard, "model-card", "medium", "Document model/provider, version, intended use, limitations, evaluation results, and known failure modes.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Data lineage record", input.Config.Governance.DataLineage, "data-lineage", "medium", "Map prompts, retrieval sources, logs, personal data, retention, and approved storage.")
	return enrich(category("MAP", score, strengths, gaps),
		"Evaluates whether the system context, intended purpose, data ownership, evidence sources, and scan scope are mapped before risk measurement.",
		[]string{"System purpose", "Workload class", "Data lineage", "Evidence inventory", "Included and excluded scan scope"},
		[]schema.ControlReference{
			{Framework: "NIST AI RMF", Reference: "MAP", Topic: "Context is established and risks are identified", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clause 4; Annex A.5", Topic: "Organizational context and AI system impact assessment", URL: standardURL},
			{Framework: "AIUC-1", Reference: "Data & Privacy", Topic: "Data policies, access controls, and safeguards against leakage", URL: aiucURL},
		})
}

func nistMeasure(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if len(input.TestCases) > 0 {
		score += 20
		strengths = append(strengths, "Evaluation cases are versioned")
	} else {
		gaps = append(gaps, "Evaluation cases are missing")
	}
	if hasAnyCategory(input.TestCases, "prompt-injection", "pii", "output-safety") {
		score += 20
		strengths = append(strengths, "Security, privacy, or safety cases are configured")
	} else {
		gaps = append(gaps, "Security, privacy, and safety evaluation cases are missing")
	}
	if hasAnyCategory(input.TestCases, "grounding", "hallucination") {
		score += 20
		strengths = append(strengths, "Grounding or hallucination cases are configured")
	} else {
		gaps = append(gaps, "Reliability and grounding cases are missing")
	}
	if realCoverage(input.ToolResults) > 0 {
		score += 20
		strengths = append(strengths, fmt.Sprintf("%d real evaluator(s) produced evidence", realCoverage(input.ToolResults)))
	} else {
		gaps = append(gaps, "No external evaluator produced real evidence")
	}
	if !hasHighRiskFinding(input.ToolResults, "prompt-injection", "pii", "credential", "grounding", "hallucination", "runtime-security", "code-security", "dependency") {
		score += 20
		strengths = append(strengths, "No high-severity measurement findings are open")
	} else {
		gaps = append(gaps, "High-severity measurement findings are open")
		*findings = append(*findings, gap("high", "risk-measurement", "NIST MEASURE found high-risk technical evidence", "Treat high and critical findings as release blockers or document risk acceptance."))
	}
	return enrich(category("MEASURE", score, strengths, gaps),
		"Evaluates prompt attack resistance, privacy, safety, grounding, code, dependency, agent, and infrastructure evidence.",
		[]string{"Evaluation results", "Scanner artifacts", "Hallucination/grounding evidence", "Code and dependency findings", "Terraform plan findings"},
		[]schema.ControlReference{
			{Framework: "NIST AI RMF", Reference: "MEASURE", Topic: "AI risks and trustworthiness characteristics are assessed and analyzed", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clauses 8-9; Annex A.6/A.7", Topic: "Operational control, lifecycle evidence, data controls, and evaluation", URL: standardURL},
			{Framework: "AIUC-1", Reference: "Security/Safety/Reliability", Topic: "Agent security, harmful output prevention, and reliability testing", URL: aiucURL},
		})
}

func nistManage(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Settings.BlockOnCritical {
		score += 20
		strengths = append(strengths, "Critical findings block release gates")
	} else {
		gaps = append(gaps, "Critical findings are not configured to block release")
	}
	if input.Config.Governance.ReevaluateOnChange {
		score += 20
		strengths = append(strengths, "Material changes require re-evaluation")
	} else {
		gaps = append(gaps, "Change-triggered re-evaluation is missing")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI incident response runbook", input.Config.Governance.IncidentResponseRunbook, "incident-response", "medium", "Document containment, evidence preservation, notification, remediation, re-approval, and post-incident review.")
	if input.Config.Governance.EvaluationCadence != "" {
		score += 15
		strengths = append(strengths, "Recurring evaluation cadence is defined")
	} else {
		gaps = append(gaps, "Recurring evaluation cadence is not defined")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 15, "Monitoring plan", input.Config.Governance.MonitoringPlan, "monitoring-plan", "medium", "Define metrics, sampling, alert thresholds, owner, monitoring cadence, and evidence retention.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Change-management plan", input.Config.Governance.ChangeManagement, "change-management", "medium", "Define changes that require re-evaluation, reviewer approval, and release evidence.")
	return enrich(category("MANAGE", score, strengths, gaps),
		"Evaluates whether measured risks drive release gates, reassessment, incident response, and ongoing risk treatment.",
		[]string{"Release gate policy", "Risk treatment plan", "Change-management trigger", "Incident response runbook", "Monitoring cadence"},
		[]schema.ControlReference{
			{Framework: "NIST AI RMF", Reference: "MANAGE", Topic: "Risks are prioritized, responded to, and monitored", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clause 10", Topic: "Corrective action and continual improvement", URL: standardURL},
			{Framework: "AIUC-1", Reference: "Accountability", Topic: "Decision traceability and controlled risk acceptance", URL: aiucURL},
		})
}

func aiucDataPrivacy(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Governance.DataOwner != "" {
		score += 20
		strengths = append(strengths, "Data owner is defined")
	} else {
		gaps = append(gaps, "Data owner is missing")
	}
	if hasAnyCategory(input.TestCases, "pii", "privacy") {
		score += 25
		strengths = append(strengths, "PII/privacy evaluation cases are configured")
	} else {
		gaps = append(gaps, "PII/privacy evaluation is missing")
	}
	if !hasHighRiskFinding(input.ToolResults, "pii", "privacy", "credential", "data-exfiltration") {
		score += 30
		strengths = append(strengths, "No high-risk privacy findings are open")
	} else {
		gaps = append(gaps, "High-risk privacy findings are open")
		*findings = append(*findings, gap("high", "privacy-risk", "AIUC-1 Data & Privacy evidence found high-risk issues", "Fix or formally accept privacy, credential, and data-leakage risks before release."))
	}
	addDoc(input, &score, &strengths, &gaps, findings, 25, "Data lineage record", input.Config.Governance.DataLineage, "data-lineage", "medium", "Map the data used by prompts, retrieval, logs, storage, retention, and model-provider calls.")
	return enrich(category("Data & Privacy", score, strengths, gaps),
		"Evaluates protection against customer-data leakage, IP leakage, credentials in prompts/plans, and unauthorized data handling.",
		[]string{"Data owner", "PII regression cases", "Secret scanning output", "Data leakage findings", "Approved evidence sources"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Data & Privacy", Topic: "Customer data policies, access controls, and safeguards", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "MEASURE 2", Topic: "Privacy-enhanced trustworthy AI characteristics", URL: nistPlaybookURL},
			{Framework: "ISO/IEC 42001", Reference: "Annex A.7", Topic: "Data for AI systems", URL: standardURL},
		})
}

func aiucSecurity(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if hasAnyCategory(input.TestCases, "prompt-injection") {
		score += 25
		strengths = append(strengths, "Prompt-injection cases are configured")
	} else {
		gaps = append(gaps, "Prompt-injection testing is missing")
	}
	if len(input.Config.Inputs.AgentSkills) > 0 || len(input.Config.Inputs.Targets) > 0 || len(input.Config.Inputs.Include) > 0 {
		score += 20
		strengths = append(strengths, "Agent/source scan scope is configured")
	}
	if realCoverage(input.ToolResults) > 0 {
		score += 15
		strengths = append(strengths, "Real scanner evidence is available")
	} else {
		gaps = append(gaps, "No real scanner evidence is available")
	}
	if !hasHighRiskFinding(input.ToolResults, "prompt-injection", "agent-safety", "runtime-security", "code-security", "dependency", "iam-policy") {
		score += 40
		strengths = append(strengths, "No high-risk security findings are open")
	} else {
		gaps = append(gaps, "High-risk security findings are open")
	}
	return enrich(category("Security", score, strengths, gaps),
		"Evaluates adversarial prompt resistance, tool authorization, source-code risk, dependency risk, and infrastructure exposure.",
		[]string{"Prompt attack tests", "Agent skill manifests", "Code scan results", "Dependency scan results", "Terraform plan findings"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Security", Topic: "Jailbreaks, prompt injection, unauthorized tool calls, and exploitable agent behavior", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "MEASURE/MANAGE", Topic: "Secure and resilient assessment plus risk response", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clause 8; Annex A.6", Topic: "Operational controls and AI lifecycle management", URL: standardURL},
		})
}

func aiucSafety(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if hasAnyCategory(input.TestCases, "output-safety") {
		score += 35
		strengths = append(strengths, "Unsafe-output evaluation cases are configured")
	} else {
		gaps = append(gaps, "Unsafe-output testing is missing")
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 20
		strengths = append(strengths, "Human review is required for release")
	} else {
		gaps = append(gaps, "Human review is not required")
	}
	if !hasHighRiskFinding(input.ToolResults, "output-safety", "unsafe") {
		score += 25
		strengths = append(strengths, "No high-risk safety findings are open")
	} else {
		gaps = append(gaps, "High-risk safety findings are open")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Human oversight plan", input.Config.Governance.HumanOversightPlan, "human-oversight", "high", "Define review checkpoints, blocked actions, escalation, exception handling, and approver roles.")
	return enrich(category("Safety", score, strengths, gaps),
		"Evaluates safeguards against harmful output, brand risk, unsafe instructions, and missing human review.",
		[]string{"Safety test cases", "Refusal behavior evidence", "Human review workflow", "Safety findings and closure evidence"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Safety", Topic: "Prevention of harmful AI outputs and brand risk", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "MEASURE 2", Topic: "Safe trustworthy AI characteristics", URL: nistPlaybookURL},
			{Framework: "ISO/IEC 42001", Reference: "Annex A.9", Topic: "Responsible use of AI systems", URL: standardURL},
		})
}

func aiucReliability(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if hasAnyCategory(input.TestCases, "grounding", "hallucination") {
		score += 40
		strengths = append(strengths, "Grounding/hallucination cases are configured")
	} else {
		gaps = append(gaps, "Grounding and hallucination testing is missing")
	}
	if len(input.Evidence) > 0 {
		score += 25
		strengths = append(strengths, "Evidence sources are configured")
	} else {
		gaps = append(gaps, "Evidence sources are missing")
	}
	if !hasHighRiskFinding(input.ToolResults, "grounding", "hallucination", "rag", "context") {
		score += 35
		strengths = append(strengths, "No high-risk reliability findings are open")
	} else {
		gaps = append(gaps, "High-risk reliability findings are open")
		*findings = append(*findings, gap("high", "reliability-risk", "AIUC-1 Reliability evidence found unsupported answers", "Require cited evidence spans and convert unsupported responses into regression cases."))
	}
	return enrich(category("Reliability", score, strengths, gaps),
		"Evaluates hallucination resistance, grounded answers, dependable retrieval context, and tool-call reliability.",
		[]string{"Knowledge/evidence files", "Grounding cases", "Exported chatbot outputs", "Verifier results", "Reliability regression history"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Reliability", Topic: "Hallucination prevention and reliable tool calls to business systems", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "MEASURE 2", Topic: "Valid and reliable trustworthy AI characteristics", URL: nistPlaybookURL},
			{Framework: "ISO/IEC 42001", Reference: "Clause 9", Topic: "Monitoring, measurement, analysis, and evaluation", URL: standardURL},
		})
}

func aiucAccountability(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Owner != "" {
		score += 15
		strengths = append(strengths, "Accountable owner is defined")
	} else {
		gaps = append(gaps, "Accountable owner is missing")
	}
	if input.Config.Governance.ApprovalWorkflow != "" {
		score += 15
		strengths = append(strengths, "Approval workflow is documented")
	} else {
		gaps = append(gaps, "Approval workflow is missing")
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 15
		strengths = append(strengths, "Human review is required")
	} else {
		gaps = append(gaps, "Human review is not required")
	}
	if input.Config.Governance.RemediationTracking != "" {
		score += 15
		strengths = append(strengths, "Remediation tracking is documented")
	} else {
		gaps = append(gaps, "Remediation tracking is missing")
	}
	if len(input.TestSources) > 0 {
		score += 10
		strengths = append(strengths, "Evaluation cases are traceable")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 15, "AI risk register", input.Config.Governance.RiskRegister, "risk-register", "high", "Maintain a risk register with owner, treatment status, residual risk, and acceptance evidence.")
	addDoc(input, &score, &strengths, &gaps, findings, 15, "Decision audit log", input.Config.Governance.AuditLog, "decision-trail", "medium", "Link approvals, exceptions, scan reports, and risk acceptances in a maintained audit log.")
	return enrich(category("Accountability", score, strengths, gaps),
		"Evaluates release ownership, human approval, traceability, remediation, and evidence needed to explain deployment decisions.",
		[]string{"System owner", "Approval workflow", "Human review records", "Decision trail", "Remediation closure evidence"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Accountability", Topic: "Agent ownership, oversight, auditability, and risk decisions", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "GOVERN", Topic: "Accountability and policies across the AI lifecycle", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clauses 5, 7.5, 10", Topic: "Roles, documented information, and continual improvement", URL: standardURL},
		})
}

func aiucSociety(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Purpose != "" {
		score += 20
		strengths = append(strengths, "Use-case purpose is documented")
	} else {
		gaps = append(gaps, "Use-case purpose is missing")
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 15
		strengths = append(strengths, "Human oversight is part of the release decision")
	}
	if input.Config.Governance.EvaluationCadence != "" {
		score += 15
		strengths = append(strengths, "Recurring evaluation supports ongoing impact review")
	} else {
		gaps = append(gaps, "Recurring impact review cadence is missing")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI impact assessment", input.Config.Governance.ImpactAssessment, "impact-assessment", "medium", "Review intended users, affected stakeholders, foreseeable misuse, harms, safeguards, and residual impact.")
	addDoc(input, &score, &strengths, &gaps, findings, 15, "User disclosure", input.Config.Governance.UserDisclosure, "transparency", "medium", "Document user-facing AI disclosure, limitations, escalation paths, appeal/redress, and provenance language.")
	addDoc(input, &score, &strengths, &gaps, findings, 15, "AI incident response runbook", input.Config.Governance.IncidentResponseRunbook, "incident-response", "medium", "Document an incident path for harmful, misleading, or materially incorrect AI behavior.")
	return enrich(category("Society", score, strengths, gaps),
		"Evaluates whether use-case purpose, oversight, recurring review, and incident handling support responsible deployment.",
		[]string{"Use-case purpose", "Impact review notes", "Human oversight criteria", "Monitoring cadence", "Incident handling route"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Society", Topic: "Responsible deployment and broader misuse-risk consideration", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "MAP/MANAGE", Topic: "Contextual impacts and risk response", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Annex A.5/A.8", Topic: "AI system impact assessment and interested-party information", URL: standardURL},
		})
}

func assignIDs(findings []schema.Finding, framework string) {
	prefix := "ISO"
	if framework == "nist-ai-rmf" {
		prefix = "NIST"
	}
	if framework == "aiuc1" {
		prefix = "AIUC"
	}
	for i := range findings {
		findings[i].ID = fmt.Sprintf("%s-%03d", prefix, i+1)
	}
}

func relativePaths(root string, paths []string) []string {
	var values []string
	for _, path := range paths {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		values = append(values, filepath.ToSlash(rel))
	}
	return values
}

func evidenceFiles(input Input) []string {
	seen := map[string]bool{}
	var values []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		values = append(values, path)
	}
	for _, path := range input.TestSources {
		add(path)
	}
	for _, path := range relativePaths(input.RootDir, input.Evidence) {
		add(path)
	}
	for _, path := range relativePaths(input.RootDir, config.Expand(input.RootDir, input.Config.Inputs.TerraformPlanJSON)) {
		add(path)
	}
	for _, path := range governanceDocumentPaths(input.Config.Governance) {
		rel, _, _ := documentStatus(input, path)
		add(rel)
	}
	return values
}

func governanceDocumentPaths(g config.GovernanceConfig) []string {
	return []string{
		g.PolicyPath,
		g.RiskRegister,
		g.ImpactAssessment,
		g.ModelCard,
		g.DataLineage,
		g.HumanOversightPlan,
		g.MonitoringPlan,
		g.ChangeManagement,
		g.IncidentResponseRunbook,
		g.VendorReview,
		g.TrainingRecords,
		g.UserDisclosure,
		g.AuditLog,
	}
}

func normalizeFramework(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	switch value {
	case "", "iso", "iso42001", "iso-42001", "iso/iec-42001":
		return "iso42001"
	case "nist", "nist-ai-rmf", "nistairmf", "ai-rmf":
		return "nist-ai-rmf"
	case "aiuc", "aiuc1", "aiuc-1":
		return "aiuc1"
	default:
		return value
	}
}

func toolFindings(results []schema.ToolResult) []schema.Finding {
	var findings []schema.Finding
	for _, result := range results {
		for _, finding := range result.Findings {
			if finding.Domain == "" {
				finding.Domain = scanners.DomainForCategory(finding.Category)
			}
			if finding.SourceTool == "" {
				finding.SourceTool = result.Name
			}
			if finding.ExecutionMode == "" {
				finding.ExecutionMode = result.Mode
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func hasAnyCategory(cases []config.TestCase, values ...string) bool {
	for _, tc := range cases {
		for _, value := range values {
			if strings.EqualFold(tc.Category, value) {
				return true
			}
		}
	}
	return false
}

func hasHighRiskFinding(results []schema.ToolResult, categories ...string) bool {
	for _, result := range results {
		for _, finding := range result.Findings {
			severity := strings.ToLower(finding.Severity)
			if severity != "high" && severity != "critical" {
				continue
			}
			value := strings.ToLower(finding.Category + " " + finding.Domain + " " + finding.Title)
			for _, category := range categories {
				if strings.Contains(value, strings.ToLower(category)) {
					return true
				}
			}
		}
	}
	return false
}

func hasBlockingFinding(findings []schema.Finding) bool {
	for _, finding := range findings {
		severity := strings.ToLower(finding.Severity)
		if severity == "critical" || severity == "high" {
			return true
		}
	}
	return false
}

func realCoverage(results []schema.ToolResult) int {
	count := 0
	for _, result := range results {
		if result.Mode == "real" && result.Status == "available" {
			count++
		}
	}
	return count
}
