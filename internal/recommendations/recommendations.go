package recommendations

import (
	"sort"
	"strings"

	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

func Build(findings []schema.Finding) []schema.Recommendation {
	byCategory := map[string][]schema.Finding{}
	for _, finding := range findings {
		key := strings.ToLower(finding.Category)
		byCategory[key] = append(byCategory[key], finding)
	}
	byTitle := map[string]schema.Recommendation{}
	for category, related := range byCategory {
		template := templateFor(category)
		ids := make([]string, 0, len(related))
		priority := template.Priority
		for _, finding := range related {
			ids = append(ids, finding.ID)
			if finding.Severity == "critical" {
				priority = 1
			} else if finding.Severity == "high" && priority > 2 {
				priority = 2
			}
		}
		template.Priority = priority
		template.RelatedFindings = ids
		key := strings.ToLower(template.Title)
		if existing, ok := byTitle[key]; ok {
			if template.Priority < existing.Priority {
				existing.Priority = template.Priority
			}
			existing.RelatedFindings = append(existing.RelatedFindings, template.RelatedFindings...)
			byTitle[key] = existing
		} else {
			byTitle[key] = template
		}
	}
	items := make([]schema.Recommendation, 0, len(byTitle))
	for _, item := range byTitle {
		items = append(items, item)
	}
	if len(items) == 0 {
		items = append(items, schema.Recommendation{
			Priority: 5, Title: "Maintain the evaluation baseline",
			WhyItMatters:    "A passing assessment is a point-in-time result.",
			SuggestedAction: "Rerun InfraSeal whenever prompts, models, evidence, agent skills, or dependencies change.",
			EstimatedEffort: "15 minutes", OwnerSuggestion: "AI system owner",
		})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Priority < items[j].Priority })
	for i := range items {
		items[i].Priority = i + 1
	}
	return items
}

func templateFor(category string) schema.Recommendation {
	switch {
	case strings.Contains(category, "ownership"), strings.Contains(category, "inventory"):
		return schema.Recommendation{Priority: 1, Title: "Create an AI inventory and assign an owner", WhyItMatters: "Accountability is required for risk acceptance, change control, and incident response.", SuggestedAction: "Document the system name, purpose, model, data sources, deployment environment, and accountable owner in infraseal.yaml or an AI inventory.", EstimatedEffort: "30 minutes", OwnerSuggestion: "AI governance lead"}
	case strings.Contains(category, "approval"), strings.Contains(category, "oversight"):
		return schema.Recommendation{Priority: 1, Title: "Add a human approval workflow", WhyItMatters: "High-impact AI changes and side effects need accountable review before deployment.", SuggestedAction: "Define the approver, approval evidence, blocking conditions, and emergency override process.", EstimatedEffort: "1 hour", OwnerSuggestion: "Product owner"}
	case strings.Contains(category, "cadence"), strings.Contains(category, "monitor"):
		return schema.Recommendation{Priority: 2, Title: "Establish an evaluation cadence", WhyItMatters: "Model, prompt, data, and dependency drift can invalidate a prior result.", SuggestedAction: "Schedule monthly evaluation and require re-assessment after material changes.", EstimatedEffort: "30 minutes", OwnerSuggestion: "MLOps lead"}
	case strings.Contains(category, "incident"):
		return schema.Recommendation{Priority: 2, Title: "Add an AI incident response runbook", WhyItMatters: "Unsafe or materially incorrect model decisions need a repeatable containment and review process.", SuggestedAction: "Document triage, containment, user notification, evidence preservation, and re-approval steps.", EstimatedEffort: "2 hours", OwnerSuggestion: "Security lead"}
	case strings.Contains(category, "ground"), strings.Contains(category, "halluc"), strings.Contains(category, "evidence"):
		return schema.Recommendation{Priority: 2, Title: "Strengthen grounding validation", WhyItMatters: "Unsupported claims can create customer harm and unreliable decisions.", SuggestedAction: "Require cited evidence spans, add unsupported-claim cases, and fail closed when evidence cannot be resolved.", EstimatedEffort: "1 hour", OwnerSuggestion: "AI engineer"}
	case strings.Contains(category, "inject"), strings.Contains(category, "jailbreak"):
		return schema.Recommendation{Priority: 2, Title: "Harden prompt-injection boundaries", WhyItMatters: "Untrusted content can redirect an agent or disclose protected instructions.", SuggestedAction: "Delimit retrieved content, enforce instruction hierarchy, restrict tools, and retain adversarial regression tests.", EstimatedEffort: "2 hours", OwnerSuggestion: "AI security engineer"}
	case strings.Contains(category, "pii"), strings.Contains(category, "privacy"):
		return schema.Recommendation{Priority: 2, Title: "Add PII handling controls", WhyItMatters: "Sensitive identifiers can leak through prompts, logs, retrieval, or outputs.", SuggestedAction: "Classify sensitive fields, redact inputs and outputs, and add privacy regression tests.", EstimatedEffort: "2 hours", OwnerSuggestion: "Privacy engineer"}
	case strings.Contains(category, "agent"), strings.Contains(category, "tool"):
		return schema.Recommendation{Priority: 2, Title: "Define an agent tool approval policy", WhyItMatters: "Broad tool permissions increase the blast radius of prompt injection and agent error.", SuggestedAction: "Minimize permissions and require human approval for external transfer, destructive action, or account changes.", EstimatedEffort: "1 hour", OwnerSuggestion: "Agent platform owner"}
	case strings.Contains(category, "code"), strings.Contains(category, "vulnerab"):
		return schema.Recommendation{Priority: 3, Title: "Remediate code and dependency risk", WhyItMatters: "Reachable code flaws can bypass otherwise strong AI controls.", SuggestedAction: "Patch the affected code or module and rerun the full profile in CI.", EstimatedEffort: "Varies", OwnerSuggestion: "Application security"}
	case strings.Contains(category, "data-governance"):
		return schema.Recommendation{Priority: 2, Title: "Define data access ownership", WhyItMatters: "Data sources and access decisions need an accountable owner.", SuggestedAction: "Identify the owner for source data, access policy, retention, and evidence approval.", EstimatedEffort: "30 minutes", OwnerSuggestion: "Data owner"}
	case strings.Contains(category, "risk-management"):
		return schema.Recommendation{Priority: 3, Title: "Document remediation tracking", WhyItMatters: "Findings need owners, due dates, closure evidence, and an audit trail.", SuggestedAction: "Document the issue system or control register used to track findings through closure.", EstimatedEffort: "20 minutes", OwnerSuggestion: "Risk owner"}
	default:
		return schema.Recommendation{Priority: 3, Title: "Resolve " + strings.ReplaceAll(category, "-", " ") + " findings", WhyItMatters: "Open findings reduce confidence in the deployment decision.", SuggestedAction: "Review the evidence, implement the suggested control, add a regression test, and rerun the assessment.", EstimatedEffort: "1 hour", OwnerSuggestion: "AI system owner"}
	}
}
