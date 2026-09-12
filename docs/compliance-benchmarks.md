# Compliance Benchmarks

InfraSeal maps technical scan evidence and non-technical governance evidence to three readiness views:

- ISO/IEC 42001 readiness
- NIST AI Risk Management Framework readiness
- AIUC-1 principles readiness

These packs are readiness assessments, not certification. They are designed to help a developer or AI owner turn a repository into an evidence-backed review package.

## Limits Of A CLI Readiness Check

Some controls in ISO/IEC 42001, NIST AI RMF, and AIUC-1 are organizational controls. InfraSeal can inspect repository evidence, scan technical artifacts, identify missing documents, connect findings to benchmark topics, and recommend next steps. It cannot independently prove that executives accepted accountability, employees completed training, procurement enforced vendor terms, human review was followed in production, or an incident response process worked during a real event.

For those areas, InfraSeal treats the control as addressable evidence. A passing result means the repository contains plausible review material and no blocking technical findings were found by the configured checks. It does not replace management review, legal review, privacy review, external audit, or certification.

## What InfraSeal Checks

Technical evidence:

- Prompt-injection and jailbreak behavior
- PII, credential, and data leakage signals
- Unsafe output regression cases
- Hallucination and grounding against approved evidence
- Agent skill permissions and risky tool/workflow patterns
- Source-code security findings
- Reachable dependency vulnerability findings
- Terraform plan JSON for runtime, IAM, network, storage, database, and secret exposure

Non-technical evidence:

- AI system owner and data owner
- Approved AI policy
- AI risk register
- AI impact assessment
- Model card or workload card
- Data lineage and retention notes
- Human oversight plan and approval workflow
- Monitoring plan and evaluation cadence
- Change-management rules
- Incident response runbook
- Vendor/provider review
- Training and policy attestation records
- User disclosure and transparency text
- Decision audit log
- Remediation tracking process

## How To Meet The Controls

`infraseal init` creates starter governance templates under `.infraseal/governance/`. They intentionally contain `TODO` text and will not count as complete readiness evidence until you replace them with real content.

Minimum useful evidence for a small AI workload:

- `ai-policy.md`: approved use, prohibited use, data rules, release criteria, exceptions
- `risk-register.md`: risk, owner, severity, likelihood, treatment, due date, status, residual risk
- `impact-assessment.md`: users, affected stakeholders, misuse, harms, safeguards, go/no-go decision
- `model-card.md`: model/provider, version, intended use, limitations, eval summary, known failure modes
- `data-lineage.md`: prompts, retrieval sources, logs, personal data, retention, storage, access owner
- `human-oversight-plan.md`: blocked actions, review checkpoints, escalation, approver role
- `monitoring-plan.md`: metrics, sampling cadence, alert thresholds, owner, evidence retention
- `change-management.md`: changes that require re-evaluation and approval
- `incident-response.md`: triage, containment, evidence preservation, notification, re-approval
- `vendor-review.md`: providers, data sharing, retention, security review, contractual controls
- `training-records.md`: role-based AI training and policy attestations
- `user-disclosure.md`: user-facing AI notice, limitations, escalation and appeal/redress path
- `audit-log.md`: release decisions, approvals, exceptions, incidents, and report links

Useful operating steps:

- Assign an accountable AI system owner and data owner in the YAML.
- Keep a risk register with owner, due date, treatment decision, and residual risk.
- Record release approvals and exceptions in the audit log.
- Re-run scans before material prompt, model, tool, data, policy, or infrastructure changes.
- Preserve report artifacts for release review and later incident investigation.
- Use pull request gates for high-risk workloads so technical findings are reviewed before merge.

## ISO/IEC 42001 Readiness

InfraSeal focuses ISO/IEC 42001 first because it is the dedicated AI management system standard. The CLI maps repository evidence to Clause 4 through Clause 10 at a readiness level. It does not reproduce the licensed standard text and does not claim certification.

Clause-oriented checks:

- Clause 4 - Context: project identity, system purpose, workload type, scan scope, exclusions, impact assessment, and data lineage.
- Clause 5 - Leadership: accountable owner, data owner, AI policy, approval workflow, human review, roles, and training/attestation evidence.
- Clause 6 - Planning: risk register, impact assessment, readiness threshold, critical-finding gate, risk treatment, remediation tracking, and reassessment on material change.
- Clause 7 - Support: traceable evidence sources, evaluation cases, model card, data lineage, vendor review, training records, and report retention formats.
- Clause 8 - Operation: prompt inputs, operational test cases, prompt-injection, privacy, unsafe-output, grounding, agent-safety, runtime-plan evidence, and open high-risk technical findings.
- Clause 9 - Performance Evaluation: latest scan evidence, monitoring plan, evaluation cadence, audit log, measurement results, and unresolved high-risk measurement findings.
- Clause 10 - Improvement: change-management plan, incident response runbook, corrective-action tracking, re-evaluation triggers, audit log, closure evidence, and open critical findings.

The content checks look for evidence quality signals inside the configured files, such as owners, treatment decisions, safeguards, review cadence, evidence retention, escalation routes, provider/data-sharing notes, and exception handling. A file with only a matching name or a starter `TODO` template does not pass.

ISO reports also include per-clause control assessments with:

- Applicability: applicable, conditional, or not applicable for the scanned workload.
- Status: pass, needs evidence, needs remediation, or not applicable.
- Review method: configuration check, document content check, test-case inventory, latest technical scan, or manual review.
- Evidence checked: YAML fields, governance documents, test cases, latest scan reports, agent skill files, or Terraform plan JSON.
- Gaps and next steps: concrete repository evidence, ownership, approval, monitoring, remediation, or operating records to add.

NIST AI RMF:

- GOVERN: ownership, policy, oversight, training, decision logs
- MAP: purpose, scope, data ownership, impact assessment, model card, lineage
- MEASURE: prompt, privacy, safety, grounding, code, dependency, agent, and infrastructure evidence
- MANAGE: release gates, monitoring, change management, incident response, risk treatment

AIUC-1 principles:

- Data & Privacy
- Security
- Safety
- Reliability
- Accountability
- Society

## Future Questionnaire And Semantic Review

The current CLI uses deterministic document-quality checks and latest technical findings. A future workflow will add a step-by-step questionnaire for controls that cannot be proven from files alone, such as management accountability, training completion, vendor-contract enforcement, internal audits, exception approvals, and incident exercises.

A future local-LLM mode can add semantic extraction over governance documents to judge whether the evidence substantively satisfies each control objective. That mode should remain local or customer-controlled and should preserve excerpts, prompts, model settings, reviewer identity, and decision traces for audit review.

## Commands

```bash
infraseal compliance iso42001
infraseal compliance nist-ai-rmf
infraseal compliance aiuc1
```

Use CI gates when the report should block a pull request:

```bash
infraseal compliance nist-ai-rmf --fail-on-readiness
```

## Official References

- [ISO/IEC 42001:2023](https://www.iso.org/standard/42001)
- [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
- [NIST AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/)
- [AIUC-1 public principles](https://aiuc.com/research/introducing-aiuc-1)
- [Can AI be Auditable?](https://arxiv.org/abs/2509.00575)
- [Auditing of AI: Legal, Ethical and Technical Approaches](https://arxiv.org/abs/2407.06235)
- [Assessing the Auditability of AI-integrating Systems](https://arxiv.org/abs/2411.08906)
