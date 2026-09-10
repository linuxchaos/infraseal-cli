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

## Benchmark Views

ISO/IEC 42001:

- Technical Controls
- Governance
- Risk & Impact Management
- Human Oversight
- Operational Monitoring
- Evidence Readiness
- Transparency & Training

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
