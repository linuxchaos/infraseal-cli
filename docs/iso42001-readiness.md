# ISO/IEC 42001 Readiness Pack

InfraSeal's first compliance focus is ISO/IEC 42001 readiness. The CLI maps repository evidence and the latest local scan result to Clause 4 through Clause 10 at a readiness level. It does not reproduce the licensed standard text and it does not claim certification.

## Clause-Oriented Checks

- Clause 4 - Context: system identity, purpose, workload type, assessment scope, exclusions, impact assessment, and data lineage.
- Clause 5 - Leadership: accountable owner, data owner, policy, approval workflow, human review, roles, and training evidence.
- Clause 6 - Planning: risk register, impact assessment, readiness threshold, critical-finding gate, remediation tracking, and reassessment on material change.
- Clause 7 - Support: traceable evidence sources, evaluation cases, model card, data lineage, vendor review, training records, and report retention formats.
- Clause 8 - Operation: prompt inputs, operational test cases, prompt-injection checks, privacy checks, unsafe-output checks, grounding checks, agent-safety checks, runtime-plan evidence, and open high-risk technical findings.
- Clause 9 - Performance Evaluation: latest scan evidence, monitoring plan, evaluation cadence, audit log, measurement results, and unresolved high-risk measurement findings.
- Clause 10 - Improvement: change-management plan, incident response runbook, corrective-action tracking, re-evaluation triggers, audit log, closure evidence, and open critical findings.

## Evidence Quality

The CLI checks whether configured governance files contain plausible substance, not only whether a filename exists. Starter templates with `TODO`, very short files, or files missing expected content are reported as incomplete.

Examples of content signals:

- AI policy includes permitted use, prohibited use, data handling, release criteria, and exceptions.
- Risk register includes owners, severity or likelihood, treatment, status, and residual risk.
- Impact assessment includes stakeholders, misuse or harms, safeguards, and a go/no-go decision.
- Model card includes model identity, intended use, limitations, evaluation evidence, and monitoring triggers.
- Data lineage includes data sources, personal or sensitive data, retention or storage, and access ownership.
- Human oversight plan includes review checkpoints, approval, escalation, exceptions, and blocked actions.
- Monitoring plan includes metrics, cadence, owner or issue tracking, and evidence retention.
- Audit log includes decisions, approvals or exceptions, report evidence, incidents, changes, and release records.

## What The CLI Can And Cannot Prove

InfraSeal can show whether the repository has evidence, whether that evidence looks complete enough for review, and whether recent technical findings undermine readiness. It cannot prove that leadership accepted accountability, employees completed training, a vendor contract is enforceable, or human review was followed in production. Those areas require real organizational records and management review.

For those non-technical controls, InfraSeal reports addressable gaps and recommends the document, owner, decision record, or workflow evidence needed to improve readiness.

## Report Detail

ISO readiness reports include per-clause control assessments. Each control records whether it appears applicable to the workload, whether the current repository evidence passes, what evidence was checked, which review method was used, and what remains for manual review or remediation.

Examples:

- Assessment scope and exclusions are checked from `inputs.include`, `inputs.targets`, and `inputs.exclude`.
- Documentation processes are checked from configured governance files and expected content signals.
- Runtime controls are checked from Terraform plan JSON when present.
- Agent controls are conditional and become applicable when the workload type or configured files indicate tool or skill use.
- Open high or critical technical findings from the latest full scan can prevent Clause 8, Clause 9, or Clause 10 readiness.

Official resources:

- [ISO/IEC 42001:2023 official standard page](https://www.iso.org/standard/42001)
- [ISO 42001 explained by ISO](https://www.iso.org/home/insights-news/resources/iso-42001-explained-what-it-is.html)

InfraSeal helps organizations prepare for and maintain AI governance programs aligned with ISO/IEC 42001. It does not certify an organization, establish legal compliance, replace an accredited auditor, or guarantee that every applicable control is covered.

## Future Questionnaire And Semantic Review

The current pack uses deterministic checks and latest scan evidence. A planned questionnaire will collect human attestations for controls that need organizational evidence, including approval authority, training completion, vendor review, internal review cadence, incident response exercises, and exception handling.

A planned local-LLM mode can inspect governance documents semantically and produce quoted evidence spans, reviewer prompts, model settings, and decision traces while keeping the analysis local or customer-controlled.

Enterprise compliance packs are expected to add custom controls, centralized attestations, approval history, evidence ownership, and continuous monitoring.

See [compliance-benchmarks.md](compliance-benchmarks.md) for ISO/IEC 42001, NIST AI RMF, and AIUC-1 readiness guidance.
