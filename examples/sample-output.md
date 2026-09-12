# Sample Output

Abbreviated output from the bundled sample:

```text
InfraSeal AI Assurance

Project:      rag-support-agent
Workload:     rag-agent
Profile:      full
Targets:      prompts, app, exports, infra, .infraseal/agent-skills
Runtime:      local
Trust Score:  0/100
Decision:     FAIL

Assurance Domains
  Security            45%  NEEDS-ATTENTION 3 correlated finding(s) require review.
  Grounding           70%  NEEDS-ATTENTION 2 correlated finding(s) require review.
  Privacy            100%  PASS            No blocking gaps detected in this domain.
  Agent Safety       100%  PASS            No blocking gaps detected in this domain.
  Code Security       37%  NEEDS-ATTENTION 4 correlated finding(s) require review.
  Governance          85%  PASS            1 correlated finding(s) require review.

Findings
  CRITICAL Security         Data access without tenant filter - cross-tenant access risk
  CRITICAL Code Security    Terraform plan exposes inbound access to the internet
  HIGH     Grounding        unsupported 90-day refund claim
  HIGH     Security         prompt injection disclosure
  HIGH     Grounding        Unsupported production chatbot claim detected: 90-day unconditional refund
  HIGH     Code Security    Terraform plan makes a database publicly accessible
  HIGH     Governance       Terraform plan disables database storage encryption
  HIGH     Security         Terraform plan contains a secret-like literal value
  HIGH     Code Security    Terraform plan includes wildcard IAM policy access
  MEDIUM   Code Security    G304 Potential file inclusion via variable

Evaluation Coverage: MCPvia native active; 6 real, 1 native, 3 missing, 1 disabled, 0 errors

Reports
  csv: .infraseal/reports/scan-<timestamp>.csv
  html: .infraseal/reports/scan-<timestamp>.html
  json: .infraseal/reports/scan-<timestamp>.json
  markdown: .infraseal/reports/scan-<timestamp>.md
  pdf: .infraseal/reports/scan-<timestamp>.pdf
```

Readiness output:

```text
InfraSeal AI Governance Readiness

Overall Readiness: 93%
Status: NEEDS-ATTENTION

Clause 4 - Context
  PASS  100%

Clause 5 - Leadership
  PASS  100%

Clause 6 - Planning
  PASS  100%

Clause 7 - Support
  PASS  100%

Clause 8 - Operation
  PASS  85%
  WARN  High or critical operational findings are present in latest scan evidence

Clause 9 - Performance Evaluation
  PASS  80%
  WARN  Latest scan evidence contains high or critical measurement findings

Clause 10 - Improvement
  PASS  90%
  WARN  Critical findings remain open in latest scan evidence
```
