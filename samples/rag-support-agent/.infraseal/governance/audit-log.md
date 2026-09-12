# AI Audit Log

Release decisions, approval records, exception records, incidents, change reviews, scan reports, and evidence links are tracked here before deployment. Each entry keeps a named decision owner and remediation status.

| Date | Event | Evidence | Decision |
|---|---|---|---|
| 2026-08-28 | Sample full scan executed with intentionally risky workload data. | `.infraseal/reports/latest.json` | Demo remains blocked until hallucination, Terraform, and code findings are remediated. |
| 2026-08-28 | Governance evidence templates completed for sample purposes. | `.infraseal/governance/` | Non-technical control evidence is demonstrable, but technical findings remain unresolved. |
| 2026-09-12 | Change review opened for risky agent skill and public infrastructure findings. | `.infraseal/reports/latest-scan.json` | Approval is withheld; exception would require Support Platform Owner and AppSec sign-off with expiration. |
