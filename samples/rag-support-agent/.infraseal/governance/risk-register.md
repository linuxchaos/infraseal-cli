# AI Risk Register

| Risk | Owner | Severity | Treatment | Status |
|---|---|---:|---|---|
| Unsupported refund-policy answer could mislead customers. | Support Platform Owner | High | Add grounded response tests and sample production outputs weekly. | Open |
| Prompt-injection content could attempt to override system policy. | AppSec Reviewer | High | Maintain prompt-injection regression cases and run Prompt & Red-Team evaluation before release. | Active control |
| Terraform plan could expose AI logs or data stores publicly. | Platform Engineer | Critical | Block public ingress, public databases, wildcard IAM, and secret values in plan artifacts. | Open |
