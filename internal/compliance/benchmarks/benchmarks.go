package benchmarks

import (
	"strings"

	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

const (
	ISO42001URL     = "https://www.iso.org/standard/42001"
	NISTAIRMFURL    = "https://airc.nist.gov/airmf-resources/airmf/5-sec-core/"
	NISTPlaybookURL = "https://airc.nist.gov/airmf-resources/playbook/"
	AIUC1URL        = "https://aiuc.com/research/introducing-aiuc-1"
)

func Annotate(findings []schema.Finding) []schema.Finding {
	annotated := append([]schema.Finding{}, findings...)
	for i := range annotated {
		if len(annotated[i].Benchmarks) == 0 {
			annotated[i].Benchmarks = ReferencesFor(annotated[i].Domain, annotated[i].Category)
		}
	}
	return annotated
}

func ReferencesFor(domain, category string) []schema.ControlReference {
	value := strings.ToLower(domain + " " + category)
	switch {
	case containsAny(value, "ground", "halluc", "rag", "context", "evidence", "faithfulness"):
		return []schema.ControlReference{
			ref("ISO/IEC 42001", "Clause 9; Annex A.6/A.7", "Performance evaluation, AI lifecycle controls, and data/evidence controls", ISO42001URL),
			ref("NIST AI RMF", "MEASURE 2; MAP 4", "Trustworthiness measurement, reliability, validity, and risk context", NISTPlaybookURL),
			ref("AIUC-1", "Reliability", "Hallucination resistance, dependable answers, and reliable tool calls", AIUC1URL),
		}
	case containsAny(value, "pii", "privacy", "credential", "secret", "data-exfiltration", "data-governance"):
		return []schema.ControlReference{
			ref("ISO/IEC 42001", "Annex A.7/A.10", "Data controls, privacy, and third-party/customer information handling", ISO42001URL),
			ref("NIST AI RMF", "GOVERN; MEASURE 2", "Privacy-enhanced trustworthy AI and accountable data-risk management", NISTAIRMFURL),
			ref("AIUC-1", "Data & Privacy", "Protection against data leakage, IP leakage, and unauthorized use of user data", AIUC1URL),
		}
	case containsAny(value, "prompt-injection", "jailbreak", "output-safety", "unsafe"):
		return []schema.ControlReference{
			ref("ISO/IEC 42001", "Clause 8; Annex A.6/A.9", "Operational control, lifecycle safeguards, and responsible use controls", ISO42001URL),
			ref("NIST AI RMF", "MEASURE 2; MANAGE 2", "Safety, security, resilience, and risk treatment", NISTPlaybookURL),
			ref("AIUC-1", "Security/Safety", "Adversarial resistance and prevention of harmful outputs", AIUC1URL),
		}
	case containsAny(value, "agent", "skill", "tool", "human-approval", "decision-trail"):
		return []schema.ControlReference{
			ref("ISO/IEC 42001", "Clause 5; Annex A.3/A.9", "Roles, responsibilities, human oversight, and responsible use", ISO42001URL),
			ref("NIST AI RMF", "GOVERN; MANAGE", "Accountable oversight and risk response for deployed AI systems", NISTAIRMFURL),
			ref("AIUC-1", "Security/Accountability", "Tool authorization, agent boundaries, and auditability", AIUC1URL),
		}
	case containsAny(value, "code", "dependency", "vulnerab", "supply", "runtime", "infrastructure", "iam", "network"):
		return []schema.ControlReference{
			ref("ISO/IEC 42001", "Clause 8; Annex A.6", "Operational planning, secure lifecycle management, and release control", ISO42001URL),
			ref("NIST AI RMF", "MEASURE 2; MANAGE 4", "Secure and resilient system assessment plus risk response", NISTPlaybookURL),
			ref("AIUC-1", "Security", "Protection against exploitable code paths, unsafe tools, and infrastructure exposure", AIUC1URL),
		}
	default:
		return []schema.ControlReference{
			ref("ISO/IEC 42001", "Clauses 4-10", "AI management system governance, planning, operation, evaluation, and improvement", ISO42001URL),
			ref("NIST AI RMF", "GOVERN/MAP/MEASURE/MANAGE", "AI risk management functions across the lifecycle", NISTAIRMFURL),
			ref("AIUC-1", "Accountability", "Ownership, evidence, oversight, and decision traceability", AIUC1URL),
		}
	}
}

func ref(framework, reference, topic, url string) schema.ControlReference {
	return schema.ControlReference{Framework: framework, Reference: reference, Topic: topic, URL: url}
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
