# Evaluator Visibility

InfraSeal uses outcome-first presentation by default.

Primary output shows:

- Trust or readiness score
- Assurance domains
- Governance gaps
- Findings
- Recommendations
- Report paths

It does not lead with third-party tool names. This prevents the user experience from collapsing into a list of scanner exit codes while preserving technical credibility.

Capability provenance is available through:

- `infraseal scanners`
- `infraseal doctor`
- `--include-tool-details`
- JSON `tool_results` using InfraSeal capability labels
- Advanced Markdown/HTML/PDF appendix

These surfaces do not expose backend vendor or project names. The separate `scanner-integrations.md` document is the explicit implementation reference for operators who need dependency setup or troubleshooting.

Every adapter labels execution as real, native, missing dependency, disabled, or error. Missing or disabled optional evaluators do not create findings. The local grounding workflow is labeled native because it reads configured evidence files and exported responses directly; it is deterministic, not a model-judged semantic verifier.
