// Package report exposes stable aliases for consumers that want to ingest
// InfraSeal CLI assessment documents without depending on command internals.
package report

import "github.com/linuxchaos/infraseal-cli/internal/schema"

type Finding = schema.Finding
type Recommendation = schema.Recommendation
type DomainScore = schema.DomainScore
type ToolResult = schema.ToolResult
type ScanResult = schema.ScanResult
type ReadinessCategory = schema.ReadinessCategory
type ControlReference = schema.ControlReference
type ComplianceResult = schema.ComplianceResult
type StoredResult = schema.StoredResult
