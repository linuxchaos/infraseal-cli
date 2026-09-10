// Package plugin defines the public adapter contract for future third-party
// InfraSeal evaluators. The CLI MVP uses internal adapters while this package
// keeps the extension boundary independent from the enterprise control plane.
package plugin

import "context"

type Status string

const (
	Available         Status = "available"
	MissingDependency Status = "missing_dependency"
	Mocked            Status = "mocked"
	Disabled          Status = "disabled"
	Error             Status = "error"
)

type Finding struct {
	Severity       string         `json:"severity"`
	Domain         string         `json:"domain"`
	Category       string         `json:"category"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	Evidence       string         `json:"evidence"`
	Recommendation string         `json:"recommendation"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type Input struct {
	ProjectRoot string
	Profile     string
	Evidence    []string
	TestCases   []string
	Options     map[string]string
}

type Result struct {
	Status   Status         `json:"status"`
	Mode     string         `json:"mode"`
	Detail   string         `json:"detail"`
	Findings []Finding      `json:"findings"`
	Raw      map[string]any `json:"raw,omitempty"`
}

type Adapter interface {
	Name() string
	DisplayName() string
	Profiles() []string
	Availability(context.Context) (Status, string)
	Evaluate(context.Context, Input) (Result, error)
}
