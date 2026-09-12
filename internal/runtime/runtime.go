package runtime

import (
	"context"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type Status struct {
	Name        string
	Available   bool
	Description string
	Detail      string
}

type Provider interface {
	Name() string
	DisplayName() string
	Status(context.Context) Status
	Execute(context.Context, []scanners.Scanner, scanners.Input) ([]schema.ToolResult, error)
}

type Resolver struct {
	Providers map[string]Provider
}

func (r Resolver) Resolve(ctx context.Context, preferred, fallback string) (Provider, bool) {
	if provider, ok := r.Providers[preferred]; ok && provider.Status(ctx).Available {
		return provider, false
	}
	if provider, ok := r.Providers[fallback]; ok && provider.Status(ctx).Available {
		return provider, true
	}
	return nil, false
}

func DisabledResult(scanner scanners.Scanner, cfg config.Config) schema.ToolResult {
	status := scanner.IsAvailable(context.Background(), cfg)
	return schema.ToolResult{Name: scanner.Name(), DisplayName: scanners.PublicName(scanner.Name()), Status: status.Status, Mode: "disabled", Detail: status.Detail}
}
