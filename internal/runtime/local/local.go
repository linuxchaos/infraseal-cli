package local

import (
	"context"
	"sync"

	"github.com/linuxchaos/infraseal-cli/internal/runtime"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type Provider struct {
	Workers int
}

func (Provider) Name() string        { return "local" }
func (Provider) DisplayName() string { return "Local Evaluation Runtime" }
func (Provider) Status(context.Context) runtime.Status {
	return runtime.Status{Name: "local", Available: true, Description: "Executes MCPvia evaluation adapters on this machine.", Detail: "ready"}
}

func (p Provider) Execute(ctx context.Context, adapters []scanners.Scanner, input scanners.Input) ([]schema.ToolResult, error) {
	workers := p.Workers
	if workers <= 0 {
		workers = 4
	}
	type job struct {
		index   int
		scanner scanners.Scanner
	}
	jobs := make(chan job)
	results := make([]schema.ToolResult, len(adapters))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				result, err := item.scanner.Scan(ctx, input)
				if err != nil {
					result = schema.ToolResult{Name: item.scanner.Name(), DisplayName: item.scanner.DisplayName(), Status: scanners.StatusError, Mode: "error", Detail: err.Error()}
				}
				results[item.index] = result
			}
		}()
	}
	for index, adapter := range adapters {
		jobs <- job{index: index, scanner: adapter}
	}
	close(jobs)
	wg.Wait()
	return results, nil
}
