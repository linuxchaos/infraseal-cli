package taubyte

import (
	"context"
	"strings"
	"testing"

	"github.com/linuxchaos/infraseal-cli/internal/scanners"
)

func TestProviderReportsUnavailableUntilIntegrationIsConfigured(t *testing.T) {
	provider := Provider{}
	status := provider.Status(context.Background())
	if status.Available {
		t.Fatalf("expected Taubyte provider to be unavailable by default")
	}
	_, err := provider.Execute(context.Background(), []scanners.Scanner{}, scanners.Input{})
	if err == nil || !strings.Contains(err.Error(), "not yet available") {
		t.Fatalf("expected explicit unavailable error, got %v", err)
	}
}
