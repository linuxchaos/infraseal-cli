package registry

import (
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/agentgovernance"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/deepeval"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/giskard"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/gosec"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/govulncheck"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/guard0"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/hallbayes"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/promptfoo"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/ragas"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/skillspector"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/terraform"
)

func Default() []scanners.Scanner {
	return []scanners.Scanner{
		promptfoo.New(),
		giskard.New(),
		ragas.New(),
		deepeval.New(),
		hallbayes.New(),
		skillspector.New(),
		agentgovernance.New(),
		guard0.New(),
		terraform.New(),
		gosec.New(),
		govulncheck.New(),
	}
}
