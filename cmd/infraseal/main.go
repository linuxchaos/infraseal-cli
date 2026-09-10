package main

import (
	"fmt"
	"os"

	"github.com/linuxchaos/infraseal-cli/internal/cli"
)

var version = "0.1.0-dev"

func main() {
	if err := cli.New(version).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
