// Command reconductor is an all-in-one recon aggregator that orchestrates
// several popular open-source tools into a single pipeline.
package main

import (
	"fmt"
	"os"

	"reconductor/internal/config"
	"reconductor/internal/scope"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// Resolve the target (prompts for CIDR authorization on stdin).
	target, err := scope.Resolve(cfg, os.Stdin, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fmt.Printf("target: %s (%s) — %d host(s)\n", target.Value, target.Kind, len(target.Hosts))
	return 0
}
