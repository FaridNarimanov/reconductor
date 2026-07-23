// Command reconductor is an all-in-one recon aggregator that orchestrates
// several popular open-source tools (subfinder, httpx, naabu, nmap, whatweb,
// feroxbuster) into a single pipeline.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/modules"
	"reconductor/internal/orchestrator"
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

	color := useColor(cfg)

	// Resolve the target (prompts for CIDR authorization on stdin).
	target, err := scope.Resolve(cfg, os.Stdin, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	outDir, err := prepareOutputDir(cfg, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	st := model.NewState(target)

	modules.SetVerbose(cfg.Verbose)

	banner(target, outDir, cfg)

	// Run the pipeline.
	orch := orchestrator.New(color)
	orch.Run(context.Background(), cfg, st, os.Stdout)

	fmt.Printf("\nScan complete. Output directory: %s\n", outDir)
	return 0
}

// banner prints the run header.
func banner(t model.Target, outDir string, cfg *config.Config) {
	mode := "default (passive/low-impact)"
	if cfg.Aggressive {
		mode = "AGGRESSIVE"
	}
	fmt.Printf("reconductor — target: %s (%s) | mode: %s\n", t.Value, t.Kind, mode)
	fmt.Printf("output: %s\n\n", outDir)
}

// prepareOutputDir resolves and creates the output directory.
func prepareOutputDir(cfg *config.Config, t model.Target) (string, error) {
	dir := cfg.Output
	if dir == "" {
		ts := time.Now().Format("20060102_150405")
		dir = fmt.Sprintf("recon_%s_%s", sanitize(t.Value), ts)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return "", fmt.Errorf("cannot create output dir %q: %w", abs, err)
	}
	return abs, nil
}

var sanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func sanitize(s string) string {
	s = sanitizeRe.ReplaceAllString(s, "_")
	return strings.Trim(s, "_")
}

// useColor decides whether to emit ANSI colors: disabled for --json, when
// NO_COLOR is set, or when stdout is not a terminal.
func useColor(cfg *config.Config) bool {
	if cfg.JSONOnly {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
