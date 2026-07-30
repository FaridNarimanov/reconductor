// Package orchestrator wires the modules into an ordered pipeline, drives the
// progress UI, and translates Ctrl+C into "skip the current module" (or abort
// on a double press) instead of killing the whole program.
package orchestrator

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/modules"
	"reconductor/internal/progress"
)

// DefaultModules returns the pipeline in execution order. New modules plug in
// here without touching the orchestrator itself.
func DefaultModules() []modules.Module {
	return []modules.Module{
		modules.Subfinder{},
		modules.DNSBrute{}, // aggressive-only; feeds httpx
		modules.Httpx{},
		modules.Naabu{},
		modules.Nmap{},
		modules.WhatWeb{},
		modules.Feroxbuster{},
	}
}

// Orchestrator runs the pipeline for a single target.
type Orchestrator struct {
	mods  []modules.Module
	color bool

	mu        sync.Mutex
	curCancel context.CancelFunc
	lastSig   time.Time
}

// New builds an Orchestrator with the default module set.
func New(color bool) *Orchestrator {
	return &Orchestrator{mods: DefaultModules(), color: color}
}

// activeModules returns the modules that will run (not --skip'd and enabled for
// this target/config), which fixes the total for the [n/total] counter.
func (o *Orchestrator) activeModules(cfg *config.Config, st *model.State) []modules.Module {
	var out []modules.Module
	for _, m := range o.mods {
		if cfg.IsSkipped(m.Name()) {
			st.AddSkip(m.Name(), "disabled via --skip")
			continue
		}
		if !m.Enabled(cfg, st) {
			st.AddSkip(m.Name(), "not applicable for this target")
			continue
		}
		out = append(out, m)
	}
	return out
}

// Run executes the pipeline. Module failures are recorded in st and never abort
// the run; a single Ctrl+C skips the current module, a second within 1.5s
// aborts the remaining pipeline.
func (o *Orchestrator) Run(ctx context.Context, cfg *config.Config, st *model.State, out io.Writer) {
	active := o.activeModules(cfg, st)
	printer := progress.New(out, len(active), o.color)

	// Root context that a double Ctrl+C cancels to abort the whole pipeline.
	runCtx, abort := context.WithCancel(ctx)
	defer abort()

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGINT)
	defer signal.Stop(sigCh)

	go o.handleSignals(sigCh, abort, printer)

	for _, m := range active {
		if runCtx.Err() != nil {
			break
		}
		stage := printer.StartStage(m.Title())

		modCtx, cancel := context.WithCancel(runCtx)
		o.mu.Lock()
		o.curCancel = cancel
		o.mu.Unlock()

		err := m.Run(modCtx, cfg, st, stage)

		o.mu.Lock()
		o.curCancel = nil
		o.mu.Unlock()

		// Determine why the module stopped before releasing modCtx: a cancelled
		// modCtx (or a context.Canceled error) means the user interrupted it.
		interrupted := modCtx.Err() != nil || errors.Is(err, context.Canceled)
		cancel()

		switch {
		case runCtx.Err() != nil:
			// Whole pipeline aborted (double Ctrl+C) while this module ran.
			stage.Skipped("aborted by user")
			st.AddSkip(m.Name(), "aborted by user (Ctrl+C)")
		case interrupted:
			// Single Ctrl+C skipped this module — record and continue.
			stage.Skipped("interrupted by user")
			st.AddSkip(m.Name(), "interrupted by user (Ctrl+C)")
		case err != nil:
			stage.Fail(err)
			st.AddError(m.Name(), err)
		default:
			stage.Done()
		}
	}

	st.EndedAt = time.Now()
}

// handleSignals turns Ctrl+C into skip/abort semantics.
func (o *Orchestrator) handleSignals(sigCh <-chan os.Signal, abort context.CancelFunc, printer *progress.Printer) {
	for range sigCh {
		o.mu.Lock()
		now := time.Now()
		double := !o.lastSig.IsZero() && now.Sub(o.lastSig) < 1500*time.Millisecond
		o.lastSig = now
		cancel := o.curCancel
		o.mu.Unlock()

		if double || cancel == nil {
			printer.Info("\n[!] Aborting pipeline (Ctrl+C)...")
			abort()
			return
		}
		printer.Info("\n[!] Skipping current module (Ctrl+C again to abort)...")
		cancel()
	}
}
