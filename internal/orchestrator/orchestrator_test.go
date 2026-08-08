package orchestrator

import (
	"testing"

	"reconductor/internal/config"
	"reconductor/internal/model"
)

// activeNames returns the names of the modules that would run for the given
// config and target kind.
func activeNames(cfg *config.Config, kind model.TargetKind) map[string]bool {
	o := New(false)
	st := model.NewState(model.Target{Kind: kind, Value: "example.com"})
	names := map[string]bool{}
	for _, m := range o.activeModules(cfg, st) {
		names[m.Name()] = true
	}
	return names
}

func TestActiveModulesDomainDefault(t *testing.T) {
	names := activeNames(&config.Config{Skip: map[string]bool{}}, model.TargetDomain)

	// Domain-scoped modules run; aggressive-only modules do not.
	for _, want := range []string{"subfinder", "httpx", "realip", "ad", "wayback", "buckets"} {
		if !names[want] {
			t.Errorf("expected %q to be active for a domain target", want)
		}
	}
	for _, notWant := range []string{"dnsbrute", "kerberos"} {
		if names[notWant] {
			t.Errorf("%q should not run without --aggressive", notWant)
		}
	}
}

func TestActiveModulesIPExcludesDomainOnly(t *testing.T) {
	names := activeNames(&config.Config{Skip: map[string]bool{}}, model.TargetIP)

	// Domain-only modules must be excluded for an IP target.
	for _, notWant := range []string{"subfinder", "realip", "ad", "wayback", "buckets"} {
		if names[notWant] {
			t.Errorf("%q should not run for an IP target", notWant)
		}
	}
	// Host-oriented modules still run.
	for _, want := range []string{"httpx", "naabu", "nmap"} {
		if !names[want] {
			t.Errorf("expected %q to be active for an IP target", want)
		}
	}
}

func TestActiveModulesAggressiveEnablesExtras(t *testing.T) {
	cfg := &config.Config{Aggressive: true, Skip: map[string]bool{}}
	names := activeNames(cfg, model.TargetDomain)
	for _, want := range []string{"dnsbrute", "kerberos"} {
		if !names[want] {
			t.Errorf("expected %q to be active with --aggressive", want)
		}
	}
}

func TestActiveModulesSkip(t *testing.T) {
	cfg := &config.Config{Skip: map[string]bool{"httpx": true, "buckets": true}}
	names := activeNames(cfg, model.TargetDomain)
	if names["httpx"] || names["buckets"] {
		t.Errorf("skipped modules should not be active: %v", names)
	}
	if !names["subfinder"] {
		t.Error("non-skipped module subfinder should still be active")
	}
}
