package config

import "testing"

func TestParseShortAndLong(t *testing.T) {
	c1, err := Parse([]string{"-d", "example.com"})
	if err != nil || c1.Domain != "example.com" {
		t.Fatalf("-d: cfg=%+v err=%v", c1, err)
	}
	c2, err := Parse([]string{"--domain", "x.com"})
	if err != nil || c2.Domain != "x.com" {
		t.Fatalf("--domain: cfg=%+v err=%v", c2, err)
	}
}

func TestParseNoTarget(t *testing.T) {
	if _, err := Parse([]string{}); err == nil {
		t.Fatal("expected error when no target is given")
	}
}

func TestParseMultipleTargets(t *testing.T) {
	if _, err := Parse([]string{"-d", "a.com", "-i", "1.2.3.4"}); err == nil {
		t.Fatal("expected error when multiple targets are given")
	}
}

func TestParseSkipRepeatable(t *testing.T) {
	c, err := Parse([]string{"-d", "a.com", "--skip", "httpx", "--skip", "Naabu"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.IsSkipped("httpx") || !c.IsSkipped("naabu") {
		t.Errorf("skip map = %v", c.Skip)
	}
	if c.IsSkipped("nmap") {
		t.Error("nmap should not be skipped")
	}
}

func TestParseThreadsAndFlags(t *testing.T) {
	c, err := Parse([]string{"-i", "1.2.3.4", "-t", "50", "--aggressive", "-v"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Threads != 50 {
		t.Errorf("threads = %d, want 50", c.Threads)
	}
	if !c.Aggressive {
		t.Error("aggressive should be true")
	}
	if !c.Verbose {
		t.Error("verbose should be true")
	}
}

func TestParseThreadsFloor(t *testing.T) {
	c, err := Parse([]string{"-d", "a.com", "-t", "0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Threads < 1 {
		t.Errorf("threads should be clamped to >=1, got %d", c.Threads)
	}
}
