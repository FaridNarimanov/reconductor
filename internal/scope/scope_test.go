package scope

import (
	"bytes"
	"strings"
	"testing"

	"reconductor/internal/config"
	"reconductor/internal/model"
)

func TestExpandCIDR(t *testing.T) {
	tests := []struct {
		cidr    string
		want    []string
		wantErr bool
	}{
		// /30 has 4 addresses; network and broadcast are dropped.
		{"192.168.1.0/30", []string{"192.168.1.1", "192.168.1.2"}, false},
		// /31 has 2 addresses and both are kept (point-to-point link).
		{"10.0.0.0/31", []string{"10.0.0.0", "10.0.0.1"}, false},
		{"not-a-cidr", nil, true},
	}
	for _, tc := range tests {
		got, err := expandCIDR(tc.cidr)
		if tc.wantErr {
			if err == nil {
				t.Errorf("expandCIDR(%q): expected error, got nil", tc.cidr)
			}
			continue
		}
		if err != nil {
			t.Errorf("expandCIDR(%q): unexpected error: %v", tc.cidr, err)
			continue
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("expandCIDR(%q) = %v, want %v", tc.cidr, got, tc.want)
		}
	}
}

func TestExpandCIDRTooLarge(t *testing.T) {
	if _, err := expandCIDR("10.0.0.0/8"); err == nil {
		t.Fatal("expected error for oversized CIDR, got nil")
	}
}

func TestResolveDomain(t *testing.T) {
	cfg := &config.Config{Domain: "example.com"}
	tgt, err := Resolve(cfg, strings.NewReader(""), &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tgt.Kind != model.TargetDomain || tgt.Value != "example.com" {
		t.Errorf("got %+v", tgt)
	}
	if len(tgt.Hosts) != 1 || tgt.Hosts[0] != "example.com" {
		t.Errorf("hosts = %v", tgt.Hosts)
	}
}

func TestResolveIP(t *testing.T) {
	ok := &config.Config{IP: "1.2.3.4"}
	if tgt, err := Resolve(ok, strings.NewReader(""), &bytes.Buffer{}); err != nil || tgt.Kind != model.TargetIP {
		t.Fatalf("valid IP: tgt=%+v err=%v", tgt, err)
	}

	bad := &config.Config{IP: "999.1.1.1"}
	if _, err := Resolve(bad, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestResolveCIDRConfirmation(t *testing.T) {
	cfg := &config.Config{CIDR: "192.168.1.0/30"}

	// "yes" proceeds.
	tgt, err := Resolve(cfg, strings.NewReader("yes\n"), &bytes.Buffer{})
	if err != nil {
		t.Fatalf("expected success on 'yes', got %v", err)
	}
	if tgt.Kind != model.TargetCIDR || len(tgt.Hosts) != 2 {
		t.Errorf("got %+v", tgt)
	}

	// Anything else aborts.
	if _, err := Resolve(cfg, strings.NewReader("no\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("expected abort on 'no'")
	}
	if _, err := Resolve(cfg, strings.NewReader("YES\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("expected abort on 'YES' (only lowercase 'yes' allowed)")
	}
}
