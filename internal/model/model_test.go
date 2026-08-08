package model

import (
	"strings"
	"testing"
)

func newTestState() *State {
	return NewState(Target{Kind: TargetDomain, Value: "example.com"})
}

func TestAddSubdomainsDedup(t *testing.T) {
	s := newTestState()
	s.AddSubdomains([]string{"a.com", "b.com", "a.com", ""})
	s.AddSubdomains([]string{"b.com", "c.com"})
	got := strings.Join(s.Subdomains, ",")
	if got != "a.com,b.com,c.com" {
		t.Errorf("subdomains = %q", got)
	}
}

func TestAddOpenPortDedup(t *testing.T) {
	s := newTestState()
	s.AddOpenPort("h", 80)
	s.AddOpenPort("h", 80)
	s.AddOpenPort("h", 443)
	if len(s.OpenPorts["h"]) != 2 {
		t.Errorf("ports = %v", s.OpenPorts["h"])
	}
}

func TestAddRealIPDedup(t *testing.T) {
	s := newTestState()
	s.AddRealIP(RealIPFinding{IP: "1.2.3.4", Technique: "mx-record"})
	s.AddRealIP(RealIPFinding{IP: "1.2.3.4", Technique: "mx-record"})  // dup
	s.AddRealIP(RealIPFinding{IP: "1.2.3.4", Technique: "spf-record"}) // same IP, diff technique
	if len(s.RealIPs) != 2 {
		t.Errorf("real IPs = %v", s.RealIPs)
	}
}

func TestWebHosts(t *testing.T) {
	s := newTestState()
	s.AddLiveHost(LiveHost{Host: "a", URL: "http://a"})
	s.AddLiveHost(LiveHost{Host: "b", URL: ""}) // no URL, excluded
	hosts := s.WebHosts()
	if len(hosts) != 1 || hosts[0] != "http://a" {
		t.Errorf("web hosts = %v", hosts)
	}
}

func TestAddADUsersDedup(t *testing.T) {
	s := newTestState()
	s.AddADUsers([]string{"admin", "guest", "admin", ""})
	s.AddADUsers([]string{"guest", "svc"})
	if strings.Join(s.AD.ValidUsers, ",") != "admin,guest,svc" {
		t.Errorf("valid users = %v", s.AD.ValidUsers)
	}
}
