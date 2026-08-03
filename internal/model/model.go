// Package model defines the shared data structures that flow through the recon
// pipeline. Every module reads from and writes to a single *State value which is
// serialized into the final report at the end of the run.
package model

import (
	"sync"
	"time"
)

// TargetKind describes what kind of target the user supplied.
type TargetKind string

const (
	TargetDomain TargetKind = "domain"
	TargetIP     TargetKind = "ip"
	TargetCIDR   TargetKind = "cidr"
)

// Target is the normalized scan target derived from the CLI flags.
type Target struct {
	Kind TargetKind `json:"kind"`
	// Value is the raw user input (domain name, IP, or CIDR string).
	Value string `json:"value"`
	// Hosts is the concrete list of hosts to work with.
	Hosts []string `json:"hosts"`
}

// LiveHost is a host that responded on HTTP(S), as reported by httpx.
type LiveHost struct {
	Input      string   `json:"input"`
	URL        string   `json:"url"`
	Host       string   `json:"host"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver,omitempty"`
	Tech       []string `json:"tech,omitempty"`
}

// Service is a single open port with service/version detail from nmap.
type Service struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Name     string `json:"name,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

// WebTechFinding holds the deep fingerprint output for a single web host.
type WebTechFinding struct {
	URL     string `json:"url"`
	Summary string `json:"summary"`
}

// ContentFinding is a single URL/path discovered by content discovery.
type ContentFinding struct {
	URL           string `json:"url"`
	Status        int    `json:"status"`
	ContentLength int64  `json:"content_length"`
}

// ModuleError records a non-fatal failure so the run can continue and still
// surface what went wrong in the final report.
type ModuleError struct {
	Module string `json:"module"`
	Err    string `json:"error"`
}

// Skipped records a module or data source that was intentionally not run.
type Skipped struct {
	Module string `json:"module"`
	Reason string `json:"reason"`
}

// RealIPFinding is a candidate origin IP discovered behind a CDN/WAF.
type RealIPFinding struct {
	IP        string `json:"ip"`
	Technique string `json:"technique"`
	Detail    string `json:"detail"`
}

// SRVRecord is a single DNS SRV answer used for AD detection.
type SRVRecord struct {
	Query  string `json:"query"`
	Target string `json:"target"`
	Port   uint16 `json:"port"`
}

// ADResult holds Active Directory detection and (aggressive) recon output.
type ADResult struct {
	Detected          bool        `json:"detected"`
	DomainControllers []string    `json:"domain_controllers,omitempty"`
	SRVRecords        []SRVRecord `json:"srv_records,omitempty"`
	NamingContexts    []string    `json:"naming_contexts,omitempty"`
	SMBShares         []string    `json:"smb_shares,omitempty"`
	ValidUsers        []string    `json:"valid_users,omitempty"`
}

// State is the single mutable object shared across the whole pipeline. All
// mutating helpers are guarded by a mutex so modules may run concurrently.
type State struct {
	mu sync.Mutex

	Target    Target    `json:"target"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`

	Subdomains []string         `json:"subdomains"`
	LiveHosts  []LiveHost       `json:"live_hosts"`
	OpenPorts  map[string][]int `json:"open_ports"`
	Services   []Service        `json:"services"`
	WebTech    []WebTechFinding `json:"web_tech"`
	Content    []ContentFinding `json:"content"`

	RealIPs []RealIPFinding `json:"real_ips"`
	AD      ADResult        `json:"active_directory"`

	Errors []ModuleError `json:"errors"`
	Skips  []Skipped     `json:"skipped"`
}

// NewState returns an initialized State for the given target.
func NewState(t Target) *State {
	return &State{
		Target:    t,
		StartedAt: time.Now(),
		OpenPorts: make(map[string][]int),
	}
}

// AddSubdomains merges newly discovered subdomains, de-duplicating.
func (s *State) AddSubdomains(subs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]bool, len(s.Subdomains))
	for _, x := range s.Subdomains {
		seen[x] = true
	}
	for _, x := range subs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		s.Subdomains = append(s.Subdomains, x)
	}
}

// AddLiveHost appends a live host discovered by httpx.
func (s *State) AddLiveHost(h LiveHost) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LiveHosts = append(s.LiveHosts, h)
}

// AddOpenPort records an open port for a host.
func (s *State) AddOpenPort(host string, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.OpenPorts[host] {
		if p == port {
			return
		}
	}
	s.OpenPorts[host] = append(s.OpenPorts[host], port)
}

// AddService appends an nmap service result.
func (s *State) AddService(svc Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Services = append(s.Services, svc)
}

// AddWebTech appends a deep web fingerprint result.
func (s *State) AddWebTech(w WebTechFinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.WebTech = append(s.WebTech, w)
}

// AddContent appends a content-discovery finding.
func (s *State) AddContent(c ContentFinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Content = append(s.Content, c)
}

// AddRealIP records a candidate origin IP, de-duplicating on IP+technique.
func (s *State) AddRealIP(f RealIPFinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.RealIPs {
		if x.IP == f.IP && x.Technique == f.Technique {
			return
		}
	}
	s.RealIPs = append(s.RealIPs, f)
}

// SubdomainsCopy returns a copy of the discovered subdomains.
func (s *State) SubdomainsCopy() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.Subdomains))
	copy(out, s.Subdomains)
	return out
}

// SetAD stores the Active Directory result.
func (s *State) SetAD(ad ADResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AD = ad
}

// ADSnapshot returns a copy of the current AD result for read-only use by later
// modules (e.g. Kerberos enumeration needs the discovered domain controllers).
func (s *State) ADSnapshot() ADResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.AD
}

// AddADUsers merges Kerberos-validated usernames into the AD result.
func (s *State) AddADUsers(users []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]bool, len(s.AD.ValidUsers))
	for _, u := range s.AD.ValidUsers {
		seen[u] = true
	}
	for _, u := range users {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		s.AD.ValidUsers = append(s.AD.ValidUsers, u)
	}
}

// AddError records a non-fatal module error.
func (s *State) AddError(module string, err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Errors = append(s.Errors, ModuleError{Module: module, Err: err.Error()})
}

// AddSkip records a skipped module/source with a human-readable reason.
func (s *State) AddSkip(module, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Skips = append(s.Skips, Skipped{Module: module, Reason: reason})
}

// WebHosts returns the URLs of every live web host (used by whatweb/feroxbuster).
func (s *State) WebHosts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.LiveHosts))
	for _, h := range s.LiveHosts {
		if h.URL != "" {
			out = append(out, h.URL)
		}
	}
	return out
}
