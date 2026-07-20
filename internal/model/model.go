// Package model defines the shared data structures that flow through the recon
// pipeline. Every module reads from and writes to a single *State value.
package model

import "time"

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

// State is the single mutable object shared across the whole pipeline.
type State struct {
	Target    Target    `json:"target"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

// NewState returns an initialized State for the given target.
func NewState(t Target) *State {
	return &State{Target: t, StartedAt: time.Now()}
}
