package modules

import (
	"context"
	"encoding/xml"
	"sort"
	"strconv"
	"strings"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// Nmap runs deep service/version detection only against the ports naabu
// reported open (`nmap -sV -p <ports> -oX -`), avoiding a full-range scan on
// every host. --aggressive scans the full port range (-p-) instead.
type Nmap struct{}

func (Nmap) Name() string  { return "nmap" }
func (Nmap) Title() string { return "Deep service analysis (nmap)" }

func (Nmap) Enabled(cfg *config.Config, st *model.State) bool { return true }

// XML structures for parsing `nmap -oX -` output.
type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}
type nmapHost struct {
	Addresses []nmapAddr `xml:"address"`
	Ports     []nmapPort `xml:"ports>port"`
}
type nmapAddr struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}
type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}
type nmapState struct {
	State string `xml:"state,attr"`
}
type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func (Nmap) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	if !binaryAvailable("nmap") {
		return errMissingBinary("nmap")
	}

	// Build the per-host port spec from naabu results.
	targets := map[string]string{} // host -> comma-separated port list ("" means full range)

	if len(st.OpenPorts) > 0 {
		for host, ports := range st.OpenPorts {
			if cfg.Aggressive {
				targets[host] = "" // full range regardless of naabu findings
			} else {
				targets[host] = joinPorts(ports)
			}
		}
	} else if cfg.Aggressive {
		// No naabu data but aggressive: full-range scan of the target hosts.
		for _, h := range hostsForNmap(st) {
			targets[h] = ""
		}
	}

	if len(targets) == 0 {
		rep.Status("no open ports from naabu; nothing to analyze")
		return nil
	}

	var firstErr error
	scanned := 0
	for host, portspec := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		args := []string{"-sV", "-oX", "-"}
		if portspec == "" {
			args = append(args, "-p-")
		} else {
			args = append(args, "-p", portspec)
		}
		args = append(args, host)

		out, err := runCapture(ctx, "", "nmap", args...)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		parseNmap(out, host, st)
		scanned++
		rep.Status("scanned %s (%d/%d hosts)", host, scanned, len(targets))
	}

	rep.Status("%d services identified", len(st.Services))
	return firstErr
}

func parseNmap(xmlOut, fallbackHost string, st *model.State) {
	var run nmapRun
	if xml.Unmarshal([]byte(xmlOut), &run) != nil {
		return
	}
	for _, h := range run.Hosts {
		host := fallbackHost
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				host = a.Addr
			}
		}
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			st.AddService(model.Service{
				Host:     host,
				Port:     p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
				Name:     p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
			})
		}
	}
}

func joinPorts(ports []int) string {
	sort.Ints(ports)
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

func hostsForNmap(st *model.State) []string {
	seen := map[string]bool{}
	var out []string
	for _, lh := range st.LiveHosts {
		if lh.Host != "" && !seen[lh.Host] {
			seen[lh.Host] = true
			out = append(out, lh.Host)
		}
	}
	if len(out) == 0 {
		out = append(out, st.Target.Hosts...)
	}
	return out
}
