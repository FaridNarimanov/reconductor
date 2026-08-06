// Package report renders the final scan results: a structured JSON file, a
// LinPEAS-style HTML report, and a colorized terminal summary table.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"reconductor/internal/model"
)

// WriteJSON serializes the full state to report.json in dir.
func WriteJSON(st *model.State, dir string) (string, error) {
	path := filepath.Join(dir, "report.json")
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// portsFor returns a sorted, comma-joined open-port string for a host, using
// naabu results and falling back to nmap services.
func portsFor(st *model.State, host string) string {
	set := map[int]bool{}
	for _, p := range st.OpenPorts[host] {
		set[p] = true
	}
	for _, s := range st.Services {
		if s.Host == host {
			set[s.Port] = true
		}
	}
	if len(set) == 0 {
		return "-"
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// techFor returns a compact tech-stack string for a host URL.
func techFor(st *model.State, host string) string {
	for _, lh := range st.LiveHosts {
		if lh.Host == host && len(lh.Tech) > 0 {
			return strings.Join(lh.Tech, ", ")
		}
	}
	return "-"
}

const (
	cReset = "\033[0m"
	cBold  = "\033[1m"
	cCyan  = "\033[36m"
	cGreen = "\033[32m"
	cYell  = "\033[33m"
	cRed   = "\033[31m"
	cGray  = "\033[90m"
)

// PrintSummary writes the colorized terminal summary table.
func PrintSummary(st *model.State, out io.Writer, color bool) {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + cReset
	}

	fmt.Fprintf(out, "\n%s\n", c(cBold+cCyan, "══════════════════════ RECON SUMMARY ══════════════════════"))
	fmt.Fprintf(out, "%s %s  (%s)\n", c(cBold, "Target:"), st.Target.Value, st.Target.Kind)
	dur := st.EndedAt.Sub(st.StartedAt).Round(time.Second)
	fmt.Fprintf(out, "%s %s\n\n", c(cBold, "Duration:"), dur)

	fmt.Fprintf(out, "%s subdomains: %s | live hosts: %s | services: %s | content: %s\n\n",
		c(cBold, "Counts —"),
		c(cGreen, strconv.Itoa(len(st.Subdomains))),
		c(cGreen, strconv.Itoa(len(st.LiveHosts))),
		c(cGreen, strconv.Itoa(len(st.Services))),
		c(cGreen, strconv.Itoa(len(st.Content))),
	)

	if len(st.LiveHosts) > 0 {
		fmt.Fprintf(out, "%s\n", c(cBold, "Live hosts:"))
		fmt.Fprintf(out, "%-40s %-6s %-18s %s\n",
			c(cGray, "HOST"), c(cGray, "CODE"), c(cGray, "PORTS"), c(cGray, "TECH"))
		for _, lh := range st.LiveHosts {
			host := lh.Host
			if host == "" {
				host = lh.URL
			}
			fmt.Fprintf(out, "%-40s %-6s %-18s %s\n",
				truncate(host, 40),
				statusColor(lh.StatusCode, color),
				truncate(portsFor(st, lh.Host), 18),
				truncate(techFor(st, lh.Host), 40),
			)
		}
		fmt.Fprintln(out)
	}

	// Active Directory status.
	if st.Target.Kind == model.TargetDomain {
		if st.AD.Detected {
			fmt.Fprintf(out, "%s %s (DCs: %s)\n",
				c(cBold, "Active Directory:"),
				c(cGreen, "DETECTED"),
				strings.Join(st.AD.DomainControllers, ", "))
			if len(st.AD.SMBShares) > 0 {
				fmt.Fprintf(out, "  SMB shares: %s\n", strings.Join(st.AD.SMBShares, ", "))
			}
			if len(st.AD.ValidUsers) > 0 {
				fmt.Fprintf(out, "  %s %s\n", c(cGreen, "Valid users:"), strings.Join(st.AD.ValidUsers, ", "))
			}
			fmt.Fprintln(out)
		} else {
			fmt.Fprintf(out, "%s %s\n\n", c(cBold, "Active Directory:"), c(cGray, "not detected"))
		}
	}

	if len(st.RealIPs) > 0 {
		fmt.Fprintf(out, "%s\n", c(cBold, "Origin IP candidates:"))
		for _, r := range st.RealIPs {
			fmt.Fprintf(out, "  %s %-15s %s %s\n", c(cGreen, "•"), r.IP,
				c(cGray, "["+r.Technique+"]"), r.Detail)
		}
		fmt.Fprintln(out)
	}

	if len(st.WAF) > 0 {
		fmt.Fprintf(out, "%s\n", c(cBold, "WAF/CDN:"))
		for _, w := range st.WAF {
			fmt.Fprintf(out, "  %s %-18s %s\n", c(cYell, "▲"), w.Vendor, c(cGray, w.URL))
		}
		fmt.Fprintln(out)
	}

	if len(st.Buckets) > 0 {
		fmt.Fprintf(out, "%s\n", c(cBold, "Cloud buckets:"))
		for _, b := range st.Buckets {
			tag := "private(403)"
			if b.Accessible {
				tag = "PUBLIC(200)"
			}
			fmt.Fprintf(out, "  %s %s %s\n", c(cGreen, "•"), c(cCyan, tag), b.URL)
		}
		fmt.Fprintln(out)
	}

	// Compact counters for the higher-volume modules.
	if len(st.Wayback) > 0 || len(st.Robots) > 0 || len(st.JS) > 0 {
		fmt.Fprintf(out, "%s wayback URLs: %s | robots/sitemap paths: %s | JS files with endpoints: %s\n\n",
			c(cBold, "Extra —"),
			c(cGreen, strconv.Itoa(len(st.Wayback))),
			c(cGreen, strconv.Itoa(len(st.Robots))),
			c(cGreen, strconv.Itoa(len(st.JS))),
		)
	}

	if len(st.Skips) > 0 {
		fmt.Fprintf(out, "%s\n", c(cYell, "Skipped:"))
		for _, s := range st.Skips {
			fmt.Fprintf(out, "  %s %s — %s\n", c(cYell, "○"), s.Module, s.Reason)
		}
		fmt.Fprintln(out)
	}

	if len(st.Errors) > 0 {
		fmt.Fprintf(out, "%s\n", c(cRed, "Errors:"))
		for _, e := range st.Errors {
			fmt.Fprintf(out, "  %s %s: %s\n", c(cRed, "✗"), e.Module, e.Err)
		}
		fmt.Fprintln(out)
	}
}

func statusColor(code int, color bool) string {
	s := strconv.Itoa(code)
	if code == 0 {
		s = "-"
	}
	if !color {
		return s
	}
	switch {
	case code >= 200 && code < 300:
		return cGreen + s + cReset
	case code >= 300 && code < 400:
		return cCyan + s + cReset
	case code >= 400:
		return cYell + s + cReset
	default:
		return s
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
