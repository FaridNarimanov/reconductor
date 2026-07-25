package modules

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// Naabu performs fast port discovery via `naabu -silent -json`. Default scans
// the top 1000 ports; --aggressive scans the full range (-p -).
type Naabu struct{}

func (Naabu) Name() string  { return "naabu" }
func (Naabu) Title() string { return "Fast port discovery (naabu)" }

func (Naabu) Enabled(cfg *config.Config, st *model.State) bool { return true }

// naabuLine tolerates both the flat and nested "port" shapes across naabu
// versions by decoding port lazily.
type naabuLine struct {
	Host string          `json:"host"`
	IP   string          `json:"ip"`
	Port json.RawMessage `json:"port"`
}

func (Naabu) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	if !binaryAvailable("naabu") {
		return errMissingBinary("naabu")
	}

	hosts := naabuTargets(st)
	if len(hosts) == 0 {
		rep.Status("no hosts to scan")
		return nil
	}

	args := []string{"-silent", "-json"}
	if cfg.Aggressive {
		args = append(args, "-p", "-")
	} else {
		args = append(args, "-top-ports", "1000")
	}
	if cfg.Threads > 0 {
		args = append(args, "-c", strconv.Itoa(cfg.Threads))
	}

	stdin := strings.Join(hosts, "\n") + "\n"
	count := 0
	err := runLines(ctx, stdin, func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			return
		}
		var n naabuLine
		if json.Unmarshal([]byte(line), &n) != nil {
			return
		}
		port := parsePort(n.Port)
		if port == 0 {
			return
		}
		key := n.Host
		if key == "" {
			key = n.IP
		}
		st.AddOpenPort(key, port)
		count++
	}, "naabu", args...)

	rep.Status("%d open ports across %d hosts", count, len(st.OpenPorts))
	return err
}

// naabuTargets prefers hosts confirmed live by httpx, falling back to the
// original target hosts / subdomains.
func naabuTargets(st *model.State) []string {
	seen := map[string]bool{}
	var hosts []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	for _, lh := range st.LiveHosts {
		add(lh.Host)
	}
	if len(hosts) == 0 {
		if st.Target.Kind == model.TargetDomain {
			for _, s := range st.Subdomains {
				add(s)
			}
		}
		for _, h := range st.Target.Hosts {
			add(h)
		}
	}
	return hosts
}

// parsePort extracts a port number from either an integer or a nested object.
func parsePort(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var i int
	if json.Unmarshal(raw, &i) == nil {
		return i
	}
	var obj struct {
		Port  int `json:"Port"`
		Port2 int `json:"port"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		if obj.Port != 0 {
			return obj.Port
		}
		return obj.Port2
	}
	return 0
}
