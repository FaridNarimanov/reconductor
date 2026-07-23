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

// Httpx probes for live HTTP(S) hosts and does an initial tech-detect using
// `httpx -silent -json -tech-detect -status-code -title`, fed the subdomain
// (or target) list on stdin.
type Httpx struct{}

func (Httpx) Name() string  { return "httpx" }
func (Httpx) Title() string { return "Live host detection + tech-detect (httpx)" }

func (Httpx) Enabled(cfg *config.Config, st *model.State) bool { return true }

// httpxLine mirrors the subset of httpx's JSON output that we consume.
type httpxLine struct {
	Input      string   `json:"input"`
	URL        string   `json:"url"`
	Host       string   `json:"host"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver"`
	Tech       []string `json:"tech"`
}

func (Httpx) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	// Prefer "httpx-toolkit": on Kali that is the ProjectDiscovery binary, while
	// plain "httpx" is the unrelated Python HTTP client. On other systems only
	// "httpx" exists (the ProjectDiscovery one) and is used.
	bin, ok := resolveTool("httpx-toolkit", "httpx")
	if !ok {
		return errMissingBinary("httpx")
	}

	// Choose inputs: discovered subdomains for a domain target, otherwise the
	// concrete target hosts (single IP or CIDR expansion).
	var inputs []string
	if st.Target.Kind == model.TargetDomain && len(st.Subdomains) > 0 {
		inputs = st.Subdomains
	} else {
		inputs = st.Target.Hosts
	}
	if len(inputs) == 0 {
		rep.Status("no inputs to probe")
		return nil
	}

	threads := cfg.Threads
	if threads < 1 {
		threads = 20
	}

	stdin := strings.Join(inputs, "\n") + "\n"
	err := runLines(ctx, stdin, func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			return
		}
		var h httpxLine
		if json.Unmarshal([]byte(line), &h) != nil {
			return
		}
		st.AddLiveHost(model.LiveHost{
			Input:      h.Input,
			URL:        h.URL,
			Host:       h.Host,
			StatusCode: h.StatusCode,
			Title:      h.Title,
			WebServer:  h.WebServer,
			Tech:       h.Tech,
		})
	}, bin, "-silent", "-json", "-tech-detect", "-status-code", "-title",
		"-threads", strconv.Itoa(threads))

	rep.Status("%d live hosts", len(st.LiveHosts))
	return err
}
