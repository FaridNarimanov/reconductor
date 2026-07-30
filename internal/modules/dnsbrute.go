package modules

import (
	"context"
	"net"
	"sync"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// DNSBrute performs active subdomain brute-forcing against the target domain
// using a compact built-in prefix list. It runs only in --aggressive mode (it
// generates active DNS traffic) and complements passive subfinder results.
type DNSBrute struct{}

func (DNSBrute) Name() string  { return "dnsbrute" }
func (DNSBrute) Title() string { return "Active DNS subdomain brute-force" }

// Enabled: domain targets in aggressive mode only.
func (DNSBrute) Enabled(cfg *config.Config, st *model.State) bool {
	return st.Target.Kind == model.TargetDomain && cfg.Aggressive
}

// commonPrefixes is a small, high-signal built-in wordlist so the module needs
// no external file to function.
var commonPrefixes = []string{
	"www", "mail", "remote", "webmail", "server", "ns1", "ns2", "smtp", "secure",
	"vpn", "api", "dev", "staging", "test", "portal", "admin", "gitlab", "git",
	"jenkins", "jira", "confluence", "docs", "cdn", "assets", "static", "img",
	"blog", "shop", "store", "app", "apps", "mobile", "m", "beta", "demo",
	"dashboard", "internal", "intranet", "corp", "ftp", "sftp", "proxy", "gw",
	"autodiscover", "owa", "exchange", "lync", "sip", "ldap", "dc", "ad",
}

func (DNSBrute) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	domain := st.Target.Value

	workers := cfg.Threads
	if workers < 1 {
		workers = 20
	}

	jobs := make(chan string)
	var mu sync.Mutex
	var found []string
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if ctx.Err() != nil {
					return
				}
				if _, err := net.LookupHost(host); err == nil {
					mu.Lock()
					found = append(found, host)
					mu.Unlock()
				}
			}
		}()
	}

	for _, p := range commonPrefixes {
		select {
		case <-ctx.Done():
			// Stop feeding jobs if the module was interrupted.
			goto drain
		case jobs <- p + "." + domain:
		}
	}
drain:
	close(jobs)
	wg.Wait()

	st.AddSubdomains(found)
	rep.Status("%d subdomains resolved via brute-force", len(found))
	return ctx.Err()
}
