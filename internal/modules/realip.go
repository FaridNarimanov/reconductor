package modules

import (
	"context"
	"encoding/json"
	"net"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// RealIP tries to uncover origin IPs hidden behind a CDN/WAF using only
// key-free sources: Certificate Transparency (crt.sh), comparison of subdomain
// A records against Cloudflare's public IP ranges, and MX/SPF analysis. Shodan
// and Censys are used only if their API keys are present in the environment.
type RealIP struct{}

func (RealIP) Name() string  { return "realip" }
func (RealIP) Title() string { return "Real-IP discovery (CDN bypass)" }

func (RealIP) Enabled(cfg *config.Config, st *model.State) bool {
	return st.Target.Kind == model.TargetDomain
}

const (
	crtShURL     = "https://crt.sh/?q=%s&output=json"
	cloudflareV4 = "https://www.cloudflare.com/ips-v4"
)

func (RealIP) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	domain := st.Target.Value

	// 1) crt.sh — historical certificate subdomains (also enriches subdomains).
	names := fetchCrtSh(ctx, domain, rep)
	if len(names) > 0 {
		st.AddSubdomains(names)
		rep.Status("crt.sh: %d certificate names", len(names))
	}

	// 2) Non-proxied subdomain check against Cloudflare ranges.
	cfRanges := fetchCloudflareRanges(ctx)
	candidates := unique(append(st.SubdomainsCopy(), names...))
	checked := 0
	for _, host := range candidates {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ips, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		checked++
		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.To4() == nil {
				continue
			}
			if inRanges(parsed, cfRanges) {
				continue // proxied by Cloudflare — not an origin candidate
			}
			st.AddRealIP(model.RealIPFinding{
				IP:        ip,
				Technique: "non-proxied-subdomain",
				Detail:    host,
			})
		}
	}
	rep.Status("resolved %d hosts, %d origin candidates so far", checked, len(st.RealIPs))

	// 3) MX records — mail infra is usually not behind the web CDN.
	if mxs, err := net.LookupMX(domain); err == nil {
		for _, mx := range mxs {
			host := strings.TrimSuffix(mx.Host, ".")
			if ips, err := net.LookupHost(host); err == nil {
				for _, ip := range ips {
					if net.ParseIP(ip).To4() == nil {
						continue
					}
					st.AddRealIP(model.RealIPFinding{IP: ip, Technique: "mx-record", Detail: host})
				}
			}
		}
	}

	// 4) SPF ip4: entries from TXT records.
	if txts, err := net.LookupTXT(domain); err == nil {
		for _, txt := range txts {
			for _, ip := range parseSPFIPs(txt) {
				st.AddRealIP(model.RealIPFinding{IP: ip, Technique: "spf-record", Detail: "v=spf1"})
			}
		}
	}

	// 5) Optional key-gated sources: used only when their env vars are present.
	queryShodan(ctx, domain, st, rep)
	queryCensys(ctx, domain, st, rep)

	rep.Status("%d origin IP candidate(s)", len(st.RealIPs))
	return nil
}

// crtShEntry is one record from the crt.sh JSON output.
type crtShEntry struct {
	NameValue string `json:"name_value"`
}

func fetchCrtSh(ctx context.Context, domain string, rep progress.Reporter) []string {
	url := strings.Replace(crtShURL, "%s", "%25."+domain, 1)
	// crt.sh can be very slow under load; give it a generous timeout.
	status, _, body, err := httpGetT(ctx, url, 45*time.Second)
	if err != nil || status != 200 || len(body) == 0 {
		return nil
	}
	var entries []crtShEntry
	if json.Unmarshal(body, &entries) != nil {
		return nil
	}
	set := map[string]bool{}
	for _, e := range entries {
		for _, n := range strings.Split(e.NameValue, "\n") {
			n = strings.TrimSpace(strings.ToLower(n))
			n = strings.TrimPrefix(n, "*.")
			if n != "" && !strings.ContainsAny(n, " *") && strings.HasSuffix(n, domain) {
				set[n] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	return out
}

// fetchCloudflareRanges downloads Cloudflare's published IPv4 ranges. On failure
// it returns nil (all IPs then count as origin candidates).
func fetchCloudflareRanges(ctx context.Context) []*net.IPNet {
	status, _, body, err := httpGet(ctx, cloudflareV4)
	if err != nil || status != 200 {
		return nil
	}
	var nets []*net.IPNet
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(line); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func inRanges(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseSPFIPs extracts ip4:<addr>[/mask] entries from an SPF TXT record.
func parseSPFIPs(txt string) []string {
	if !strings.Contains(txt, "v=spf1") {
		return nil
	}
	var ips []string
	for _, field := range strings.Fields(txt) {
		if v, ok := strings.CutPrefix(field, "ip4:"); ok {
			ip := v
			if i := strings.IndexByte(ip, '/'); i >= 0 {
				ip = ip[:i]
			}
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

// queryShodan searches Shodan for hosts serving a certificate for the domain,
// yielding origin IP candidates. It runs only when SHODAN_API_KEY is set.
func queryShodan(ctx context.Context, domain string, st *model.State, rep progress.Reporter) {
	key := os.Getenv("SHODAN_API_KEY")
	if key == "" {
		st.AddSkip("shodan", "Shodan lookup — no API key found (set SHODAN_API_KEY to enable)")
		return
	}
	rep.Status("querying Shodan...")
	url := "https://api.shodan.io/shodan/host/search?key=" + key +
		"&query=" + neturl.QueryEscape("ssl.cert.subject.CN:"+domain)
	status, _, body, err := httpGetT(ctx, url, 30*time.Second)
	if err != nil || status != 200 {
		st.AddError("shodan", errStatus("shodan", status, err))
		return
	}
	var res struct {
		Matches []struct {
			IPStr string `json:"ip_str"`
		} `json:"matches"`
	}
	if json.Unmarshal(body, &res) != nil {
		return
	}
	for _, m := range res.Matches {
		if net.ParseIP(m.IPStr) != nil {
			st.AddRealIP(model.RealIPFinding{IP: m.IPStr, Technique: "shodan-ssl-cert", Detail: domain})
		}
	}
}

// queryCensys searches Censys hosts for the domain's certificate CN. It runs
// only when both CENSYS_API_ID and CENSYS_API_SECRET are set.
func queryCensys(ctx context.Context, domain string, st *model.State, rep progress.Reporter) {
	id := os.Getenv("CENSYS_API_ID")
	secret := os.Getenv("CENSYS_API_SECRET")
	if id == "" || secret == "" {
		st.AddSkip("censys", "Censys lookup — no API credentials (set CENSYS_API_ID and CENSYS_API_SECRET)")
		return
	}
	rep.Status("querying Censys...")
	q := "services.tls.certificates.leaf_data.subject.common_name:" + domain
	url := "https://search.censys.io/api/v2/hosts/search?q=" + neturl.QueryEscape(q)
	status, _, body, err := httpGetBasicAuth(ctx, url, 30*time.Second, id, secret)
	if err != nil || status != 200 {
		st.AddError("censys", errStatus("censys", status, err))
		return
	}
	var res struct {
		Result struct {
			Hits []struct {
				IP string `json:"ip"`
			} `json:"hits"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &res) != nil {
		return
	}
	for _, h := range res.Result.Hits {
		if net.ParseIP(h.IP) != nil {
			st.AddRealIP(model.RealIPFinding{IP: h.IP, Technique: "censys-ssl-cert", Detail: domain})
		}
	}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}
