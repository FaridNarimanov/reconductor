package modules

import (
	"context"
	"net/http"
	"strings"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// WAF performs simple signature-based WAF/CDN fingerprinting from HTTP response
// headers (Cloudflare, Akamai, Sucuri, Imperva/Incapsula, AWS CloudFront, …).
type WAF struct{}

func (WAF) Name() string  { return "waf" }
func (WAF) Title() string { return "WAF/CDN fingerprint (headers)" }

func (WAF) Enabled(cfg *config.Config, st *model.State) bool { return true }

// wafSignature matches a vendor by a header name and (optional) value substring.
type wafSignature struct {
	vendor string
	header string
	value  string // if empty, presence of the header is enough
}

var wafSignatures = []wafSignature{
	{"Cloudflare", "cf-ray", ""},
	{"Cloudflare", "server", "cloudflare"},
	{"Akamai", "x-akamai-transformed", ""},
	{"Akamai", "server", "akamaighost"},
	{"Sucuri", "x-sucuri-id", ""},
	{"Sucuri", "server", "sucuri"},
	{"Imperva/Incapsula", "x-iinfo", ""},
	{"Imperva/Incapsula", "x-cdn", "incapsula"},
	{"AWS CloudFront", "x-amz-cf-id", ""},
	{"AWS CloudFront", "via", "cloudfront"},
	{"Fastly", "x-served-by", "cache-"},
	{"Fastly", "x-fastly-request-id", ""},
}

func (WAF) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	urls := st.WebHosts()
	if len(urls) == 0 {
		rep.Status("no live web hosts")
		return nil
	}

	for _, u := range urls {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, headers, _, err := httpGet(ctx, u)
		if err != nil {
			continue
		}
		for _, f := range matchWAF(headers) {
			f.URL = u
			st.AddWAF(f)
		}
	}
	rep.Status("%d WAF/CDN signal(s)", len(st.WAF))
	return nil
}

// matchWAF returns deduplicated vendor findings for one set of headers.
func matchWAF(h http.Header) []model.WAFFinding {
	seen := map[string]bool{}
	var out []model.WAFFinding
	for _, sig := range wafSignatures {
		val := h.Get(sig.header)
		if val == "" {
			continue
		}
		if sig.value != "" && !strings.Contains(strings.ToLower(val), sig.value) {
			continue
		}
		if seen[sig.vendor] {
			continue
		}
		seen[sig.vendor] = true
		out = append(out, model.WAFFinding{
			Vendor:   sig.vendor,
			Evidence: sig.header + ": " + val,
		})
	}
	return out
}
