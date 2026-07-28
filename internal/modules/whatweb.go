package modules

import (
	"context"
	"strings"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// WhatWeb enriches the initial httpx tech-stack with deep CMS/plugin-level
// fingerprints via `whatweb -a 3 --color=never --log-brief=-` against each live
// web host.
type WhatWeb struct{}

func (WhatWeb) Name() string  { return "whatweb" }
func (WhatWeb) Title() string { return "Deep tech/CMS fingerprint (whatweb)" }

// Enabled is target/config-gated only (always true here); the "no live hosts"
// case is handled inside Run so the [n/total] stage count stays deterministic.
func (WhatWeb) Enabled(cfg *config.Config, st *model.State) bool { return true }

func (WhatWeb) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	if !binaryAvailable("whatweb") {
		return errMissingBinary("whatweb")
	}

	urls := st.WebHosts()
	if len(urls) == 0 {
		rep.Status("no live web hosts")
		return nil
	}

	var firstErr error
	for i, u := range urls {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		out, err := runCapture(ctx, "", "whatweb", "-a", "3", "--color=never", "--log-brief=-", u)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		summary := strings.TrimSpace(out)
		if summary != "" {
			st.AddWebTech(model.WebTechFinding{URL: u, Summary: firstLine(summary)})
		}
		rep.Status("fingerprinted %d/%d hosts", i+1, len(urls))
	}
	return firstErr
}
