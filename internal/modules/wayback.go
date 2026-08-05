package modules

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// Wayback pulls historical URLs for the target domain directly from the Wayback
// Machine CDX API (no external gau binary needed).
type Wayback struct{}

func (Wayback) Name() string  { return "wayback" }
func (Wayback) Title() string { return "Historical URLs (Wayback CDX)" }

func (Wayback) Enabled(cfg *config.Config, st *model.State) bool {
	return st.Target.Kind == model.TargetDomain
}

// waybackLimit caps how many historical URLs we keep to avoid huge reports.
const waybackLimit = 5000

func (Wayback) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	url := "https://web.archive.org/cdx/search/cdx?url=" + st.Target.Value +
		"/*&output=json&fl=original&collapse=urlkey&limit=" + strconv.Itoa(waybackLimit)

	// web.archive.org is frequently slow to first byte; allow a generous timeout.
	status, _, body, err := httpGetT(ctx, url, 60*time.Second)
	if err != nil {
		return err
	}
	if status != 200 || len(body) == 0 {
		rep.Status("no wayback data (status %d)", status)
		return nil
	}

	// CDX JSON is an array of arrays; the first row is a header.
	var rows [][]string
	if json.Unmarshal(body, &rows) != nil {
		rep.Status("could not parse wayback response")
		return nil
	}
	var urls []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 { // skip header
			continue
		}
		urls = append(urls, row[0])
	}
	st.AddWayback(urls)
	rep.Status("%d historical URLs", len(st.Wayback))
	return nil
}
