package modules

import (
	"context"
	"encoding/xml"
	"strings"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// Robots fetches robots.txt and sitemap.xml from each live web host and extracts
// the referenced paths/URLs.
type Robots struct{}

func (Robots) Name() string  { return "robots" }
func (Robots) Title() string { return "robots.txt / sitemap.xml parsing" }

func (Robots) Enabled(cfg *config.Config, st *model.State) bool { return true }

// sitemap mirrors the subset of the sitemap.xml schema we read.
type sitemap struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
	// Sitemap index files reference other sitemaps.
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

func (Robots) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	urls := st.WebHosts()
	if len(urls) == 0 {
		rep.Status("no live web hosts")
		return nil
	}

	for _, base := range urls {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		host := strings.TrimRight(base, "/")
		parseRobots(ctx, host, st)
		parseSitemap(ctx, host+"/sitemap.xml", host, st)
	}
	rep.Status("%d robots/sitemap path(s)", len(st.Robots))
	return nil
}

func parseRobots(ctx context.Context, host string, st *model.State) {
	status, _, body, err := httpGet(ctx, host+"/robots.txt")
	if err != nil || status != 200 {
		return
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "disallow:"), strings.HasPrefix(lower, "allow:"):
			path := strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
			if path != "" {
				st.AddRobots(model.RobotsFinding{Host: host, Source: "robots.txt", Path: path})
			}
		case strings.HasPrefix(lower, "sitemap:"):
			sm := strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
			if sm != "" {
				parseSitemap(ctx, sm, host, st)
			}
		}
	}
}

func parseSitemap(ctx context.Context, url, host string, st *model.State) {
	status, _, body, err := httpGet(ctx, url)
	if err != nil || status != 200 || len(body) == 0 {
		return
	}
	var sm sitemap
	if xml.Unmarshal(body, &sm) != nil {
		return
	}
	for _, u := range sm.URLs {
		if loc := strings.TrimSpace(u.Loc); loc != "" {
			st.AddRobots(model.RobotsFinding{Host: host, Source: "sitemap.xml", Path: loc})
		}
	}
	// Note: nested sitemap indexes are recorded but not recursively fetched to
	// keep the module bounded.
	for _, s := range sm.Sitemaps {
		if loc := strings.TrimSpace(s.Loc); loc != "" {
			st.AddRobots(model.RobotsFinding{Host: host, Source: "sitemap-index", Path: loc})
		}
	}
}
