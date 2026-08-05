package modules

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// JSAnalysis downloads the .js files discovered by feroxbuster and extracts
// candidate endpoints/paths via regex.
type JSAnalysis struct{}

func (JSAnalysis) Name() string  { return "jsanalysis" }
func (JSAnalysis) Title() string { return "JavaScript endpoint analysis" }

func (JSAnalysis) Enabled(cfg *config.Config, st *model.State) bool { return true }

// endpointRe matches quoted absolute/relative paths and full URLs commonly used
// as API endpoints inside JavaScript.
var endpointRe = regexp.MustCompile(`["'](https?://[^"'\s]+|/[a-zA-Z0-9_./?=&%~+-]{2,})["']`)

// jsMaxFiles caps how many JS files we fetch to keep the module bounded.
const jsMaxFiles = 50

func (JSAnalysis) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	var jsFiles []string
	for _, u := range st.ContentURLs() {
		if strings.HasSuffix(strings.ToLower(strings.Split(u, "?")[0]), ".js") {
			jsFiles = append(jsFiles, u)
		}
	}
	if len(jsFiles) == 0 {
		rep.Status("no .js files from content discovery")
		return nil
	}
	if len(jsFiles) > jsMaxFiles {
		jsFiles = jsFiles[:jsMaxFiles]
	}

	total := 0
	for i, f := range jsFiles {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		status, _, body, err := httpGet(ctx, f)
		if err != nil || status != 200 || len(body) == 0 {
			continue
		}
		endpoints := extractEndpoints(string(body))
		if len(endpoints) > 0 {
			st.AddJS(model.JSFinding{File: f, Endpoints: endpoints})
			total += len(endpoints)
		}
		rep.Status("analyzed %d/%d JS files (%d endpoints)", i+1, len(jsFiles), total)
	}
	return nil
}

// extractEndpoints returns the unique, sorted endpoint candidates in src.
func extractEndpoints(src string) []string {
	matches := endpointRe.FindAllStringSubmatch(src, -1)
	set := map[string]bool{}
	for _, m := range matches {
		e := m[1]
		// Filter obvious noise: pure file extensions and very common libs.
		if e == "" || strings.HasPrefix(e, "//") {
			continue
		}
		set[e] = true
	}
	out := make([]string, 0, len(set))
	for e := range set {
		out = append(out, e)
	}
	sort.Strings(out)
	// Cap per-file to keep reports readable.
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}
