package modules

import (
	"context"
	"strings"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// Subfinder performs passive subdomain discovery via `subfinder -d <d> -silent`.
// It only runs for domain targets.
type Subfinder struct{}

func (Subfinder) Name() string  { return "subfinder" }
func (Subfinder) Title() string { return "Subdomain discovery (subfinder)" }

func (Subfinder) Enabled(cfg *config.Config, st *model.State) bool {
	return st.Target.Kind == model.TargetDomain
}

func (Subfinder) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	if !binaryAvailable("subfinder") {
		return errMissingBinary("subfinder")
	}

	var found []string
	err := runLines(ctx, "", func(line string) {
		s := strings.TrimSpace(line)
		if s != "" {
			found = append(found, s)
		}
	}, "subfinder", "-d", st.Target.Value, "-silent")

	// Always include the apex domain itself as a target.
	found = append(found, st.Target.Value)
	st.AddSubdomains(found)
	rep.Status("%d subdomains found", len(st.Subdomains))
	return err
}
