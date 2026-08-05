package modules

import (
	"context"
	"strings"
	"sync"
	"time"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// Buckets probes common S3/GCS bucket naming patterns derived from the target's
// base name to find publicly reachable cloud storage.
type Buckets struct{}

func (Buckets) Name() string  { return "buckets" }
func (Buckets) Title() string { return "Cloud bucket discovery (S3/GCS)" }

func (Buckets) Enabled(cfg *config.Config, st *model.State) bool {
	return st.Target.Kind == model.TargetDomain
}

// bucketSuffixes are appended to the base name to build candidate bucket names.
var bucketSuffixes = []string{
	"", "-backup", "-backups", "-assets", "-static", "-media", "-uploads",
	"-dev", "-staging", "-prod", "-data", "-logs", "-private", "-public",
}

func (Buckets) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	base := baseName(st.Target.Value)
	if base == "" {
		rep.Status("could not derive a base name")
		return nil
	}

	// Build the full candidate URL list.
	seen := map[string]bool{}
	type probe struct{ name, url string }
	var probes []probe
	for _, suf := range bucketSuffixes {
		name := base + suf
		if seen[name] {
			continue
		}
		seen[name] = true
		probes = append(probes,
			probe{name, "https://" + name + ".s3.amazonaws.com"},
			probe{name, "https://storage.googleapis.com/" + name},
		)
	}

	// Probe concurrently — each request is independent.
	workers := cfg.Threads
	if workers < 1 {
		workers = 20
	}
	jobs := make(chan probe)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if ctx.Err() != nil {
					return
				}
				status, _, _, err := httpGetT(ctx, p.url, 8*time.Second)
				if err != nil {
					continue
				}
				// 200 = listable/public, 403 = exists but access denied. Both
				// mean the bucket name is taken and worth noting.
				if status == 200 || status == 403 {
					st.AddBucket(model.BucketFinding{
						Name:       p.name,
						URL:        p.url,
						Status:     status,
						Accessible: status == 200,
					})
				}
			}
		}()
	}
	for _, p := range probes {
		select {
		case <-ctx.Done():
			goto done
		case jobs <- p:
		}
	}
done:
	close(jobs)
	wg.Wait()

	rep.Status("probed %d candidates, %d bucket(s) found", len(probes), len(st.Buckets))
	return ctx.Err()
}

// baseName extracts the registrable label from a domain (e.g. "example" from
// "www.example.com").
func baseName(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	parts := strings.Split(d, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return ""
}
