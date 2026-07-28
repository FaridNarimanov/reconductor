package modules

import (
	"context"
	"encoding/json"
	"os"
	"strconv"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// Feroxbuster performs content/directory discovery against live web hosts only,
// via `feroxbuster -u <url> -w <wordlist> --silent --json`. Default mode uses a
// small wordlist and 20 threads; --aggressive uses a larger wordlist and 100
// threads.
type Feroxbuster struct{}

func (Feroxbuster) Name() string  { return "feroxbuster" }
func (Feroxbuster) Title() string { return "Content discovery (feroxbuster)" }

// Enabled is target/config-gated only (always true here); the "no live hosts"
// case is handled inside Run so the [n/total] stage count stays deterministic.
func (Feroxbuster) Enabled(cfg *config.Config, st *model.State) bool { return true }

// Candidate wordlists tried in order when the user did not supply --wordlist.
var (
	smallWordlists = []string{
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/dirb/wordlists/common.txt",
	}
	largeWordlists = []string{
		"/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
		"/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
		"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
	}
)

// feroxLine is one NDJSON record from feroxbuster; we only keep responses.
type feroxLine struct {
	Type          string `json:"type"`
	URL           string `json:"url"`
	Status        int    `json:"status"`
	ContentLength int64  `json:"content_length"`
}

func (Feroxbuster) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	if !binaryAvailable("feroxbuster") {
		return errMissingBinary("feroxbuster")
	}

	wordlist := resolveWordlist(cfg)
	if wordlist == "" {
		rep.Status("no wordlist available")
		return nil
	}

	threads := cfg.Threads
	if threads <= 0 {
		threads = 20
	}
	if cfg.Aggressive {
		threads = 100
	}

	urls := st.WebHosts()
	if len(urls) == 0 {
		rep.Status("no live web hosts")
		return nil
	}
	rep.Status("using wordlist %s (%d threads)", wordlist, threads)

	var firstErr error
	for i, u := range urls {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		count := 0
		err := runLines(ctx, "", func(line string) {
			if line == "" || line[0] != '{' {
				return
			}
			var f feroxLine
			if json.Unmarshal([]byte(line), &f) != nil {
				return
			}
			if f.Type != "response" || f.URL == "" {
				return
			}
			st.AddContent(model.ContentFinding{
				URL:           f.URL,
				Status:        f.Status,
				ContentLength: f.ContentLength,
			})
			count++
		}, "feroxbuster",
			"-u", u,
			"-w", wordlist,
			"-t", strconv.Itoa(threads),
			"--silent", "--json",
		)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
		rep.Status("%s -> %d paths (%d/%d hosts)", u, count, i+1, len(urls))
	}
	return firstErr
}

// resolveWordlist returns the user's wordlist if provided, otherwise the first
// existing candidate for the current mode.
func resolveWordlist(cfg *config.Config) string {
	if cfg.Wordlist != "" {
		if fileExists(cfg.Wordlist) {
			return cfg.Wordlist
		}
		return ""
	}
	candidates := smallWordlists
	if cfg.Aggressive {
		candidates = append(largeWordlists, smallWordlists...)
	}
	for _, w := range candidates {
		if fileExists(w) {
			return w
		}
	}
	return ""
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
