// Package modules contains one independent recon module per external tool or
// data source. Each module implements the Module interface and is wired into
// the pipeline by the orchestrator. Modules never call os.Exit or panic on
// failure; they return an error which the orchestrator records so the run can
// continue.
package modules

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// verbose toggles [debug] logging to stderr for external commands and HTTP
// requests. Set once at startup via SetVerbose.
var verbose atomic.Bool

// SetVerbose enables or disables debug logging for the modules package.
func SetVerbose(v bool) { verbose.Store(v) }

// debugf writes a [debug] line to stderr when verbose logging is enabled.
func debugf(format string, args ...any) {
	if verbose.Load() {
		fmt.Fprintf(os.Stderr, "\033[90m[debug] "+format+"\033[0m\n", args...)
	}
}

// userAgent is sent with every HTTP request the stdlib-based modules make.
const userAgent = "reconductor/0.2 (+https://github.com/FaridNarimanov/reconductor)"

// defaultHTTPTimeout is used by httpGet; per-call overrides use httpGetT.
const defaultHTTPTimeout = 25 * time.Second

// httpClient is shared by the pure-Go modules (crt.sh, wayback, WAF, buckets,
// robots, JS). Timeouts are enforced per call via context deadlines rather than
// a client-wide Timeout so slow sources (crt.sh, Wayback) can wait longer.
var httpClient = &http.Client{}

// httpGet performs a GET request with the default timeout.
func httpGet(ctx context.Context, url string) (int, http.Header, []byte, error) {
	return httpGetT(ctx, url, defaultHTTPTimeout)
}

// httpGetT is httpGet with an explicit timeout.
func httpGetT(ctx context.Context, url string, timeout time.Duration) (int, http.Header, []byte, error) {
	return httpDo(ctx, url, timeout, nil)
}

// httpGetBasicAuth is httpGetT with HTTP Basic authentication (used by Censys).
func httpGetBasicAuth(ctx context.Context, url string, timeout time.Duration, user, pass string) (int, http.Header, []byte, error) {
	return httpDo(ctx, url, timeout, func(req *http.Request) { req.SetBasicAuth(user, pass) })
}

// httpDo performs a GET honoring ctx cancellation and returns the (capped) body
// plus response headers. modify, if non-nil, customizes the request before it
// is sent.
func httpDo(ctx context.Context, url string, timeout time.Duration, modify func(*http.Request)) (int, http.Header, []byte, error) {
	debugf("http GET %s (timeout %s)", url, timeout)
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(rctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if modify != nil {
		modify(req)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // cap at 8 MiB
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	return resp.StatusCode, resp.Header, body, nil
}

// Module is a single unit of work in the recon pipeline.
type Module interface {
	// Name is the stable identifier used for --skip and error reporting.
	Name() string
	// Title is the human-friendly label shown in the progress UI.
	Title() string
	// Enabled reports whether this module should run for the given config and
	// current state (e.g. subfinder only runs for domain targets). Disabled
	// modules are not counted in the [n/total] stage total.
	Enabled(cfg *config.Config, st *model.State) bool
	// Run executes the module. It must respect ctx cancellation (used for the
	// Ctrl+C "skip current module" behavior) and report sub-status via rep.
	Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error
}

// binaryAvailable reports whether an external tool is present in PATH.
func binaryAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// resolveTool returns the first candidate binary found in PATH. This lets a
// module accept known distro-specific names (e.g. Kali ships ProjectDiscovery
// httpx as "httpx-toolkit" to avoid clashing with the Python httpx client).
func resolveTool(candidates ...string) (string, bool) {
	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return c, true
		}
	}
	return "", false
}

// errMissingBinary is returned when a required external tool is not installed.
func errMissingBinary(name string) error {
	return fmt.Errorf("%q not found in PATH", name)
}

// runLines runs a command, feeds stdin (if non-empty), and calls onLine for
// each line of stdout. It respects ctx cancellation. stderr is captured and
// returned as part of the error only if the command fails.
func runLines(ctx context.Context, stdin string, onLine func(string), name string, args ...string) error {
	debugf("exec: %s %s", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)

	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		onLine(scanner.Text())
	}

	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		// Cancelled (skipped by user) — not a real failure.
		return ctx.Err()
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s: %v (%s)", name, waitErr, firstLine(msg))
		}
		return fmt.Errorf("%s: %v", name, waitErr)
	}
	return nil
}

// runCapture runs a command and returns its full stdout as a string.
func runCapture(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	debugf("exec: %s %s", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, stderr strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.String(), ctx.Err()
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return out.String(), fmt.Errorf("%s: %v (%s)", name, err, firstLine(msg))
		}
		return out.String(), fmt.Errorf("%s: %v", name, err)
	}
	return out.String(), nil
}

// errStatus builds an error describing a failed HTTP API call.
func errStatus(name string, status int, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	return fmt.Errorf("%s: unexpected HTTP status %d", name, status)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
