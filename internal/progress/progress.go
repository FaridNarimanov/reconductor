// Package progress renders the live, stage-based terminal UI: "[3/8] Port
// discovery (naabu)..." with a completion tick and elapsed time, plus indented
// sub-status lines emitted from inside a module.
package progress

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// ANSI color codes; kept minimal and self-contained (LinPEAS-style output).
const (
	colReset  = "\033[0m"
	colGreen  = "\033[32m"
	colRed    = "\033[31m"
	colYellow = "\033[33m"
	colCyan   = "\033[36m"
	colBold   = "\033[1m"
	colGray   = "\033[90m"
)

// Reporter is the handle a running module uses to emit sub-status lines.
type Reporter interface {
	// Status prints an indented status line under the current stage.
	Status(format string, args ...any)
}

// Printer manages the ordered stage counter and terminal output.
type Printer struct {
	mu      sync.Mutex
	out     io.Writer
	total   int
	current int
	color   bool
	start   time.Time
}

// New creates a Printer that writes to out. total is the number of enabled
// stages so the [n/total] counter is accurate. color toggles ANSI coloring.
func New(out io.Writer, total int, color bool) *Printer {
	return &Printer{out: out, total: total, color: color, start: time.Now()}
}

func (p *Printer) c(code, s string) string {
	if !p.color {
		return s
	}
	return code + s + colReset
}

// stage represents one active stage returned by StartStage.
type stage struct {
	p       *Printer
	name    string
	started time.Time
}

// StartStage advances the counter and prints the stage header.
func (p *Printer) StartStage(name string) *stage {
	p.mu.Lock()
	p.current++
	n := p.current
	p.mu.Unlock()

	fmt.Fprintf(p.out, "%s %s\n",
		p.c(colCyan+colBold, fmt.Sprintf("[%d/%d]", n, p.total)),
		p.c(colBold, name),
	)
	return &stage{p: p, name: name, started: time.Now()}
}

// Status implements Reporter: an indented arrow line under the current stage.
func (s *stage) Status(format string, args ...any) {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(s.p.out, "    %s %s\n", s.p.c(colGray, "->"), msg)
}

// Done closes the stage with a green tick and the elapsed time.
func (s *stage) Done() {
	elapsed := time.Since(s.started).Round(time.Millisecond)
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	fmt.Fprintf(s.p.out, "    %s %s %s\n",
		s.p.c(colGreen, "✓"),
		s.p.c(colGreen, "done"),
		s.p.c(colGray, fmt.Sprintf("(%s)", elapsed)),
	)
}

// Fail closes the stage with a red mark and the error text.
func (s *stage) Fail(err error) {
	elapsed := time.Since(s.started).Round(time.Millisecond)
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	fmt.Fprintf(s.p.out, "    %s %s %s\n",
		s.p.c(colRed, "✗"),
		s.p.c(colRed, err.Error()),
		s.p.c(colGray, fmt.Sprintf("(%s)", elapsed)),
	)
}

// Skipped closes the stage as intentionally skipped (yellow).
func (s *stage) Skipped(reason string) {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	fmt.Fprintf(s.p.out, "    %s %s\n",
		s.p.c(colYellow, "○"),
		s.p.c(colYellow, "skipped: "+reason),
	)
}

// Info prints a top-level (non-stage) informational line.
func (p *Printer) Info(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.out, "%s\n", fmt.Sprintf(format, args...))
}

// Elapsed returns the total time since the Printer was created.
func (p *Printer) Elapsed() time.Duration {
	return time.Since(p.start).Round(time.Millisecond)
}
