package progress

import (
	"bytes"
	"strings"
	"testing"
)

func TestStageOutput(t *testing.T) {
	var buf bytes.Buffer
	p := New(&buf, 3, false) // color off for stable assertions

	stage := p.StartStage("Port discovery")
	stage.Status("%d ports found", 5)
	stage.Done()

	out := buf.String()
	if !strings.Contains(out, "[1/3]") {
		t.Errorf("missing stage counter in:\n%s", out)
	}
	if !strings.Contains(out, "Port discovery") {
		t.Errorf("missing stage name in:\n%s", out)
	}
	if !strings.Contains(out, "-> 5 ports found") {
		t.Errorf("missing status line in:\n%s", out)
	}
	if !strings.Contains(out, "done") {
		t.Errorf("missing completion marker in:\n%s", out)
	}
}

func TestStageCounterIncrements(t *testing.T) {
	var buf bytes.Buffer
	p := New(&buf, 2, false)
	p.StartStage("first")
	p.StartStage("second")
	out := buf.String()
	if !strings.Contains(out, "[1/2]") || !strings.Contains(out, "[2/2]") {
		t.Errorf("counter did not increment correctly:\n%s", out)
	}
}

func TestStageSkippedAndFail(t *testing.T) {
	var buf bytes.Buffer
	p := New(&buf, 1, false)
	s := p.StartStage("x")
	s.Skipped("no data")
	if !strings.Contains(buf.String(), "skipped: no data") {
		t.Errorf("missing skipped marker: %s", buf.String())
	}
}
