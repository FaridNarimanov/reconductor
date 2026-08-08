package report

import (
	"testing"

	"reconductor/internal/model"
)

func TestPortsFor(t *testing.T) {
	st := model.NewState(model.Target{})
	st.AddOpenPort("h", 443)
	st.AddOpenPort("h", 80)
	st.AddService(model.Service{Host: "h", Port: 22}) // merged in from nmap
	if got := portsFor(st, "h"); got != "22,80,443" {
		t.Errorf("portsFor = %q", got)
	}
	if got := portsFor(st, "missing"); got != "-" {
		t.Errorf("portsFor(missing) = %q, want -", got)
	}
}

func TestTechFor(t *testing.T) {
	st := model.NewState(model.Target{})
	st.AddLiveHost(model.LiveHost{Host: "h", Tech: []string{"nginx", "PHP"}})
	if got := techFor(st, "h"); got != "nginx, PHP" {
		t.Errorf("techFor = %q", got)
	}
	if got := techFor(st, "none"); got != "-" {
		t.Errorf("techFor(none) = %q, want -", got)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "he…"},
		{"hello", 1, "h"},
	}
	for _, tc := range tests {
		if got := truncate(tc.s, tc.n); got != tc.want {
			t.Errorf("truncate(%q,%d) = %q, want %q", tc.s, tc.n, got, tc.want)
		}
	}
}

func TestStatusColorNoColor(t *testing.T) {
	if got := statusColor(200, false); got != "200" {
		t.Errorf("statusColor(200,false) = %q", got)
	}
	if got := statusColor(0, false); got != "-" {
		t.Errorf("statusColor(0,false) = %q, want -", got)
	}
}
