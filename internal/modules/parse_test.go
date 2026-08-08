package modules

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"reconductor/internal/model"
)

func TestParsePort(t *testing.T) {
	tests := []struct {
		raw  string
		want int
	}{
		{`80`, 80},
		{`{"port":443}`, 443},
		{`{"Port":22}`, 22},
		{``, 0},
		{`"nope"`, 0},
	}
	for _, tc := range tests {
		got := parsePort(json.RawMessage(tc.raw))
		if got != tc.want {
			t.Errorf("parsePort(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestJoinPorts(t *testing.T) {
	// Input is intentionally unsorted; joinPorts sorts ascending.
	if got := joinPorts([]int{443, 22, 80}); got != "22,80,443" {
		t.Errorf("joinPorts = %q", got)
	}
}

func TestParseNmap(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>`
	st := model.NewState(model.Target{})
	parseNmap(xml, "fallback", st)
	if len(st.Services) != 1 {
		t.Fatalf("expected 1 open service, got %d", len(st.Services))
	}
	svc := st.Services[0]
	if svc.Host != "1.2.3.4" || svc.Port != 80 || svc.Name != "http" || svc.Product != "nginx" {
		t.Errorf("service = %+v", svc)
	}
}

func TestParseNmapFallbackHost(t *testing.T) {
	// No <address> element: the fallback host should be used.
	xml := `<nmaprun><host><ports><port protocol="tcp" portid="8080">` +
		`<state state="open"/><service name="http-proxy"/></port></ports></host></nmaprun>`
	st := model.NewState(model.Target{})
	parseNmap(xml, "myhost", st)
	if len(st.Services) != 1 || st.Services[0].Host != "myhost" {
		t.Errorf("services = %+v", st.Services)
	}
}

func TestParseSPFIPs(t *testing.T) {
	txt := "v=spf1 ip4:1.2.3.4 ip4:5.6.7.0/24 include:_spf.google.com -all"
	got := parseSPFIPs(txt)
	if strings.Join(got, ",") != "1.2.3.4,5.6.7.0" {
		t.Errorf("parseSPFIPs = %v", got)
	}
	if parseSPFIPs("not an spf record") != nil {
		t.Error("non-SPF text should return nil")
	}
}

func TestParseNamingContexts(t *testing.T) {
	out := "dn:\nnamingContexts: DC=example,DC=com\nnamingContexts: CN=Configuration,DC=example,DC=com\n"
	got := parseNamingContexts(out)
	if len(got) != 2 || got[0] != "DC=example,DC=com" {
		t.Errorf("naming contexts = %v", got)
	}
}

func TestParseSMBShares(t *testing.T) {
	out := "Disk|Users|home dirs\nDisk|C$|default share\nPrinter|HP|printer\nIPC|IPC$|"
	got := parseSMBShares(out)
	if strings.Join(got, ",") != "Users,C$" {
		t.Errorf("smb shares = %v", got)
	}
}

func TestParseKerbrute(t *testing.T) {
	out := `2020/01/01 12:00:00 >  [+] VALID USERNAME:	 admin@example.com
2020/01/01 12:00:01 >  [+] VALID USERNAME:  guest@example.com
some noise line`
	got := parseKerbrute(out)
	if strings.Join(got, ",") != "admin,guest" {
		t.Errorf("kerbrute users = %v", got)
	}
}

func TestMatchWAF(t *testing.T) {
	h := http.Header{}
	h.Set("cf-ray", "7abc-DFW")
	h.Set("server", "cloudflare")
	got := matchWAF(h)
	if len(got) != 1 || got[0].Vendor != "Cloudflare" {
		t.Errorf("matchWAF cloudflare = %+v", got)
	}

	h2 := http.Header{}
	h2.Set("x-sucuri-id", "12345")
	if got := matchWAF(h2); len(got) != 1 || got[0].Vendor != "Sucuri" {
		t.Errorf("matchWAF sucuri = %+v", got)
	}

	if got := matchWAF(http.Header{}); len(got) != 0 {
		t.Errorf("empty headers should match nothing, got %+v", got)
	}
}

func TestBaseName(t *testing.T) {
	tests := map[string]string{
		"www.example.com": "example",
		"example.com":     "example",
		"localhost":       "localhost",
		"EXAMPLE.COM":     "example",
	}
	for in, want := range tests {
		if got := baseName(in); got != want {
			t.Errorf("baseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractEndpoints(t *testing.T) {
	src := `var a = "/api/v1/users"; fetch('https://api.example.com/v2/data');
	        var proto = "//cdn.example.com/lib.js"; var x = "/api/v1/users";`
	got := extractEndpoints(src)
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "/api/v1/users") {
		t.Errorf("expected /api/v1/users in %v", got)
	}
	if !strings.Contains(joined, "https://api.example.com/v2/data") {
		t.Errorf("expected full URL in %v", got)
	}
	// Protocol-relative //... is filtered out.
	if strings.Contains(joined, "//cdn.example.com/lib.js") {
		t.Errorf("protocol-relative URL should be filtered, got %v", got)
	}
	// Duplicates are collapsed.
	count := 0
	for _, e := range got {
		if e == "/api/v1/users" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected /api/v1/users once, got %d", count)
	}
}

func TestUnique(t *testing.T) {
	got := unique([]string{"a", "b", "a", "", "c", "b"})
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("unique = %v", got)
	}
}
