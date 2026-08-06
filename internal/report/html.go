package report

import (
	"html/template"
	"os"
	"path/filepath"
	"time"

	"reconductor/internal/model"
)

// liveRow is a precomputed live-host row (ports resolved ahead of rendering so
// the template stays free of function calls with arguments).
type liveRow struct {
	Host       string
	URL        string
	StatusCode int
	Title      string
	Tech       []string
	Ports      string
}

// htmlData is the view model passed to the HTML template.
type htmlData struct {
	State    *model.State
	Duration string
	LiveRows []liveRow
}

// WriteHTML renders report.html in dir using a LinPEAS-style dark theme.
func WriteHTML(st *model.State, dir string) (string, error) {
	path := filepath.Join(dir, "report.html")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	rows := make([]liveRow, 0, len(st.LiveHosts))
	for _, lh := range st.LiveHosts {
		rows = append(rows, liveRow{
			Host:       lh.Host,
			URL:        lh.URL,
			StatusCode: lh.StatusCode,
			Title:      lh.Title,
			Tech:       lh.Tech,
			Ports:      portsFor(st, lh.Host),
		})
	}

	data := htmlData{
		State:    st,
		Duration: st.EndedAt.Sub(st.StartedAt).Round(time.Second).String(),
		LiveRows: rows,
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", err
	}
	if err := tmpl.Execute(f, data); err != nil {
		return "", err
	}
	return path, nil
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Report — {{.State.Target.Value}}</title>
<style>
  :root {
    --bg:#0d1117; --panel:#161b22; --border:#30363d; --text:#c9d1d9;
    --muted:#8b949e; --green:#3fb950; --cyan:#39c5cf; --yellow:#d29922;
    --red:#f85149; --accent:#58a6ff;
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:14px; line-height:1.5; }
  .wrap { max-width:1100px; margin:0 auto; padding:24px; }
  h1 { color:var(--accent); font-size:22px; margin:0 0 4px; }
  h2 { color:var(--cyan); font-size:16px; border-bottom:1px solid var(--border);
    padding-bottom:6px; margin:28px 0 12px; }
  .sub { color:var(--muted); margin-bottom:20px; }
  .cards { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:8px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:8px;
    padding:12px 16px; min-width:130px; }
  .card .n { font-size:24px; font-weight:700; color:var(--green); }
  .card .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.5px; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
    border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  th,td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--border);
    vertical-align:top; word-break:break-word; }
  th { color:var(--muted); font-weight:600; text-transform:uppercase; font-size:12px; }
  tr:last-child td { border-bottom:none; }
  .tag { display:inline-block; padding:1px 8px; border-radius:12px; font-size:12px; }
  .ok { color:var(--green); } .redir { color:var(--cyan); }
  .warn { color:var(--yellow); } .err { color:var(--red); }
  .pill { background:#21262d; color:var(--text); }
  ul.plain { list-style:none; padding:0; margin:0; columns:3; }
  ul.plain li { padding:2px 0; color:var(--muted); }
  .skip { color:var(--yellow); } .error { color:var(--red); }
  code { background:#21262d; padding:1px 5px; border-radius:4px; }
  .foot { color:var(--muted); margin-top:32px; font-size:12px; text-align:center; }
</style>
</head>
<body>
<div class="wrap">
  <h1>▶ Recon Report</h1>
  <div class="sub">Target: <code>{{.State.Target.Value}}</code> ({{.State.Target.Kind}}) ·
    started {{.State.StartedAt.Format "2006-01-02 15:04:05"}} · duration {{.Duration}}</div>

  <div class="cards">
    <div class="card"><div class="n">{{len .State.Subdomains}}</div><div class="l">Subdomains</div></div>
    <div class="card"><div class="n">{{len .State.LiveHosts}}</div><div class="l">Live Hosts</div></div>
    <div class="card"><div class="n">{{len .State.Services}}</div><div class="l">Services</div></div>
    <div class="card"><div class="n">{{len .State.Content}}</div><div class="l">Content Paths</div></div>
    <div class="card"><div class="n">{{len .State.Errors}}</div><div class="l">Errors</div></div>
  </div>

  {{if .LiveRows}}
  <h2>Live Hosts</h2>
  <table>
    <tr><th>Host</th><th>URL</th><th>Code</th><th>Title</th><th>Ports</th><th>Tech</th></tr>
    {{range .LiveRows}}
    <tr>
      <td>{{.Host}}</td>
      <td><a href="{{.URL}}" style="color:var(--accent)">{{.URL}}</a></td>
      <td class="{{if and (ge .StatusCode 200) (lt .StatusCode 300)}}ok{{else if and (ge .StatusCode 300) (lt .StatusCode 400)}}redir{{else if ge .StatusCode 400}}warn{{end}}">{{.StatusCode}}</td>
      <td>{{.Title}}</td>
      <td>{{.Ports}}</td>
      <td>{{range .Tech}}<span class="tag pill">{{.}}</span> {{end}}</td>
    </tr>
    {{end}}
  </table>
  {{end}}

  {{if .State.Services}}
  <h2>Services (nmap)</h2>
  <table>
    <tr><th>Host</th><th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th></tr>
    {{range .State.Services}}
    <tr>
      <td>{{.Host}}</td><td>{{.Port}}</td><td>{{.Protocol}}</td>
      <td>{{.Name}}</td><td>{{.Product}}</td><td>{{.Version}}</td>
    </tr>
    {{end}}
  </table>
  {{end}}

  {{if .State.WebTech}}
  <h2>Web Fingerprints (whatweb)</h2>
  <table>
    <tr><th>URL</th><th>Summary</th></tr>
    {{range .State.WebTech}}
    <tr><td><a href="{{.URL}}" style="color:var(--accent)">{{.URL}}</a></td><td>{{.Summary}}</td></tr>
    {{end}}
  </table>
  {{end}}

  {{if .State.Content}}
  <h2>Content Discovery (feroxbuster)</h2>
  <table>
    <tr><th>Status</th><th>Length</th><th>URL</th></tr>
    {{range .State.Content}}
    <tr>
      <td class="{{if and (ge .Status 200) (lt .Status 300)}}ok{{else if ge .Status 400}}warn{{end}}">{{.Status}}</td>
      <td>{{.ContentLength}}</td>
      <td><a href="{{.URL}}" style="color:var(--accent)">{{.URL}}</a></td>
    </tr>
    {{end}}
  </table>
  {{end}}

  {{if .State.Target.Kind}}{{if eq (printf "%s" .State.Target.Kind) "domain"}}
  <h2>Active Directory</h2>
  {{if .State.AD.Detected}}
  <p class="ok">✔ AD environment detected.</p>
  <table>
    <tr><th>SRV Query</th><th>Target</th><th>Port</th></tr>
    {{range .State.AD.SRVRecords}}
    <tr><td>{{.Query}}</td><td>{{.Target}}</td><td>{{.Port}}</td></tr>
    {{end}}
  </table>
  {{if .State.AD.NamingContexts}}<p style="margin-top:12px"><b>Naming contexts (LDAP):</b></p>
  <ul>{{range .State.AD.NamingContexts}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
  {{if .State.AD.SMBShares}}<p><b>SMB shares (null session):</b></p>
  <ul>{{range .State.AD.SMBShares}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
  {{if .State.AD.ValidUsers}}<p><b>Valid users (Kerberos):</b></p>
  <ul>{{range .State.AD.ValidUsers}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
  {{else}}
  <p class="sub">No Active Directory SRV records found.</p>
  {{end}}
  {{end}}{{end}}

  {{if .State.RealIPs}}
  <h2>Origin IP Candidates (CDN bypass)</h2>
  <table>
    <tr><th>IP</th><th>Technique</th><th>Detail</th></tr>
    {{range .State.RealIPs}}
    <tr><td>{{.IP}}</td><td><span class="tag pill">{{.Technique}}</span></td><td>{{.Detail}}</td></tr>
    {{end}}
  </table>
  {{end}}

  {{if .State.WAF}}
  <h2>WAF / CDN</h2>
  <table>
    <tr><th>Vendor</th><th>URL</th><th>Evidence</th></tr>
    {{range .State.WAF}}
    <tr><td class="warn">{{.Vendor}}</td><td>{{.URL}}</td><td><code>{{.Evidence}}</code></td></tr>
    {{end}}
  </table>
  {{end}}

  {{if .State.Buckets}}
  <h2>Cloud Buckets</h2>
  <table>
    <tr><th>Status</th><th>Access</th><th>URL</th></tr>
    {{range .State.Buckets}}
    <tr>
      <td class="{{if .Accessible}}warn{{else}}redir{{end}}">{{.Status}}</td>
      <td>{{if .Accessible}}<span class="warn">PUBLIC</span>{{else}}private{{end}}</td>
      <td><a href="{{.URL}}" style="color:var(--accent)">{{.URL}}</a></td>
    </tr>
    {{end}}
  </table>
  {{end}}

  {{if .State.JS}}
  <h2>JavaScript Endpoints</h2>
  {{range .State.JS}}
  <p style="margin-bottom:4px"><b><a href="{{.File}}" style="color:var(--accent)">{{.File}}</a></b></p>
  <ul class="plain">{{range .Endpoints}}<li>{{.}}</li>{{end}}</ul>
  {{end}}
  {{end}}

  {{if .State.Robots}}
  <h2>robots.txt / sitemap.xml</h2>
  <table>
    <tr><th>Source</th><th>Host</th><th>Path</th></tr>
    {{range .State.Robots}}
    <tr><td>{{.Source}}</td><td>{{.Host}}</td><td>{{.Path}}</td></tr>
    {{end}}
  </table>
  {{end}}

  {{if .State.Wayback}}
  <h2>Historical URLs (Wayback) — {{len .State.Wayback}}</h2>
  <details><summary style="cursor:pointer;color:var(--accent)">Show URLs</summary>
  <ul class="plain">{{range .State.Wayback}}<li>{{.}}</li>{{end}}</ul>
  </details>
  {{end}}

  {{if .State.Subdomains}}
  <h2>Subdomains</h2>
  <ul class="plain">{{range .State.Subdomains}}<li>{{.}}</li>{{end}}</ul>
  {{end}}

  {{if .State.Skips}}
  <h2>Skipped</h2>
  <ul>{{range .State.Skips}}<li class="skip">○ <b>{{.Module}}</b> — {{.Reason}}</li>{{end}}</ul>
  {{end}}

  {{if .State.Errors}}
  <h2>Errors</h2>
  <ul>{{range .State.Errors}}<li class="error">✗ <b>{{.Module}}</b>: {{.Err}}</li>{{end}}</ul>
  {{end}}

  <div class="foot">Generated by reconductor · {{.State.EndedAt.Format "2006-01-02 15:04:05"}}</div>
</div>
</body>
</html>
`
