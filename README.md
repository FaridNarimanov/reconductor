# reconductor

An all-in-one **recon aggregator** for the early stages of a penetration test.
Give it a domain, IP, or CIDR range and it orchestrates several popular
open-source tools into a single pipeline, then renders the results as a
colorized terminal summary plus **JSON** and **LinPEAS-style HTML** reports.

Written in **Go using only the standard library** — external tools are invoked
via `os/exec`, so `go build` pulls in no third-party modules.

> ⚠️ **Authorized use only.** Run this only against assets you own or are
> explicitly permitted to test. Scanning a CIDR range requires you to type `yes`
> at an authorization prompt before anything happens.

## Pipeline

The MVP runs the following modules in order; each feeds the next:

| # | Stage | Tool | Notes |
|---|-------|------|-------|
| 1 | Subdomain discovery | `subfinder -d <domain> -silent` | domain targets only |
| 2 | Live host + tech-detect | `httpx -silent -json -tech-detect -status-code -title` | subdomains piped on stdin |
| 3 | Fast port discovery | `naabu -silent -json` | top-1000 ports (full range with `--aggressive`) |
| 4 | Deep service analysis | `nmap -sV -p <naabu-ports> -oX -` | only the ports naabu found; XML parsed |
| 5 | Deep tech/CMS fingerprint | `whatweb -a 3 --color=never --log-brief=-` | live web hosts only |
| 6 | Content discovery | `feroxbuster -u <url> -w <wordlist> --silent --json` | live web hosts only |

### Extended modules

These run automatically after the core pipeline. They are pure-Go (standard
library only — no external binaries) except for the aggressive AD recon, which
shells out to `ldapsearch`/`smbclient`.

| Module | What it does | Target |
|--------|--------------|--------|
| `dnsbrute` | Active DNS subdomain brute-force with a built-in prefix list | domain, `--aggressive` only |
| `jsanalysis` | Downloads `.js` files found by feroxbuster and regex-extracts endpoints | web hosts |
| `realip` | Origin-IP discovery behind CDNs: crt.sh, Cloudflare range comparison, MX/SPF (Shodan/Censys if keys set) | domain |
| `ad` | Passive AD detection via DNS SRV records; aggressive LDAP anon-bind + SMB null-session against DCs | domain |
| `kerberos` | Kerberos user enumeration (kerbrute) against a discovered DC | domain, `--aggressive` only |
| `wayback` | Historical URLs from the Wayback Machine CDX API | domain |
| `waf` | Signature-based WAF/CDN fingerprinting from response headers | web hosts |
| `robots` | Parses `robots.txt` and `sitemap.xml` for referenced paths | web hosts |
| `buckets` | Probes common S3/GCS bucket naming patterns (concurrently) | domain |

Every module is **fault-tolerant**: a missing tool, timeout, or non-zero exit is
recorded and shown in the final *Errors* section — the pipeline keeps going.
Each module name can be turned off with `--skip <name>`.

## Install

Requires **Go 1.26+** to build:

```bash
git clone <your-repo-url> reconductor
cd reconductor
go build -o reconductor ./cmd/reconductor
# optional: install into $GOBIN / $PATH
go install ./cmd/reconductor
```

### External tools

reconductor shells out to these tools; install the ones you need and make sure
they are in your `PATH`. Any that are missing are skipped gracefully.

| Tool | Purpose | Install (Debian/Kali) |
|------|---------|-----------------------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | passive subdomains | `apt install subfinder` or `go install .../subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | live host / tech-detect | `apt install httpx-toolkit` |
| [naabu](https://github.com/projectdiscovery/naabu) | fast port scan | `go install .../naabu/v2/cmd/naabu@latest` |
| [nmap](https://nmap.org/) | service/version detect | `apt install nmap` |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | CMS/plugin fingerprint | `apt install whatweb` |
| [feroxbuster](https://github.com/epi052/feroxbuster) | content discovery | `apt install feroxbuster` |
| `ldapsearch`, `smbclient` | AD recon (aggressive) | `apt install ldap-utils smbclient` |

> **Kali note:** ProjectDiscovery's `httpx` ships as **`httpx-toolkit`** to avoid
> clashing with the Python `httpx` HTTP client (which also installs a `/usr/bin/httpx`).
> reconductor automatically prefers `httpx-toolkit` when present, so both setups work.

Feroxbuster needs a wordlist. reconductor auto-detects common SecLists / dirb
paths; override with `--wordlist`.

## Usage

```bash
reconductor -d example.com          # domain (full pipeline)
reconductor -i 1.2.3.4              # single IP
reconductor -c 1.2.3.0/24          # CIDR range (asks for authorization first)

reconductor -d example.com --aggressive
reconductor -d example.com --skip feroxbuster --skip whatweb
reconductor -d example.com --json -o ./out
```

### Flags

| Flag | Description |
|------|-------------|
| `-d, --domain` | Domain target |
| `-i, --ip` | Single IP target |
| `-c, --cidr` | CIDR range (triggers a mandatory authorization prompt) |
| `--aggressive` | Enable all aggressive operations (see below) |
| `-o, --output` | Output directory (default: `./recon_<target>_<timestamp>/`) |
| `--json` | Write JSON only (no HTML, no summary table) |
| `--skip <module>` | Disable a module; repeatable (`--skip feroxbuster --skip whatweb`) |
| `-t, --threads` | Overall parallelism level (default 20) |
| `--wordlist` | Custom wordlist path for feroxbuster |
| `-v, --verbose` | Verbose debug logging |

### `--aggressive` mode

By default reconductor only performs passive / low-impact operations. The
`--aggressive` flag additionally enables:

- full-range nmap (`-p-`) and naabu (`-p -`) instead of the top-1000 ports,
- a larger feroxbuster wordlist with more threads,
- active DNS subdomain brute-force (`dnsbrute`),
- and — against discovered domain controllers — SMB null-session share
  enumeration (`smbclient -L`), LDAP anonymous bind (`ldapsearch`), and
  Kerberos user enumeration (`kerbrute`, if installed).

## Output

Each run creates an output directory containing:

- **`report.json`** — the complete structured result (target, subdomains, live
  hosts, open ports, nmap services, web fingerprints, content findings, skipped
  sources, and errors).
- **`report.html`** — a self-contained, dark-themed HTML report.

The terminal shows a live, stage-based progress UI:

```
[2/6] Live host detection + tech-detect (httpx)
    -> 47 live hosts
    ✓ done (6.3s)
```

Press **Ctrl+C** to skip the current module and continue to the next; press it
again quickly to abort the remaining pipeline.

## API keys (optional)

reconductor runs with **zero configuration** — no config file, no required setup.
Key-optional sources are queried only if their environment variables are set,
and otherwise skipped with a note in the report:

| Source | Environment variable(s) |
|--------|-------------------------|
| Shodan | `SHODAN_API_KEY` |
| Censys | `CENSYS_API_ID` **and** `CENSYS_API_SECRET` |

When present, the `realip` module uses them to find hosts serving the target's
TLS certificate (additional origin-IP candidates).

## Project layout

```
cmd/reconductor/           # CLI entry point
internal/
  config/                # flag parsing
  scope/                 # target normalization + CIDR authorization prompt
  model/                 # shared State + result types
  progress/              # live stage-based terminal UI
  modules/               # one file per external tool (Module interface)
  orchestrator/          # ordered pipeline + Ctrl+C handling
  report/                # JSON, HTML, and terminal-summary rendering
```

Modules implement a small `Module` interface and are registered in
`orchestrator.DefaultModules()`, so new capabilities plug in without touching the
pipeline core.

## Testing

Unit tests cover the pure logic — flag parsing, target/CIDR resolution, tool
output parsers (nmap XML, naabu/httpx JSON, SPF, kerbrute, ldapsearch,
smbclient, WAF headers, JS endpoints), pipeline gating, and report formatting:

```bash
go test ./...          # run all tests
go test -race ./...    # with the race detector
go test -cover ./...   # with coverage
```

No test reaches the network or shells out to an external tool, so the suite is
fast and hermetic.

## Roadmap

All planned recon modules are implemented (see *Extended modules* above).
Possible future work:

- AS-REP roasting of accounts found via Kerberos user enumeration
- Recursive sitemap-index following and screenshotting of live hosts
- Additional key-optional sources (SecurityTrails, VirusTotal)

## License

For educational and authorized security-testing use.


