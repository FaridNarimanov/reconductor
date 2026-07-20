# reconductor

An all-in-one **recon aggregator** for the early stages of a penetration test.
Give it a domain, IP, or CIDR range and it orchestrates several popular
open-source tools into a single pipeline.

Written in **Go using only the standard library** — external tools are invoked
via `os/exec`.

> ⚠️ For educational and authorized security-testing use only.

## Status

Early development. See the roadmap in the commit history.

## Build

```bash
go build -o reconductor ./cmd/reconductor
```
