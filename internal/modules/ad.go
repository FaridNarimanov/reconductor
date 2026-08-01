package modules

import (
	"context"
	"net"
	"sort"
	"strings"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// ActiveDirectory detects an AD environment passively via DNS SRV records
// (net.LookupSRV, no external tools). In --aggressive mode, if AD is detected,
// it additionally attempts an LDAP anonymous bind and an SMB null session
// against each discovered domain controller.
type ActiveDirectory struct{}

func (ActiveDirectory) Name() string  { return "ad" }
func (ActiveDirectory) Title() string { return "Active Directory detection (DNS SRV)" }

// Enabled: domain targets only (SRV lookups need a domain name).
func (ActiveDirectory) Enabled(cfg *config.Config, st *model.State) bool {
	return st.Target.Kind == model.TargetDomain
}

// srvQueries maps a human label to the (service, proto, name-suffix) tuple that
// net.LookupSRV expands into "_service._proto.<name>".
type srvQuery struct {
	service string
	proto   string
	// namePrefix is prepended to the domain, e.g. "dc._msdcs" for the LDAP DC
	// locator record. Empty means the bare domain.
	namePrefix string
}

func (ActiveDirectory) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	domain := st.Target.Value
	queries := []srvQuery{
		{"ldap", "tcp", "dc._msdcs"},
		{"kerberos", "tcp", ""},
		{"gc", "tcp", ""},
		{"kpasswd", "tcp", ""},
	}

	var ad model.ADResult
	dcSet := map[string]bool{}

	for _, q := range queries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := domain
		if q.namePrefix != "" {
			name = q.namePrefix + "." + domain
		}
		_, addrs, err := net.LookupSRV(q.service, q.proto, name)
		if err != nil || len(addrs) == 0 {
			continue
		}
		ad.Detected = true
		for _, a := range addrs {
			target := strings.TrimSuffix(a.Target, ".")
			ad.SRVRecords = append(ad.SRVRecords, model.SRVRecord{
				Query:  "_" + q.service + "._" + q.proto + "." + name,
				Target: target,
				Port:   a.Port,
			})
			if target != "" {
				dcSet[target] = true
			}
		}
	}

	for dc := range dcSet {
		ad.DomainControllers = append(ad.DomainControllers, dc)
	}
	sort.Strings(ad.DomainControllers)

	if !ad.Detected {
		rep.Status("no AD SRV records found")
		st.SetAD(ad)
		return nil
	}
	rep.Status("AD detected: %d domain controller(s)", len(ad.DomainControllers))

	// Aggressive-only deep recon against discovered DCs.
	if cfg.Aggressive {
		adAggressiveRecon(ctx, &ad, st, rep)
	} else {
		st.AddSkip("ad-ldap", "aggressive mode required for LDAP anonymous bind")
		st.AddSkip("ad-smb", "aggressive mode required for SMB null session")
	}

	st.SetAD(ad)
	return nil
}

// adAggressiveRecon attempts LDAP anonymous bind and SMB null session against
// each domain controller. Missing tools are recorded and skipped.
func adAggressiveRecon(ctx context.Context, ad *model.ADResult, st *model.State, rep progress.Reporter) {
	haveLdap := binaryAvailable("ldapsearch")
	haveSmb := binaryAvailable("smbclient")
	if !haveLdap {
		st.AddSkip("ad-ldap", "ldapsearch not found in PATH")
	}
	if !haveSmb {
		st.AddSkip("ad-smb", "smbclient not found in PATH")
	}

	ncSet := map[string]bool{}
	shareSet := map[string]bool{}

	for _, dc := range ad.DomainControllers {
		if ctx.Err() != nil {
			return
		}
		if haveLdap {
			rep.Status("LDAP anonymous bind -> %s", dc)
			out, err := runCapture(ctx, "", "ldapsearch",
				"-x", "-H", "ldap://"+dc, "-b", "", "-s", "base", "namingContexts")
			if err != nil {
				st.AddError("ad-ldap", err)
			} else {
				for _, nc := range parseNamingContexts(out) {
					ncSet[nc] = true
				}
			}
		}
		if haveSmb {
			rep.Status("SMB null session -> %s", dc)
			out, err := runCapture(ctx, "", "smbclient", "-L", "//"+dc, "-N", "-g")
			if err != nil {
				st.AddError("ad-smb", err)
			} else {
				for _, sh := range parseSMBShares(out) {
					shareSet[sh] = true
				}
			}
		}
	}

	for nc := range ncSet {
		ad.NamingContexts = append(ad.NamingContexts, nc)
	}
	for sh := range shareSet {
		ad.SMBShares = append(ad.SMBShares, sh)
	}
	sort.Strings(ad.NamingContexts)
	sort.Strings(ad.SMBShares)
}

// parseNamingContexts extracts "namingContexts: <dn>" values from ldapsearch.
func parseNamingContexts(out string) []string {
	var res []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "namingContexts:"); ok {
			if nc := strings.TrimSpace(v); nc != "" {
				res = append(res, nc)
			}
		}
	}
	return res
}

// parseSMBShares extracts share names from `smbclient -L -g` output lines like
// "Disk|ShareName|Comment".
func parseSMBShares(out string) []string {
	var res []string
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) >= 2 && strings.EqualFold(parts[0], "Disk") {
			if name := strings.TrimSpace(parts[1]); name != "" {
				res = append(res, name)
			}
		}
	}
	return res
}
