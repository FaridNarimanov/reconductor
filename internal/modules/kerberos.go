package modules

import (
	"context"
	"os"
	"regexp"
	"strings"

	"reconductor/internal/config"
	"reconductor/internal/model"
	"reconductor/internal/progress"
)

// Kerberos performs Kerberos user enumeration (AS-REQ probing) against a
// discovered domain controller using kerbrute. It runs only in --aggressive
// mode, only when AD was detected, and only if kerbrute is present in PATH.
type Kerberos struct{}

func (Kerberos) Name() string  { return "kerberos" }
func (Kerberos) Title() string { return "Kerberos user enumeration (kerbrute)" }

// Enabled: aggressive mode against a domain target. The AD-detected and
// kerbrute-present checks happen in Run so this shows as a countable stage.
func (Kerberos) Enabled(cfg *config.Config, st *model.State) bool {
	return st.Target.Kind == model.TargetDomain && cfg.Aggressive
}

// commonUsers is a small built-in username list so the module works without an
// external wordlist. It mirrors typical default/service accounts.
var commonUsers = []string{
	"administrator", "admin", "guest", "krbtgt", "root", "user", "test",
	"backup", "service", "svc", "svc-admin", "sqlservice", "sql", "web",
	"helpdesk", "support", "operator", "manager", "hr", "it", "dev",
	"jsmith", "jdoe", "ann", "bob", "alice", "mike", "john", "david",
}

// kerbruteValidRe matches kerbrute's "[+] VALID USERNAME: user@domain" output.
var kerbruteValidRe = regexp.MustCompile(`VALID USERNAME:\s+([^\s@]+)`)

func (Kerberos) Run(ctx context.Context, cfg *config.Config, st *model.State, rep progress.Reporter) error {
	ad := st.ADSnapshot()
	if !ad.Detected || len(ad.DomainControllers) == 0 {
		rep.Status("no domain controller detected; skipping")
		st.AddSkip("kerberos", "no AD/domain controller detected")
		return nil
	}
	if !binaryAvailable("kerbrute") {
		rep.Status("kerbrute not in PATH")
		st.AddSkip("kerberos", "kerbrute not found in PATH")
		return nil
	}

	// kerbrute reads usernames from a file; materialize the built-in list.
	userFile, cleanup, err := writeTempList(commonUsers)
	if err != nil {
		return err
	}
	defer cleanup()

	dc := ad.DomainControllers[0]
	rep.Status("enumerating %d candidate users against %s", len(commonUsers), dc)

	out, err := runCapture(ctx, "", "kerbrute", "userenum",
		"--dc", dc, "-d", st.Target.Value, userFile)
	// kerbrute exits non-zero when no users are found; parse output regardless.
	valid := parseKerbrute(out)
	st.AddADUsers(valid)
	rep.Status("%d valid user(s) found", len(valid))

	if err != nil && len(valid) == 0 {
		// Only surface the error when we also got nothing useful.
		return err
	}
	return nil
}

func parseKerbrute(out string) []string {
	var users []string
	for _, m := range kerbruteValidRe.FindAllStringSubmatch(out, -1) {
		users = append(users, strings.TrimSpace(m[1]))
	}
	return users
}

// writeTempList writes lines to a temp file and returns its path plus a cleanup
// function that removes it.
func writeTempList(lines []string) (string, func(), error) {
	f, err := os.CreateTemp("", "reconductor-users-*.txt")
	if err != nil {
		return "", func() {}, err
	}
	_, err = f.WriteString(strings.Join(lines, "\n") + "\n")
	closeErr := f.Close()
	if err != nil {
		os.Remove(f.Name())
		return "", func() {}, err
	}
	if closeErr != nil {
		os.Remove(f.Name())
		return "", func() {}, closeErr
	}
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}
