// Package config parses and holds the command-line configuration for reconductor.
package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config holds every runtime option derived from CLI flags.
type Config struct {
	Domain     string
	IP         string
	CIDR       string
	Aggressive bool
	Output     string
	JSONOnly   bool
	Skip       map[string]bool
	Threads    int
	Wordlist   string
	Verbose    bool
}

// stringList implements flag.Value for repeatable string flags (--skip).
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// Parse reads os.Args and returns a validated Config. It supports both the
// short (-d) and long (--domain) form of every flag.
func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("reconductor", flag.ContinueOnError)

	var (
		domain, ip, cidr, output, wordlist string
		aggressive, jsonOnly, verbose      bool
		threads                            int
		skips                              stringList
	)

	// Register each option under both its short and long name; both write into
	// the same variable so either form works.
	fs.StringVar(&domain, "d", "", "Domain target")
	fs.StringVar(&domain, "domain", "", "Domain target")
	fs.StringVar(&ip, "i", "", "Single IP target")
	fs.StringVar(&ip, "ip", "", "Single IP target")
	fs.StringVar(&cidr, "c", "", "CIDR range target (triggers confirmation prompt)")
	fs.StringVar(&cidr, "cidr", "", "CIDR range target (triggers confirmation prompt)")
	fs.BoolVar(&aggressive, "aggressive", false, "Enable all aggressive operations")
	fs.StringVar(&output, "o", "", "Output directory (default: ./recon_<target>_<timestamp>/)")
	fs.StringVar(&output, "output", "", "Output directory (default: ./recon_<target>_<timestamp>/)")
	fs.BoolVar(&jsonOnly, "json", false, "JSON output only (no HTML report)")
	fs.Var(&skips, "skip", "Disable a module (repeatable): --skip feroxbuster --skip whatweb")
	fs.IntVar(&threads, "t", 20, "Overall parallelism level")
	fs.IntVar(&threads, "threads", 20, "Overall parallelism level")
	fs.StringVar(&wordlist, "wordlist", "", "Custom wordlist path for feroxbuster")
	fs.BoolVar(&verbose, "v", false, "Verbose debug logging")
	fs.BoolVar(&verbose, "verbose", false, "Verbose debug logging")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "reconductor - all-in-one recon aggregator\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  reconductor -d example.com\n  reconductor -i 1.2.3.4\n  reconductor -c 1.2.3.0/24\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg := &Config{
		Domain:     strings.TrimSpace(domain),
		IP:         strings.TrimSpace(ip),
		CIDR:       strings.TrimSpace(cidr),
		Aggressive: aggressive,
		Output:     output,
		JSONOnly:   jsonOnly,
		Skip:       map[string]bool{},
		Threads:    threads,
		Wordlist:   wordlist,
		Verbose:    verbose,
	}
	for _, s := range skips {
		cfg.Skip[strings.ToLower(strings.TrimSpace(s))] = true
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	n := 0
	if c.Domain != "" {
		n++
	}
	if c.IP != "" {
		n++
	}
	if c.CIDR != "" {
		n++
	}
	switch {
	case n == 0:
		return fmt.Errorf("no target specified: use -d, -i, or -c")
	case n > 1:
		return fmt.Errorf("only one target type may be specified at a time")
	}
	if c.Threads < 1 {
		c.Threads = 1
	}
	return nil
}

// IsSkipped reports whether the named module was disabled via --skip.
func (c *Config) IsSkipped(module string) bool {
	return c.Skip[strings.ToLower(module)]
}
