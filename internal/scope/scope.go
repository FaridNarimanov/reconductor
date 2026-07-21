// Package scope turns raw CLI target flags into a normalized model.Target and
// enforces the mandatory confirmation prompt for CIDR ranges.
package scope

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"

	"reconductor/internal/config"
	"reconductor/internal/model"
)

// MaxCIDRHosts caps how many host addresses we expand from a CIDR range so an
// accidental /8 does not generate millions of entries.
const MaxCIDRHosts = 65536

// Resolve builds a model.Target from the configuration. For CIDR targets it
// prompts on prompt/promptOut for explicit "yes" confirmation before expanding
// the range; any other answer aborts with an error.
func Resolve(cfg *config.Config, promptIn io.Reader, promptOut io.Writer) (model.Target, error) {
	switch {
	case cfg.Domain != "":
		return model.Target{
			Kind:  model.TargetDomain,
			Value: cfg.Domain,
			Hosts: []string{cfg.Domain},
		}, nil

	case cfg.IP != "":
		if net.ParseIP(cfg.IP) == nil {
			return model.Target{}, fmt.Errorf("invalid IP address: %q", cfg.IP)
		}
		return model.Target{
			Kind:  model.TargetIP,
			Value: cfg.IP,
			Hosts: []string{cfg.IP},
		}, nil

	case cfg.CIDR != "":
		hosts, err := expandCIDR(cfg.CIDR)
		if err != nil {
			return model.Target{}, err
		}
		if err := confirmCIDR(cfg.CIDR, len(hosts), promptIn, promptOut); err != nil {
			return model.Target{}, err
		}
		return model.Target{
			Kind:  model.TargetCIDR,
			Value: cfg.CIDR,
			Hosts: hosts,
		}, nil
	}
	return model.Target{}, fmt.Errorf("no target specified")
}

// confirmCIDR enforces the mandatory authorization prompt. Only the exact
// answer "yes" allows the scan to proceed.
func confirmCIDR(cidr string, count int, in io.Reader, out io.Writer) error {
	fmt.Fprintf(out, "\n[!] You are about to scan the CIDR range %s (%d hosts).\n", cidr, count)
	fmt.Fprintf(out, "    Do you have authorization to scan this range? Type 'yes' to continue: ")

	reader := bufio.NewReader(in)
	line, _ := reader.ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return fmt.Errorf("CIDR scan aborted: authorization not confirmed")
	}
	return nil
}

// expandCIDR returns every usable host address in the range.
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var hosts []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); inc(cur) {
		hosts = append(hosts, cur.String())
		if len(hosts) > MaxCIDRHosts {
			return nil, fmt.Errorf("CIDR range too large (>%d hosts); narrow the range", MaxCIDRHosts)
		}
	}

	// Drop network and broadcast addresses for ranges larger than /31.
	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

// inc increments an IP address in place.
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
