package main

import "testing"

func TestSanitize(t *testing.T) {
	tests := map[string]string{
		"example.com":  "example.com",
		"1.2.3.0/24":   "1.2.3.0_24",
		"a b/c:d":      "a_b_c_d",
		"__trim__":     "trim",
		"host.name-01": "host.name-01",
	}
	for in, want := range tests {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
