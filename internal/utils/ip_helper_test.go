package utils

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/LanodonF/coordinate-foister/internal/logger"
	"inet.af/netaddr"
)

func TestMain(m *testing.M) {
	logger.InitLogger()
	os.Exit(m.Run())
}

func TestParseIPsPreservesExistingTargetFormats(t *testing.T) {
	withLookupIP(t, func(host string) ([]net.IP, error) {
		t.Fatalf("unexpected DNS lookup for %q", host)
		return nil, nil
	})

	ips, _, err := ParseIPs("192.168.1.5,192.168.1.10-11,10.0.0.0/30")
	if err != nil {
		t.Fatalf("ParseIPs() error = %v", err)
	}

	want := []string{
		"10.0.0.0",
		"10.0.0.1",
		"10.0.0.2",
		"10.0.0.3",
		"192.168.1.5",
		"192.168.1.10",
		"192.168.1.11",
	}
	assertIPStrings(t, ips, want)
}

func TestParseIPsResolvesDNSName(t *testing.T) {
	withLookupIP(t, func(host string) ([]net.IP, error) {
		if host != "alpha.test" {
			return nil, fmt.Errorf("unexpected host %q", host)
		}
		return []net.IP{
			net.ParseIP("203.0.113.10"),
			net.ParseIP("2001:db8::1"),
		}, nil
	})

	ips, _, err := ParseIPs("alpha.test")
	if err != nil {
		t.Fatalf("ParseIPs() error = %v", err)
	}

	assertIPStrings(t, ips, []string{"203.0.113.10", "2001:db8::1"})
}

func TestParseIPsResolvesMixedDNSAndIPTargets(t *testing.T) {
	withLookupIP(t, func(host string) ([]net.IP, error) {
		if host != "mixed.test" {
			return nil, fmt.Errorf("unexpected host %q", host)
		}
		return []net.IP{net.ParseIP("198.51.100.20")}, nil
	})

	ips, _, err := ParseIPs("mixed.test,192.0.2.1-2,10.0.0.0/31")
	if err != nil {
		t.Fatalf("ParseIPs() error = %v", err)
	}

	want := []string{
		"10.0.0.0",
		"10.0.0.1",
		"192.0.2.1",
		"192.0.2.2",
		"198.51.100.20",
	}
	assertIPStrings(t, ips, want)
}

func TestParseIPsTreatsHyphenatedHostnameAsDNSName(t *testing.T) {
	withLookupIP(t, func(host string) ([]net.IP, error) {
		if host != "hyphen-name.test" {
			return nil, fmt.Errorf("unexpected host %q", host)
		}
		return []net.IP{net.ParseIP("198.51.100.21")}, nil
	})

	ips, _, err := ParseIPs("hyphen-name.test")
	if err != nil {
		t.Fatalf("ParseIPs() error = %v", err)
	}

	assertIPStrings(t, ips, []string{"198.51.100.21"})
}

func TestParseIPsReturnsDNSLookupError(t *testing.T) {
	withLookupIP(t, func(host string) ([]net.IP, error) {
		if host != "missing.test" {
			return nil, fmt.Errorf("unexpected host %q", host)
		}
		return nil, fmt.Errorf("lookup failed")
	})

	_, _, err := ParseIPs("missing.test")
	if err == nil {
		t.Fatal("ParseIPs() error = nil, want DNS resolution error")
	}
	if !strings.Contains(err.Error(), "failed to resolve DNS target 'missing.test'") {
		t.Fatalf("ParseIPs() error = %q, want DNS target context", err)
	}
}

func TestParseIPsRejectsInvalidIPLiteralWithoutDNSLookup(t *testing.T) {
	withLookupIP(t, func(host string) ([]net.IP, error) {
		t.Fatalf("unexpected DNS lookup for %q", host)
		return nil, nil
	})

	_, _, err := ParseIPs("999.1.1.1")
	if err == nil {
		t.Fatal("ParseIPs() error = nil, want invalid IP error")
	}
	if !strings.Contains(err.Error(), "invalid IP '999.1.1.1'") {
		t.Fatalf("ParseIPs() error = %q, want invalid IP context", err)
	}
}

func TestParseIPsReturnsErrorWhenDNSHasNoUsableIPs(t *testing.T) {
	withLookupIP(t, func(host string) ([]net.IP, error) {
		if host != "empty.test" {
			return nil, fmt.Errorf("unexpected host %q", host)
		}
		return []net.IP{nil}, nil
	})

	_, _, err := ParseIPs("empty.test")
	if err == nil {
		t.Fatal("ParseIPs() error = nil, want no usable IP error")
	}
	if !strings.Contains(err.Error(), "resolved to no usable IP addresses") {
		t.Fatalf("ParseIPs() error = %q, want no usable IP context", err)
	}
}

func TestParseIPsLiveDNSForEvilblackcat(t *testing.T) {
	if os.Getenv("COORDINATE_LIVE_DNS_TEST") == "" {
		t.Skip("set COORDINATE_LIVE_DNS_TEST=1 to run live DNS smoke test")
	}

	ips, _, err := ParseIPs("evilblackcat.com")
	if err != nil {
		t.Fatalf("ParseIPs() error = %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("ParseIPs() returned no IPs for evilblackcat.com")
	}
	t.Logf("evilblackcat.com resolved to %v", ipStrings(ips))
}

func withLookupIP(t *testing.T, fn func(string) ([]net.IP, error)) {
	t.Helper()

	originalLookupIP := lookupIP
	lookupIP = fn
	t.Cleanup(func() {
		lookupIP = originalLookupIP
	})
}

func assertIPStrings(t *testing.T, got []netaddr.IP, want []string) {
	t.Helper()

	gotStrings := ipStrings(got)
	if len(gotStrings) != len(want) {
		t.Fatalf("got IPs %v, want %v", gotStrings, want)
	}

	gotSet := make(map[string]bool, len(gotStrings))
	for _, ip := range gotStrings {
		gotSet[ip] = true
	}

	for _, ip := range want {
		if !gotSet[ip] {
			t.Fatalf("got IPs %v, want %v", gotStrings, want)
		}
	}
}

func ipStrings(ips []netaddr.IP) []string {
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.String())
	}
	return result
}
