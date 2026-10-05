package pull

import "testing"

func TestTemplatabise(t *testing.T) {
	cases := []struct {
		in     string
		domain string
		want   string
	}{
		{"dioberg.co.uk", "dioberg.co.uk", "{domain}"},
		{"dioberg.co.uk.", "dioberg.co.uk", "{domain}."},
		{"www.dioberg.co.uk", "dioberg.co.uk", "www.{domain}"},
		{"fm1.dioberg.co.uk.dkim.fmhosted.com", "dioberg.co.uk", "fm1.{domain}.dkim.fmhosted.com"},
		{"v=DMARC1; p=reject; rua=mailto:dmarc-reports@dioberg.co.uk", "dioberg.co.uk",
			"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}"},
		{"rua=mailto:d@dioberg.co.uk; pct=100", "dioberg.co.uk", "rua=mailto:d@{domain}; pct=100"},
		{"v=spf1 mx a:dioberg.co.uk ~all", "dioberg.co.uk", "v=spf1 mx a:{domain} ~all"},
		{"xdioberg.co.uk", "dioberg.co.uk", "xdioberg.co.uk"},
		{"dioberg.co.ukx", "dioberg.co.uk", "dioberg.co.ukx"},
		{"foo_dioberg.co.uk", "dioberg.co.uk", "foo_dioberg.co.uk"},
		{"foo-dioberg.co.uk", "dioberg.co.uk", "foo-dioberg.co.uk"},
		{"fmhosted.com", "dioberg.co.uk", "fmhosted.com"},
		{"short.co.uk", "dioberg.co.uk", "short.co.uk"},
		{"fm1._domainkey", "dioberg.co.uk", "fm1._domainkey"},
		{"dioberg.co.uk.dioberg.co.uk", "dioberg.co.uk", "{domain}.{domain}"},
	}
	for _, c := range cases {
		if got := templatabise(c.in, c.domain); got != c.want {
			t.Errorf("templatabise(%q, %q) = %q, want %q", c.in, c.domain, got, c.want)
		}
	}
}
