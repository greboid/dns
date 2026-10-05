package pull_test

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greboid/dns-dashboard/internal/config"
	"github.com/greboid/dns-dashboard/internal/dns"
	"github.com/greboid/dns-dashboard/internal/pull"
	"github.com/greboid/dns-dashboard/internal/snippets"
	"gopkg.in/yaml.v3"
)

func recordSet(records []snippets.Record) map[string]bool {
	set := make(map[string]bool)
	for _, r := range records {
		set[r.Name+"\x00"+r.Type+"\x00"+r.Content] = true
	}
	return set
}

func TestGenerateRoundTrip(t *testing.T) {
	input := map[string][]dns.Record{
		"alpha.test": {
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "www", Type: "CNAME", Content: "alpha.test.", TTL: new(3600)},
			{Name: "", Type: "MX", Content: "mail.alpha.test", TTL: new(3600), Priority: new(10)},
			{Name: "", Type: "TXT", Content: "alpha-only", TTL: new(300)},
		},
		"beta.test": {
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "www", Type: "CNAME", Content: "beta.test.", TTL: new(3600)},
			{Name: "", Type: "MX", Content: "mail.beta.test", TTL: new(3600), Priority: new(10)},
		},
		"gamma.test": {
			{Name: "", Type: "A", Content: "203.0.113.99", TTL: new(3600)},
		},
	}
	expected := map[string][]snippets.Record{
		"alpha.test": {
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "", Type: "MX", Content: "mail.alpha.test", TTL: new(3600), Priority: new(10)},
			{Name: "www", Type: "CNAME", Content: "alpha.test.", TTL: new(3600)},
			{Name: "", Type: "TXT", Content: "alpha-only", TTL: new(300)},
		},
		"beta.test": {
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "", Type: "MX", Content: "mail.beta.test", TTL: new(3600), Priority: new(10)},
			{Name: "www", Type: "CNAME", Content: "beta.test.", TTL: new(3600)},
		},
		"gamma.test": {
			{Name: "", Type: "A", Content: "203.0.113.99", TTL: new(3600)},
		},
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(cfg.Snippets) != 3 {
		t.Fatalf("expected 3 snippets, got %d: %v", len(cfg.Snippets), cfg.Snippets)
	}
	for _, want := range []string{"a-apex", "cname-www", "mx-apex"} {
		if _, ok := cfg.Snippets[want]; !ok {
			t.Errorf("missing snippet %q, have %v", want, slices.Sorted(maps.Keys(cfg.Snippets)))
		}
	}

	path := filepath.Join(t.TempDir(), "domains.yaml")
	writeConfig(t, path, cfg)

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, domain := range loaded.DomainNames() {
		got, err := loaded.ExpandRecords(domain)
		if err != nil {
			t.Fatalf("ExpandRecords(%s): %v", domain, err)
		}
		wantSet := recordSet(expected[domain])
		gotSet := recordSet(got)
		for key := range wantSet {
			if !gotSet[key] {
				t.Errorf("%s: missing record %q", domain, key)
			}
		}
		for key := range gotSet {
			if !wantSet[key] {
				t.Errorf("%s: unexpected record %q", domain, key)
			}
		}
		if len(got) != len(expected[domain]) {
			t.Errorf("%s: got %d records, want %d", domain, len(got), len(expected[domain]))
		}
	}
}

func TestGenerateMinSharedThreshold(t *testing.T) {
	input := map[string][]dns.Record{
		"alpha.test": {{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)}},
		"beta.test":  {{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)}},
		"gamma.test": {{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)}},
	}

	cfg, err := pull.Generate(input, pull.Options{MinShared: 4})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cfg.Snippets) != 0 {
		t.Fatalf("expected no snippets with MinShared=4, got %d", len(cfg.Snippets))
	}
	for _, domain := range []string{"alpha.test", "beta.test", "gamma.test"} {
		if len(cfg.Domains[domain].Records) != 1 {
			t.Errorf("%s: expected 1 inline record, got %d", domain, len(cfg.Domains[domain].Records))
		}
	}
}

func TestGenerateSnippetNameCollisions(t *testing.T) {
	input := map[string][]dns.Record{
		"alpha.test": {
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "", Type: "A", Content: "203.0.113.11", TTL: new(3600)},
		},
		"beta.test": {
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "", Type: "A", Content: "203.0.113.11", TTL: new(3600)},
		},
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cfg.Snippets) != 1 {
		t.Fatalf("expected 1 merged snippet, got %d", len(cfg.Snippets))
	}
	snippet, ok := cfg.Snippets["a-apex"]
	if !ok {
		t.Fatalf("missing snippet a-apex")
	}
	if len(snippet.Records) != 2 {
		t.Errorf("expected 2 records in merged snippet, got %d", len(snippet.Records))
	}
	for _, domain := range []string{"alpha.test", "beta.test"} {
		if refs := len(cfg.Domains[domain].Snippets); refs != 1 {
			t.Errorf("%s: expected 1 snippet ref, got %d", domain, refs)
		}
		if refs := len(cfg.Domains[domain].Records); refs != 0 {
			t.Errorf("%s: expected 0 inline records, got %d", domain, refs)
		}
	}
}

func TestGenerateMergesSharedNSTypes(t *testing.T) {
	ns := func(content string) dns.Record {
		return dns.Record{Name: "", Type: "NS", Content: content, TTL: new(86400)}
	}
	domainRecords := func() []dns.Record {
		return []dns.Record{ns("ns1.mydnshost.co.uk"), ns("ns2.mydnshost.co.uk"), ns("ns3.mydnshost.co.uk"), ns("ns4.mydnshost.co.uk")}
	}
	input := map[string][]dns.Record{
		"alpha.test": domainRecords(),
		"beta.test":  domainRecords(),
		"gamma.test": domainRecords(),
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cfg.Snippets) != 1 {
		t.Fatalf("expected 1 snippet for the 4 shared NS records, got %d", len(cfg.Snippets))
	}
	snippet, ok := cfg.Snippets["ns-apex"]
	if !ok {
		t.Fatalf("missing snippet ns-apex, have %v", cfg.Snippets)
	}
	if len(snippet.Records) != 4 {
		t.Errorf("expected 4 NS records in the snippet, got %d", len(snippet.Records))
	}
	for _, domain := range []string{"alpha.test", "beta.test", "gamma.test"} {
		if refs := len(cfg.Domains[domain].Snippets); refs != 1 {
			t.Errorf("%s: expected 1 snippet ref, got %d", domain, refs)
		}
	}

	// The merged snippet must expand back to exactly the original records.
	path := filepath.Join(t.TempDir(), "domains.yaml")
	writeConfig(t, path, cfg)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, domain := range loaded.DomainNames() {
		got, err := loaded.ExpandRecords(domain)
		if err != nil {
			t.Fatalf("ExpandRecords(%s): %v", domain, err)
		}
		want := recordSet([]snippets.Record{
			{Name: "", Type: "NS", Content: "ns1.mydnshost.co.uk", TTL: new(86400)},
			{Name: "", Type: "NS", Content: "ns2.mydnshost.co.uk", TTL: new(86400)},
			{Name: "", Type: "NS", Content: "ns3.mydnshost.co.uk", TTL: new(86400)},
			{Name: "", Type: "NS", Content: "ns4.mydnshost.co.uk", TTL: new(86400)},
		})
		if !maps.Equal(recordSet(got), want) {
			t.Errorf("%s: expanded records %v do not match original", domain, got)
		}
	}
}

func TestGenerateSeparatesRecordsWithDifferentDomainSets(t *testing.T) {
	googleMx := dns.Record{Name: "", Type: "MX", Content: "smtp.google.com", TTL: new(3600), Priority: new(10)}
	fastmailMx := dns.Record{Name: "", Type: "MX", Content: "in1-smtp.messagingengine.com", TTL: new(3600), Priority: new(10)}
	input := map[string][]dns.Record{
		"alpha.test": {googleMx},
		"beta.test":  {googleMx},
		"gamma.test": {fastmailMx},
		"delta.test": {fastmailMx},
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cfg.Snippets) != 2 {
		t.Fatalf("expected 2 snippets, got %d", len(cfg.Snippets))
	}
	if _, ok := cfg.Snippets["mx-apex"]; !ok {
		t.Errorf("missing snippet mx-apex")
	}
	if _, ok := cfg.Snippets["mx-apex-2"]; !ok {
		t.Errorf("missing snippet mx-apex-2")
	}
	if got := len(cfg.Domains["alpha.test"].Snippets); got != 1 {
		t.Errorf("alpha.test: expected 1 snippet ref, got %d", got)
	}
	if got := len(cfg.Domains["gamma.test"].Snippets); got != 1 {
		t.Errorf("gamma.test: expected 1 snippet ref, got %d", got)
	}
	if cfg.Domains["alpha.test"].Snippets[0].Name == cfg.Domains["gamma.test"].Snippets[0].Name {
		t.Errorf("alpha and gamma should reference different snippets, both reference %s", cfg.Domains["alpha.test"].Snippets[0].Name)
	}
}

func TestGenerateOutputFormat(t *testing.T) {
	input := map[string][]dns.Record{
		"alpha.test": {
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "www", Type: "CNAME", Content: "alpha.test.", TTL: new(3600)},
		},
		"beta.test": {
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "www", Type: "CNAME", Content: "beta.test.", TTL: new(3600)},
		},
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	t.Logf("generated config:\n%s", out)

	for _, want := range []string{
		"snippets:",
		"a-apex:",
		"name: '@'",
		"cname-www:",
		"content: '{domain}.'",
		"alpha.test:",
		"- a-apex",
		"- cname-www",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("generated YAML missing %q:\n%s", want, out)
		}
	}
}

func writeConfig(t *testing.T, path string, cfg *config.File) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestGenerateWildcardSnippets(t *testing.T) {
	a := func(name string) dns.Record {
		return dns.Record{Name: name, Type: "A", Content: "203.0.113.10", TTL: new(3600)}
	}
	input := map[string][]dns.Record{
		"alpha.test": {a(""), a("www")},
		"beta.test":  {a(""), a("www")},
		"gamma.test": {a(""), a("www"), a("mail")},
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cfg.Snippets) != 1 {
		t.Fatalf("expected 1 wildcard snippet, got %d", len(cfg.Snippets))
	}
	snippet, ok := cfg.Snippets["a-203-0-113-10"]
	if !ok {
		t.Fatalf("missing snippet a-203-0-113-10, have %v", cfg.Snippets)
	}
	if len(snippet.Records) != 1 || snippet.Records[0].Name != "*" {
		t.Errorf("expected a single wildcard record, got %+v", snippet.Records)
	}
	wantNames := map[string][]string{
		"alpha.test": {"@", "www"},
		"beta.test":  {"@", "www"},
		"gamma.test": {"@", "mail", "www"},
	}
	for domain, want := range wantNames {
		refs := cfg.Domains[domain].Snippets
		if len(refs) != 1 || !slices.Equal(refs[0].Names, want) {
			t.Errorf("%s: got refs %+v, want names %v", domain, refs, want)
		}
		if len(cfg.Domains[domain].Records) != 0 {
			t.Errorf("%s: expected no inline records", domain)
		}
	}

	path := filepath.Join(t.TempDir(), "domains.yaml")
	writeConfig(t, path, cfg)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for domain, want := range wantNames {
		got, err := loaded.ExpandRecords(domain)
		if err != nil {
			t.Fatalf("ExpandRecords(%s): %v", domain, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: got %d records, want %d", domain, len(got), len(want))
		}
		for i, name := range want {
			expanded := ""
			if name != "@" {
				expanded = name
			}
			if got[i].Name != expanded || got[i].Type != "A" || got[i].Content != "203.0.113.10" {
				t.Errorf("%s: record %d = %+v, want A %s 203.0.113.10", domain, i, got[i], expanded)
			}
		}
	}
}

func TestGenerateWildcardUniformSingleNameStaysScalar(t *testing.T) {
	a := dns.Record{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)}
	input := map[string][]dns.Record{
		"alpha.test": {a},
		"beta.test":  {a},
		"gamma.test": {a},
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, ok := cfg.Snippets["a-apex"]; !ok {
		t.Fatalf("expected scalar snippet a-apex, have %v", cfg.Snippets)
	}
	for domain := range cfg.Domains {
		for _, ref := range cfg.Domains[domain].Snippets {
			if len(ref.Names) != 0 {
				t.Errorf("%s: expected scalar snippet ref, got names %v", domain, ref.Names)
			}
		}
	}
}

func TestGenerateWildcardDifferentContentSeparate(t *testing.T) {
	a := func(content string, names ...string) []dns.Record {
		var out []dns.Record
		for _, n := range names {
			out = append(out, dns.Record{Name: n, Type: "A", Content: content, TTL: new(3600)})
		}
		return out
	}
	input := map[string][]dns.Record{
		"alpha.test": append(a("203.0.113.10", "", "www"), a("203.0.113.11", "", "www")...),
		"beta.test":  append(a("203.0.113.10", "", "www"), a("203.0.113.11", "", "www")...),
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cfg.Snippets) != 2 {
		t.Fatalf("expected 2 wildcard snippets, got %d", len(cfg.Snippets))
	}
	for _, want := range []string{"a-203-0-113-10", "a-203-0-113-11"} {
		if _, ok := cfg.Snippets[want]; !ok {
			t.Errorf("missing snippet %s, have %v", want, cfg.Snippets)
		}
	}
	if refs := cfg.Domains["alpha.test"].Snippets; len(refs) != 2 {
		t.Errorf("alpha.test: expected 2 snippet refs, got %d", len(refs))
	}
}

func TestGenerateWildcardDomainPlaceholderContent(t *testing.T) {
	rrclone := func(content string, names ...string) []dns.Record {
		var out []dns.Record
		for _, n := range names {
			out = append(out, dns.Record{Name: n, Type: "RRCLONE", Content: content, TTL: new(3600)})
		}
		return out
	}
	input := map[string][]dns.Record{
		"alpha.test": rrclone("alpha.test", "www", "mail"),
		"beta.test":  rrclone("beta.test", "www", "mail"),
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	snippet, ok := cfg.Snippets["rrclone-domain"]
	if !ok {
		t.Fatalf("missing wildcard snippet rrclone-domain, have %v", cfg.Snippets)
	}
	if snippet.Records[0].Content != "{domain}" {
		t.Errorf("expected templated content {domain}, got %q", snippet.Records[0].Content)
	}

	path := filepath.Join(t.TempDir(), "domains.yaml")
	writeConfig(t, path, cfg)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, domain := range loaded.DomainNames() {
		got, err := loaded.ExpandRecords(domain)
		if err != nil {
			t.Fatalf("ExpandRecords(%s): %v", domain, err)
		}
		want := map[string]bool{
			"www\x00RRCLONE\x00" + domain:  true,
			"mail\x00RRCLONE\x00" + domain: true,
		}
		if !maps.Equal(recordSet(got), want) {
			t.Errorf("%s: expanded records %v do not match original", domain, got)
		}
	}
}

func TestGenerateMergesDKIMPattern(t *testing.T) {
	domains := []string{"alpha.test", "beta.test", "gamma.test"}
	input := make(map[string][]dns.Record)
	for _, d := range domains {
		input[d] = []dns.Record{
			{Name: "fm1._domainkey", Type: "CNAME", Content: "fm1." + d + ".dkim.fmhosted.com", TTL: new(86400)},
			{Name: "fm2._domainkey", Type: "CNAME", Content: "fm2." + d + ".dkim.fmhosted.com", TTL: new(86400)},
			{Name: "fm3._domainkey", Type: "CNAME", Content: "fm3." + d + ".dkim.fmhosted.com", TTL: new(86400)},
		}
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cfg.Snippets) != 1 {
		t.Fatalf("expected 1 merged snippet, got %d", len(cfg.Snippets))
	}
	snippet, ok := cfg.Snippets["cname"]
	if !ok {
		t.Fatalf("missing snippet cname, have %v", cfg.Snippets)
	}
	if len(snippet.Records) != 3 {
		t.Fatalf("expected 3 records in merged snippet, got %d", len(snippet.Records))
	}
	for i, fm := range []string{"fm1", "fm2", "fm3"} {
		r := snippet.Records[i]
		if r.Name != fm+"._domainkey" || r.Content != fm+".{domain}.dkim.fmhosted.com" {
			t.Errorf("snippet record %d = %+v, want %s._domainkey -> %s.{domain}.dkim.fmhosted.com", i, r, fm, fm)
		}
	}
	for _, d := range domains {
		if refs := len(cfg.Domains[d].Snippets); refs != 1 {
			t.Errorf("%s: expected 1 snippet ref, got %d", d, refs)
		}
		if refs := len(cfg.Domains[d].Records); refs != 0 {
			t.Errorf("%s: expected no inline records, got %d", d, refs)
		}
	}

	path := filepath.Join(t.TempDir(), "domains.yaml")
	writeConfig(t, path, cfg)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, d := range domains {
		got, err := loaded.ExpandRecords(d)
		if err != nil {
			t.Fatalf("ExpandRecords(%s): %v", d, err)
		}
		want := recordSet([]snippets.Record{
			{Name: "fm1._domainkey", Type: "CNAME", Content: "fm1." + d + ".dkim.fmhosted.com", TTL: new(86400)},
			{Name: "fm2._domainkey", Type: "CNAME", Content: "fm2." + d + ".dkim.fmhosted.com", TTL: new(86400)},
			{Name: "fm3._domainkey", Type: "CNAME", Content: "fm3." + d + ".dkim.fmhosted.com", TTL: new(86400)},
		})
		if !maps.Equal(recordSet(got), want) {
			t.Errorf("%s: expanded records %v do not match original", d, got)
		}
	}
}

func TestGenerateMergesDMARCPattern(t *testing.T) {
	domains := []string{"alpha.test", "beta.test", "gamma.test"}
	input := make(map[string][]dns.Record)
	for _, d := range domains {
		input[d] = []dns.Record{
			{Name: "", Type: "TXT", Content: "v=DMARC1; p=reject; rua=mailto:dmarc-reports@" + d, TTL: new(86400)},
		}
	}

	cfg, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	snippet, ok := cfg.Snippets["txt-apex"]
	if !ok {
		t.Fatalf("missing snippet txt-apex, have %v", cfg.Snippets)
	}
	if len(snippet.Records) != 1 {
		t.Fatalf("expected 1 record in merged snippet, got %d", len(snippet.Records))
	}
	if got := snippet.Records[0].Content; got != "v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}" {
		t.Errorf("snippet content = %q", got)
	}
	for _, d := range domains {
		if refs := len(cfg.Domains[d].Snippets); refs != 1 {
			t.Errorf("%s: expected 1 snippet ref, got %d", d, refs)
		}
		if refs := len(cfg.Domains[d].Records); refs != 0 {
			t.Errorf("%s: expected no inline records, got %d", d, refs)
		}
	}

	path := filepath.Join(t.TempDir(), "domains.yaml")
	writeConfig(t, path, cfg)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, d := range domains {
		got, err := loaded.ExpandRecords(d)
		if err != nil {
			t.Fatalf("ExpandRecords(%s): %v", d, err)
		}
		want := recordSet([]snippets.Record{
			{Name: "", Type: "TXT", Content: "v=DMARC1; p=reject; rua=mailto:dmarc-reports@" + d, TTL: new(86400)},
		})
		if !maps.Equal(recordSet(got), want) {
			t.Errorf("%s: expanded records %v do not match original", d, got)
		}
	}
}

func TestGenerateMergesSnippetsSharedAcrossDomains(t *testing.T) {
	input := map[string][]dns.Record{
		"alpha.test": {
			{Name: "", Type: "NS", Content: "ns1.mydnshost.co.uk", TTL: new(86400)},
			{Name: "", Type: "NS", Content: "ns2.mydnshost.co.uk", TTL: new(86400)},
			{Name: "", Type: "TXT", Content: "v=DMARC1; rua=mailto:d@alpha.test", TTL: new(3600)},
			{Name: "", Type: "MX", Content: "mail.alpha.test", TTL: new(3600), Priority: new(10)},
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "www", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
		},
		"beta.test": {
			{Name: "", Type: "NS", Content: "ns1.mydnshost.co.uk", TTL: new(86400)},
			{Name: "", Type: "NS", Content: "ns2.mydnshost.co.uk", TTL: new(86400)},
			{Name: "", Type: "TXT", Content: "v=DMARC1; rua=mailto:d@beta.test", TTL: new(3600)},
			{Name: "", Type: "MX", Content: "mail.beta.test", TTL: new(3600), Priority: new(10)},
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "www", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
		},
	}

	cfg, err := pull.Generate(input, pull.Options{MergeSnippets: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cfg.Snippets) != 2 {
		t.Fatalf("expected 2 snippets, got %d: %v", len(cfg.Snippets), cfg.Snippets)
	}
	merged, ok := cfg.Snippets["mx-ns-txt"]
	if !ok {
		t.Fatalf("missing merged snippet mx-ns-txt, have %v", cfg.Snippets)
	}
	if len(merged.Records) != 4 {
		t.Errorf("expected 4 records in merged snippet, got %d", len(merged.Records))
	}
	if _, ok := cfg.Snippets["a-203-0-113-10"]; !ok {
		t.Errorf("missing wildcard snippet a-203-0-113-10")
	}
	for _, d := range []string{"alpha.test", "beta.test"} {
		refs := cfg.Domains[d].Snippets
		if len(refs) != 2 {
			t.Errorf("%s: expected 2 snippet refs, got %d", d, len(refs))
		}
		for _, ref := range refs {
			if len(ref.Names) != 0 && ref.Name != "a-203-0-113-10" {
				t.Errorf("%s: unexpected names on scalar ref %s", d, ref.Name)
			}
		}
		if len(cfg.Domains[d].Records) != 0 {
			t.Errorf("%s: expected no inline records", d)
		}
	}

	path := filepath.Join(t.TempDir(), "domains.yaml")
	writeConfig(t, path, cfg)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, d := range []string{"alpha.test", "beta.test"} {
		got, err := loaded.ExpandRecords(d)
		if err != nil {
			t.Fatalf("ExpandRecords(%s): %v", d, err)
		}
		want := recordSet([]snippets.Record{
			{Name: "", Type: "NS", Content: "ns1.mydnshost.co.uk", TTL: new(86400)},
			{Name: "", Type: "NS", Content: "ns2.mydnshost.co.uk", TTL: new(86400)},
			{Name: "", Type: "TXT", Content: "v=DMARC1; rua=mailto:d@" + d, TTL: new(3600)},
			{Name: "", Type: "MX", Content: "mail." + d, TTL: new(3600), Priority: new(10)},
			{Name: "", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
			{Name: "www", Type: "A", Content: "203.0.113.10", TTL: new(3600)},
		})
		if !maps.Equal(recordSet(got), want) {
			t.Errorf("%s: expanded records %v do not match original", d, got)
		}
	}

	cfgOff, err := pull.Generate(input, pull.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{"ns-apex", "txt-apex", "mx-apex", "a-203-0-113-10"} {
		if _, ok := cfgOff.Snippets[want]; !ok {
			t.Errorf("MergeSnippets off: missing snippet %s, have %v", want, cfgOff.Snippets)
		}
	}
}
