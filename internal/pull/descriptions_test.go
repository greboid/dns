package pull_test

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/greboid/dns-dashboard/internal/dns"
	"github.com/greboid/dns-dashboard/internal/pull"
	"gopkg.in/yaml.v3"
)

func TestSnippetDescriptionsMatchUsage(t *testing.T) {
	rec := func(name, typ, content string, ttl int) dns.Record {
		return dns.Record{Name: name, Type: typ, Content: content, TTL: new(ttl)}
	}
	recP := func(name, typ, content string, ttl, prio int) dns.Record {
		return dns.Record{Name: name, Type: typ, Content: content, TTL: new(ttl), Priority: new(prio)}
	}
	const domain = "DOMAIN"
	full := []dns.Record{
		rec("", "A", "203.0.113.10", 3600),
		rec("www", "A", "203.0.113.10", 3600),
		rec("_srv._tcp", "SRV", "10 5 80 www."+domain, 3600),
		rec("", "TXT", "v=DMARC1; p=reject; rua=mailto:dmarc-reports@"+domain, 86400),
		rec("", "TXT", "v=spf1 a mx include:spf.messagingengine.com -all", 3600),
		rec("", "NS", "ns1.mydnshost.co.uk", 86400),
		rec("", "NS", "ns2.mydnshost.co.uk", 86400),
		rec("fm1._domainkey", "CNAME", "fm1."+domain+".dkim.fmhosted.com", 86400),
		rec("fm2._domainkey", "CNAME", "fm2."+domain+".dkim.fmhosted.com", 86400),
		recP("", "MX", "mail."+domain, 3600, 10),
	}
	project := func(d string) []dns.Record {
		out := make([]dns.Record, 0, len(full))
		for _, r := range full {
			r.Content = strings.ReplaceAll(r.Content, domain, d)
			out = append(out, r)
		}
		return out
	}
	nsOnly := func(d string, ttl int) []dns.Record {
		return []dns.Record{
			rec("", "NS", "ns1.mydnshost.co.uk", ttl),
			rec("", "NS", "ns2.mydnshost.co.uk", ttl),
		}
	}

	records := map[string][]dns.Record{}
	six := []string{"dioberg.test", "g5da.test", "g5db.test", "greboida.test", "greboidb.test", "greg.test"}
	for _, d := range six {
		records[d] = project(d)
	}

	records["x.test"] = []dns.Record{
		rec("", "NS", "ns1.mydnshost.co.uk", 86400),
		rec("", "NS", "ns2.mydnshost.co.uk", 86400),
		rec("fm1._domainkey", "CNAME", "fm1.x.test.dkim.fmhosted.com", 86400),
		rec("fm2._domainkey", "CNAME", "fm2.x.test.dkim.fmhosted.com", 86400),
		recP("", "MX", "mail.x.test", 3600, 10),
	}
	records["nsa.test"] = nsOnly("nsa.test", 86400)
	records["nsb.test"] = nsOnly("nsb.test", 86400)
	records["nsc.test"] = nsOnly("nsc.test", 3600)

	cfg, err := pull.Generate(records, pull.Options{MergeSnippets: true})
	if err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	usage := map[string]int{}
	for d, v := range doc["domains"].(map[string]any) {
		refs, ok := v.(map[string]any)["snippets"].([]any)
		if !ok && d != "nsc.test" {
			t.Errorf("domain %s has no snippet refs", d)
			continue
		}
		for _, r := range refs {
			switch ref := r.(type) {
			case string:
				usage[ref]++
			case map[string]any:
				for name := range ref {
					usage[fmt.Sprintf("%v", name)]++
				}
			}
		}
	}

	re := regexp.MustCompile(`(?i)shared by (\d+) domains`)
	for name, v := range doc["snippets"].(map[string]any) {
		desc, _ := v.(map[string]any)["description"].(string)
		m := re.FindStringSubmatch(desc)
		if m == nil {
			t.Errorf("snippet %s has no usage in its description: %q", name, desc)
			continue
		}
		claimed, _ := strconv.Atoi(m[1])
		if claimed != usage[name] {
			t.Errorf("snippet %s claims %d domains but is used by %d", name, claimed, usage[name])
		}
	}

	if usage["ns-apex"] != 9 {
		t.Errorf("ns-apex used by %d domains, want 9", usage["ns-apex"])
	}
	if usage["cname-mx"] != 7 {
		t.Errorf("cname-mx used by %d domains, want 7", usage["cname-mx"])
	}
	if usage["a-203-0-113-10"] != 6 {
		t.Errorf("a-203-0-113-10 used by %d domains, want 6", usage["a-203-0-113-10"])
	}
}
