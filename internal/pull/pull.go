// Package pull generates a domains.yaml config from the records that exist
// on the remote DNS provider.
//
// Records are normalised by replacing occurrences of the owning domain with
// the {domain} placeholder, then grouped. Any record group that appears in
// enough domains (default 2) is promoted to a shared snippet; the rest stay
// inline in their domain.
package pull

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/greboid/dns-dashboard/internal/config"
	"github.com/greboid/dns-dashboard/internal/dns"
	"github.com/greboid/dns-dashboard/internal/snippets"
)

const domainPlaceholder = "{domain}"

// Options controls how the config is generated.
type Options struct {
	// MinShared is the minimum number of domains a record must appear in
	// (after {domain} normalisation) before it is promoted to a snippet.
	// Values below 2 are treated as 2.
	MinShared int

	// WildcardTypes are the record types eligible for wildcard snippets:
	// records with identical type and content appearing at several names
	// are emitted as one "*" snippet that each domain expands with its own
	// names list. A nil map defaults to A and RRCLONE.
	WildcardTypes map[string]bool
}

// recordSig is a normalised record identity: everything that two records must
// agree on to be considered "the same record" across domains.
type recordSig struct {
	Name     string
	Type     string
	Content  string
	TTL      int
	Priority int // -1 when unset
}

func sigOf(r dns.Record) recordSig {
	ttl := 0
	if r.TTL != nil {
		ttl = *r.TTL
	}
	priority := -1
	if r.Priority != nil {
		priority = *r.Priority
	}
	return recordSig{
		Name:     r.Name,
		Type:     r.Type,
		Content:  r.Content,
		TTL:      ttl,
		Priority: priority,
	}
}

func (s recordSig) less(other recordSig) int {
	return cmp.Or(
		cmp.Compare(s.Type, other.Type),
		cmp.Compare(s.Name, other.Name),
		cmp.Compare(s.Content, other.Content),
		cmp.Compare(s.TTL, other.TTL),
		cmp.Compare(s.Priority, other.Priority),
	)
}

// Generate builds a config from remote records. The map is keyed by domain
// name. Snippet names are derived deterministically from the record, so the
// same remote state always produces the same config.
func Generate(records map[string][]dns.Record, opts Options) (*config.File, error) {
	if opts.MinShared < 2 {
		opts.MinShared = 2
	}
	if opts.WildcardTypes == nil {
		opts.WildcardTypes = map[string]bool{"A": true, "RRCLONE": true}
	}

	domainNames := slices.Sorted(maps.Keys(records))

	perDomain := make(map[string][]recordSig)
	bySig := make(map[recordSig][]string)
	for _, domain := range domainNames {
		seen := make(map[recordSig]bool)
		for _, r := range records[domain] {
			sig := normalise(sigOf(r), domain)
			if seen[sig] {
				continue
			}
			seen[sig] = true
			perDomain[domain] = append(perDomain[domain], sig)
			bySig[sig] = append(bySig[sig], domain)
		}
	}

	// Promote wildcard candidates first: records of a wildcard-eligible
	// type with identical content (and TTL/priority) that appear at several
	// names become one "*" snippet, expanded per domain via a names list.
	snippetsOut := make(map[string]snippets.Snippet)
	wildcardSigs := make(map[recordSig]bool)
	wildcardRefs := make(map[string][]config.SnippetRef)

	type wildcardKey struct {
		typ      string
		content  string
		ttl      int
		priority int
	}
	wildcards := make(map[wildcardKey][]recordSig)
	for sig := range bySig {
		if !opts.WildcardTypes[sig.Type] {
			continue
		}
		k := wildcardKey{sig.Type, sig.Content, sig.TTL, sig.Priority}
		wildcards[k] = append(wildcards[k], sig)
	}
	for _, k := range slices.SortedFunc(maps.Keys(wildcards), func(a, b wildcardKey) int {
		return cmp.Or(
			cmp.Compare(a.typ, b.typ),
			cmp.Compare(a.content, b.content),
			cmp.Compare(a.ttl, b.ttl),
			cmp.Compare(a.priority, b.priority),
		)
	}) {
		sigs := wildcards[k]
		domainSet := make(map[string]bool)
		namesByDomain := make(map[string]map[string]bool)
		for _, sig := range sigs {
			for _, d := range bySig[sig] {
				domainSet[d] = true
				if namesByDomain[d] == nil {
					namesByDomain[d] = make(map[string]bool)
				}
				namesByDomain[d][displayName(sig.Name)] = true
			}
		}
		domains := slices.Sorted(maps.Keys(domainSet))
		if len(domains) < opts.MinShared {
			continue
		}
		// Every domain having the same single name means the scalar snippet
		// path below produces a cleaner config; leave those sigs alone.
		uniformSingle := true
		var singleName string
		for _, names := range namesByDomain {
			if len(names) != 1 {
				uniformSingle = false
				break
			}
			for name := range names {
				if singleName == "" {
					singleName = name
				} else if name != singleName {
					uniformSingle = false
					break
				}
			}
			if !uniformSingle {
				break
			}
		}
		if uniformSingle {
			continue
		}

		name := uniqueSnippetName(snippetsOut, slugify(k.typ)+"-"+wildcardSlug(k.content))
		rec := snippetRecord(sigs[0])
		rec.Name = "*"
		snippetsOut[name] = snippets.Snippet{
			Description: fmt.Sprintf("%s records shared by %d domains", k.typ, len(domains)),
			Records:     []snippets.Record{rec},
		}
		for _, sig := range sigs {
			wildcardSigs[sig] = true
		}
		for _, d := range domains {
			names := slices.Sorted(maps.Keys(namesByDomain[d]))
			wildcardRefs[d] = append(wildcardRefs[d], config.SnippetRef{Name: name, Names: names})
		}
	}

	// Promote signatures shared by enough domains to snippets, in sorted
	// order so name suffixes on collision are deterministic. Signatures of
	// the same type that are shared by exactly the same set of domains are
	// combined into a single multi-record snippet, even when their names
	// differ (e.g. the fm1/fm2/fm3._domainkey DKIM CNAMEs). Snippets whose
	// records share one name are named after it ("a-apex", "ns-apex");
	// groups spanning several names fall back to the bare type ("cname").
	sigToSnippet := make(map[recordSig]string)

	type group struct {
		domains []string
		sigs    []recordSig
	}
	groups := make(map[string]*group)
	var groupOrder []string

	for _, sig := range slices.SortedFunc(maps.Keys(bySig), recordSig.less) {
		if wildcardSigs[sig] {
			continue
		}
		domains := bySig[sig]
		if len(domains) < opts.MinShared {
			continue
		}
		key := sig.Type + "\x00" + strings.Join(domains, "\x00")
		g, ok := groups[key]
		if !ok {
			g = &group{domains: domains}
			groups[key] = g
			groupOrder = append(groupOrder, key)
		}
		g.sigs = append(g.sigs, sig)
	}

	for _, key := range groupOrder {
		g := groups[key]
		names := make(map[string]bool)
		for _, sig := range g.sigs {
			names[sig.Name] = true
		}
		base := slugify(g.sigs[0].Type)
		if len(names) == 1 {
			base = snippetName(g.sigs[0])
		}
		name := uniqueSnippetName(snippetsOut, base)
		recs := make([]snippets.Record, 0, len(g.sigs))
		for _, sig := range g.sigs {
			recs = append(recs, snippetRecord(sig))
		}
		snippetsOut[name] = snippets.Snippet{
			Description: fmt.Sprintf("Shared by %d domains", len(g.domains)),
			Records:     recs,
		}
		for _, sig := range g.sigs {
			sigToSnippet[sig] = name
		}
	}

	domainsOut := make(map[string]config.Domain)
	for _, domain := range domainNames {
		var d config.Domain
		d.Snippets = append(d.Snippets, wildcardRefs[domain]...)
		usedSnippet := make(map[string]bool)
		var inline []recordSig
		for _, sig := range perDomain[domain] {
			if wildcardSigs[sig] {
				continue
			}
			if name, ok := sigToSnippet[sig]; ok {
				if !usedSnippet[name] {
					d.Snippets = append(d.Snippets, config.SnippetRef{Name: name})
					usedSnippet[name] = true
				}
				continue
			}
			inline = append(inline, sig)
		}
		slices.SortFunc(d.Snippets, func(a, b config.SnippetRef) int {
			return cmp.Compare(a.Name, b.Name)
		})
		slices.SortFunc(inline, recordSig.less)
		for _, sig := range inline {
			d.Records = append(d.Records, config.RecordRef{Record: snippetRecord(sig)})
		}
		domainsOut[domain] = d
	}

	return &config.File{Snippets: snippetsOut, Domains: domainsOut}, nil
}

// normalise rewrites occurrences of the owning domain in the name and content
// into the {domain} placeholder so identical relative records compare equal.
func normalise(sig recordSig, domain string) recordSig {
	return recordSig{
		Name:     templatabise(sig.Name, domain),
		Type:     sig.Type,
		Content:  templatabise(sig.Content, domain),
		TTL:      sig.TTL,
		Priority: sig.Priority,
	}
}

// templatabise rewrites occurrences of the owning domain in the name and
// content into the {domain} placeholder so identical relative records
// compare equal. The domain is recognised wherever it is delimited by
// non-hostname characters: as a whole label at either end or in the middle
// (fm1.example.com.dkim.fmhosted.com), in a mailto address
// (rua=mailto:reports@example.com), or after an SPF mechanism prefix
// (a:example.com).
func templatabise(s, domain string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], domain) && atBoundary(s, i, len(domain)) {
			b.WriteString(domainPlaceholder)
			i += len(domain)
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// atBoundary reports whether the domain-sized slice at start is delimited:
// the characters either side must be outside the string or non-hostname
// characters, so the domain is never matched inside a larger name.
func atBoundary(s string, start, length int) bool {
	if start > 0 && isHostChar(s[start-1]) {
		return false
	}
	if end := start + length; end < len(s) && isHostChar(s[end]) {
		return false
	}
	return true
}

// isHostChar reports whether c can appear in a DNS label (and therefore
// glues the domain into a larger name rather than delimiting it).
func isHostChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_':
		return true
	default:
		return false
	}
}

func snippetRecord(sig recordSig) snippets.Record {
	rec := snippets.Record{
		Name:    sig.Name,
		Type:    sig.Type,
		Content: sig.Content,
	}
	if sig.TTL != 0 {
		ttl := sig.TTL
		rec.TTL = &ttl
	}
	if sig.Priority >= 0 {
		priority := sig.Priority
		rec.Priority = &priority
	}
	return rec
}

// snippetName derives a readable snippet name from the record, e.g. "a-apex"
// or "cname-www".
func snippetName(sig recordSig) string {
	name := sig.Name
	switch {
	case name == "":
		name = "apex"
	case strings.Contains(name, "*"):
		name = strings.ReplaceAll(name, "*", "wildcard")
	}
	return slugify(sig.Type) + "-" + slugify(name)
}

func slugify(s string) string {
	s = strings.ReplaceAll(s, domainPlaceholder, "domain")
	var b strings.Builder
	prevDash := true
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "record"
	}
	return out
}

// displayName renders a record name for the config: "@" for the apex.
func displayName(name string) string {
	if name == "" {
		return "@"
	}
	return name
}

// wildcardSlug derives the name suffix of a wildcard snippet from its
// record content, e.g. an A record on 203.0.113.10 becomes "a-203-0-113-10".
func wildcardSlug(content string) string {
	if content == "@" {
		return "apex"
	}
	return slugify(content)
}

func uniqueSnippetName(existing map[string]snippets.Snippet, base string) string {
	name := base
	for i := 2; ; i++ {
		if _, taken := existing[name]; !taken {
			return name
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
}
