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
	MinShared     int
	WildcardTypes map[string]bool
	MergeSnippets bool
}

type recordSig struct {
	Name     string
	Type     string
	Content  string
	TTL      int
	Priority int
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

	snippetsOut := make(map[string]snippets.Snippet)
	wildcardTypes := make(map[string]string) // snippet name -> record type
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
			Records: []snippets.Record{rec},
		}
		wildcardTypes[name] = k.typ
		for _, sig := range sigs {
			wildcardSigs[sig] = true
		}
		for _, d := range domains {
			names := slices.Sorted(maps.Keys(namesByDomain[d]))
			wildcardRefs[d] = append(wildcardRefs[d], config.SnippetRef{Name: name, Names: names})
		}
	}

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
		key := strings.Join(domains, "\x00")
		if !opts.MergeSnippets {
			key = sig.Type + "\x00" + key
		}
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
		name := uniqueSnippetName(snippetsOut, mergedSnippetName(g.sigs))
		recs := make([]snippets.Record, 0, len(g.sigs))
		for _, sig := range g.sigs {
			recs = append(recs, snippetRecord(sig))
		}
		snippetsOut[name] = snippets.Snippet{Records: recs}
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

	usage := make(map[string]int, len(snippetsOut))
	for _, d := range domainsOut {
		for _, ref := range d.Snippets {
			usage[ref.Name]++
		}
	}
	for name, s := range snippetsOut {
		if typ, ok := wildcardTypes[name]; ok {
			s.Description = fmt.Sprintf("%s records shared by %d domains", typ, usage[name])
		} else {
			s.Description = fmt.Sprintf("Shared by %d domains", usage[name])
		}
		snippetsOut[name] = s
	}

	return &config.File{Snippets: snippetsOut, Domains: domainsOut}, nil
}

func normalise(sig recordSig, domain string) recordSig {
	return recordSig{
		Name:     templatabise(sig.Name, domain),
		Type:     sig.Type,
		Content:  templatabise(sig.Content, domain),
		TTL:      sig.TTL,
		Priority: sig.Priority,
	}
}

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

func atBoundary(s string, start, length int) bool {
	if start > 0 && isHostChar(s[start-1]) {
		return false
	}
	if end := start + length; end < len(s) && isHostChar(s[end]) {
		return false
	}
	return true
}

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

func mergedSnippetName(sigs []recordSig) string {
	types := make(map[string]bool)
	names := make(map[string]bool)
	for _, sig := range sigs {
		types[sig.Type] = true
		names[sig.Name] = true
	}
	if len(types) == 1 {
		if len(names) == 1 {
			return snippetName(sigs[0])
		}
		return slugify(sigs[0].Type)
	}
	slugs := make([]string, 0, len(types))
	for t := range types {
		slugs = append(slugs, slugify(t))
	}
	slices.Sort(slugs)
	return strings.Join(slugs, "-")
}

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

func displayName(name string) string {
	if name == "" {
		return "@"
	}
	return name
}

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
