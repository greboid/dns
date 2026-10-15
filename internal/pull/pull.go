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
	g := newGenerator(opts)
	g.indexRecords(records)
	g.addWildcardSnippets()
	g.addSharedSnippets()
	domains := g.assembleDomains(slices.Sorted(maps.Keys(records)))
	return &config.File{
		Snippets: g.describeSnippets(domains),
		Domains:  domains,
	}, nil
}

type generator struct {
	opts Options

	perDomain map[string][]recordSig
	bySig     map[recordSig][]string

	snippets      map[string]snippets.Snippet
	sigToSnippet  map[recordSig]string
	wildcardSigs  map[recordSig]bool
	wildcardTypes map[string]string
	wildcardRefs  map[string][]*config.SnippetRef
}

func newGenerator(opts Options) *generator {
	if opts.MinShared < 2 {
		opts.MinShared = 2
	}
	if opts.WildcardTypes == nil {
		opts.WildcardTypes = map[string]bool{"A": true, "RRCLONE": true}
	}
	return &generator{
		opts:          opts,
		perDomain:     make(map[string][]recordSig),
		bySig:         make(map[recordSig][]string),
		snippets:      make(map[string]snippets.Snippet),
		sigToSnippet:  make(map[recordSig]string),
		wildcardSigs:  make(map[recordSig]bool),
		wildcardTypes: make(map[string]string),
		wildcardRefs:  make(map[string][]*config.SnippetRef),
	}
}

func (g *generator) indexRecords(records map[string][]dns.Record) {
	for _, domain := range slices.Sorted(maps.Keys(records)) {
		seen := make(map[recordSig]bool)
		for _, r := range records[domain] {
			sig := normalise(sigOf(r), domain)
			if seen[sig] {
				continue
			}
			seen[sig] = true
			g.perDomain[domain] = append(g.perDomain[domain], sig)
			g.bySig[sig] = append(g.bySig[sig], domain)
		}
	}
}

type wildcardKey struct {
	typ      string
	content  string
	ttl      int
	priority int
}

func (a wildcardKey) less(b wildcardKey) int {
	return cmp.Or(
		cmp.Compare(a.typ, b.typ),
		cmp.Compare(a.content, b.content),
		cmp.Compare(a.ttl, b.ttl),
		cmp.Compare(a.priority, b.priority),
	)
}

func (g *generator) addWildcardSnippets() {
	groups := make(map[wildcardKey][]recordSig)
	for sig := range g.bySig {
		if !g.opts.WildcardTypes[sig.Type] {
			continue
		}
		k := wildcardKey{sig.Type, sig.Content, sig.TTL, sig.Priority}
		groups[k] = append(groups[k], sig)
	}
	for _, k := range slices.SortedFunc(maps.Keys(groups), wildcardKey.less) {
		g.addWildcardSnippet(k, groups[k])
	}
}

func (g *generator) addWildcardSnippet(k wildcardKey, sigs []recordSig) {
	namesByDomain := g.namesByDomain(sigs)
	domains := slices.Sorted(maps.Keys(namesByDomain))
	if len(domains) < g.opts.MinShared || uniformSingleName(namesByDomain) {
		return
	}

	name := uniqueSnippetName(g.snippets, slugify(k.typ)+"-"+wildcardSlug(k.content))
	rec := snippetRecord(sigs[0])
	rec.Name = "*"
	g.snippets[name] = snippets.Snippet{Records: []*snippets.Record{rec}}
	g.wildcardTypes[name] = k.typ
	for _, sig := range sigs {
		g.wildcardSigs[sig] = true
	}
	for _, d := range domains {
		names := slices.Sorted(maps.Keys(namesByDomain[d]))
		g.wildcardRefs[d] = append(g.wildcardRefs[d], &config.SnippetRef{Name: name, Names: names})
	}
}

func (g *generator) namesByDomain(sigs []recordSig) map[string]map[string]bool {
	out := make(map[string]map[string]bool)
	for _, sig := range sigs {
		for _, d := range g.bySig[sig] {
			if out[d] == nil {
				out[d] = make(map[string]bool)
			}
			out[d][displayName(sig.Name)] = true
		}
	}
	return out
}

func uniformSingleName(namesByDomain map[string]map[string]bool) bool {
	var single string
	seen := false
	for _, names := range namesByDomain {
		keys := slices.Sorted(maps.Keys(names))
		if len(keys) != 1 {
			return false
		}
		if seen && keys[0] != single {
			return false
		}
		single, seen = keys[0], true
	}
	return true
}

func (g *generator) addSharedSnippets() {
	groups, order := g.groupSharedSigs()
	for _, key := range order {
		g.addSharedSnippet(groups[key])
	}
}

func (g *generator) groupSharedSigs() (map[string][]recordSig, []string) {
	groups := make(map[string][]recordSig)
	var order []string
	for _, sig := range slices.SortedFunc(maps.Keys(g.bySig), recordSig.less) {
		if g.wildcardSigs[sig] {
			continue
		}
		domains := g.bySig[sig]
		if len(domains) < g.opts.MinShared {
			continue
		}
		key := g.sharedGroupKey(sig, domains)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], sig)
	}
	return groups, order
}

func (g *generator) sharedGroupKey(sig recordSig, domains []string) string {
	key := strings.Join(domains, "\x00")
	if !g.opts.MergeSnippets {
		key = sig.Type + "\x00" + key
	}
	return key
}

func (g *generator) addSharedSnippet(sigs []recordSig) {
	name := uniqueSnippetName(g.snippets, mergedSnippetName(sigs))
	recs := make([]*snippets.Record, 0, len(sigs))
	for _, sig := range sigs {
		recs = append(recs, snippetRecord(sig))
	}
	g.snippets[name] = snippets.Snippet{Records: recs}
	for _, sig := range sigs {
		g.sigToSnippet[sig] = name
	}
}

func (g *generator) assembleDomains(domainNames []string) map[string]config.Domain {
	domainsOut := make(map[string]config.Domain, len(domainNames))
	for _, domain := range domainNames {
		domainsOut[domain] = g.assembleDomain(domain)
	}
	return domainsOut
}

func (g *generator) assembleDomain(domain string) config.Domain {
	snippetRefs, inline := g.classifySigs(domain)
	snippetRefs = append(snippetRefs, g.wildcardRefs[domain]...)

	slices.SortFunc(snippetRefs, func(a, b *config.SnippetRef) int {
		return cmp.Compare(a.Name, b.Name)
	})
	slices.SortFunc(inline, recordSig.less)

	var d config.Domain
	d.Snippets = snippetRefs
	for _, sig := range inline {
		d.Records = append(d.Records, &config.RecordRef{Record: snippetRecord(sig)})
	}
	return d
}

func (g *generator) classifySigs(domain string) (refs []*config.SnippetRef, inline []recordSig) {
	for _, sig := range g.perDomain[domain] {
		if g.wildcardSigs[sig] {
			continue
		}
		if name, ok := g.sigToSnippet[sig]; ok {
			refs = addUniqueRef(refs, name)
			continue
		}
		inline = append(inline, sig)
	}
	return refs, inline
}

func addUniqueRef(refs []*config.SnippetRef, name string) []*config.SnippetRef {
	for _, ref := range refs {
		if ref.Name == name {
			return refs
		}
	}
	return append(refs, &config.SnippetRef{Name: name})
}

func (g *generator) describeSnippets(domains map[string]config.Domain) map[string]snippets.Snippet {
	usage := make(map[string]int, len(g.snippets))
	for _, d := range domains {
		for _, ref := range d.Snippets {
			usage[ref.Name]++
		}
	}
	out := make(map[string]snippets.Snippet, len(g.snippets))
	for name, s := range g.snippets {
		if typ, ok := g.wildcardTypes[name]; ok {
			s.Description = fmt.Sprintf("%s records shared by %d domains", typ, usage[name])
		} else {
			s.Description = fmt.Sprintf("Shared by %d domains", usage[name])
		}
		out[name] = s
	}
	return out
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

func snippetRecord(sig recordSig) *snippets.Record {
	rec := &snippets.Record{
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
