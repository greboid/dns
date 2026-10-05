package config

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/greboid/dns-dashboard/internal/snippets"
	"gopkg.in/yaml.v3"
)

type File struct {
	Snippets map[string]snippets.Snippet `yaml:"snippets,omitempty"`
	Domains  map[string]Domain           `yaml:"domains,omitempty"`
}

type Domain struct {
	Snippets []*SnippetRef `yaml:"snippets,omitempty"`
	Records  []*RecordRef  `yaml:"records,omitempty"`
}

type SnippetRef struct {
	Name  string
	Names []string
}

func (s *SnippetRef) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		s.Name = value.Value
		return nil
	case yaml.MappingNode:
		if len(value.Content) < 2 {
			return fmt.Errorf("invalid snippet reference mapping")
		}
		s.Name = value.Content[0].Value
		var names []string
		if err := value.Content[1].Decode(&names); err != nil {
			return fmt.Errorf("invalid snippet reference names: %w", err)
		}
		s.Names = normaliseNames(names)
		return nil
	default:
		return fmt.Errorf("snippet reference must be a string or mapping")
	}
}

func (s *SnippetRef) MarshalYAML() (any, error) {
	if len(s.Names) == 0 {
		return s.Name, nil
	}
	return map[string][]string{s.Name: s.Names}, nil
}

type RecordRef struct {
	Record       *snippets.Record
	IsSnippetRef bool
	SnippetName  string
}

func (r *RecordRef) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		r.IsSnippetRef = true
		r.SnippetName = value.Value
		return nil
	case yaml.MappingNode:
		rec := &snippets.Record{}
		if err := value.Decode(rec); err != nil {
			return fmt.Errorf("invalid record: %w", err)
		}
		r.Record = rec
		return nil
	default:
		return fmt.Errorf("record reference must be a string or mapping")
	}
}

func (r *RecordRef) MarshalYAML() (any, error) {
	if r.IsSnippetRef {
		return r.SnippetName, nil
	}
	return r.Record, nil
}

func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &f, nil
}

func (f *File) ExpandRecords(domainName string) ([]snippets.Record, error) {
	domain, ok := f.Domains[domainName]
	if !ok {
		return nil, fmt.Errorf("unknown domain %q", domainName)
	}

	var records []snippets.Record
	for _, ref := range domain.Snippets {
		expanded, err := f.expandSnippetRef(domainName, ref)
		if err != nil {
			return nil, err
		}
		records = append(records, expanded...)
	}
	for _, ref := range domain.Records {
		expanded, err := f.expandRecordRef(domainName, ref)
		if err != nil {
			return nil, err
		}
		records = append(records, expanded...)
	}

	slices.SortFunc(records, func(a, b snippets.Record) int {
		return cmp.Or(
			cmp.Compare(a.Type, b.Type),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Content, b.Content),
		)
	})
	return records, nil
}

func (f *File) expandSnippetRef(domainName string, ref *SnippetRef) ([]snippets.Record, error) {
	snippet, ok := f.Snippets[ref.Name]
	if !ok {
		return nil, fmt.Errorf("domain %q: unknown snippet %q", domainName, ref.Name)
	}

	if len(snippet.Records) == 1 && snippet.Records[0].Name == "*" && len(ref.Names) > 0 {
		out := make([]snippets.Record, 0, len(ref.Names))
		for _, name := range ref.Names {
			resolved := snippet.Records[0].Resolve(domainName)
			resolved.Name = name
			out = append(out, resolved)
		}
		return out, nil
	}
	return f.resolveSnippet(snippet, domainName), nil
}

func (f *File) expandRecordRef(domainName string, ref *RecordRef) ([]snippets.Record, error) {
	if ref.IsSnippetRef {
		snippet, ok := f.Snippets[ref.SnippetName]
		if !ok {
			return nil, fmt.Errorf("domain %q: unknown snippet %q", domainName, ref.SnippetName)
		}
		return f.resolveSnippet(snippet, domainName), nil
	}
	return []snippets.Record{ref.Record.Resolve(domainName)}, nil
}

func (f *File) resolveSnippet(s snippets.Snippet, domainName string) []snippets.Record {
	out := make([]snippets.Record, 0, len(s.Records))
	for _, r := range s.Records {
		out = append(out, r.Resolve(domainName))
	}
	return out
}

func (f *File) DomainNames() []string {
	return slices.Sorted(maps.Keys(f.Domains))
}

func normaliseNames(names []string) []string {
	for i, n := range names {
		if n == "@" {
			names[i] = ""
		}
	}
	return names
}
