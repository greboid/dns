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
	Snippets map[string]snippets.Snippet `yaml:"snippets"`
	Domains  map[string]Domain           `yaml:"domains"`
}

type Domain struct {
	Snippets []SnippetRef `yaml:"snippets"`
	Records  []RecordRef  `yaml:"records"`
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

type RecordRef struct {
	Record       snippets.Record
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
		var rec snippets.Record
		if err := value.Decode(&rec); err != nil {
			return fmt.Errorf("invalid record: %w", err)
		}
		if rec.Name == "@" {
			rec.Name = ""
		}
		r.Record = rec
		return nil
	default:
		return fmt.Errorf("record reference must be a string or mapping")
	}
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
		snippet, ok := f.Snippets[ref.Name]
		if !ok {
			return nil, fmt.Errorf("domain %q: unknown snippet %q", domainName, ref.Name)
		}
		if len(snippet.Records) == 1 && snippet.Records[0].Name == "*" && len(ref.Names) > 0 {
			for _, name := range ref.Names {
				r := snippet.Records[0]
				records = append(records, snippets.Record{
					Name:     name,
					Type:     r.Type,
					Content:  r.Content,
					TTL:      r.TTL,
					Priority: r.Priority,
				})
			}
		} else {
			for _, r := range snippet.Records {
				resolved := r.Resolve(domainName)
				records = append(records, resolved)
			}
		}
	}

	for _, ref := range domain.Records {
		if ref.IsSnippetRef {
			snippet, ok := f.Snippets[ref.SnippetName]
			if !ok {
				return nil, fmt.Errorf("domain %q: unknown snippet %q", domainName, ref.SnippetName)
			}
			for _, r := range snippet.Records {
				resolved := r.Resolve(domainName)
				records = append(records, resolved)
			}
		} else {
			resolved := ref.Record.Resolve(domainName)
			records = append(records, resolved)
		}
	}

	slices.SortFunc(records, func(a, b snippets.Record) int {
		if c := cmp.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.Content, b.Content)
	})
	return records, nil
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
