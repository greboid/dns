package snippets

import (
	"strings"

	"gopkg.in/yaml.v3"
)

type Snippet struct {
	Description string   `yaml:"description"`
	Records     []Record `yaml:"records"`
}

type Record struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Content  string `yaml:"content"`
	TTL      *int   `yaml:"ttl,omitempty"`
	Priority *int   `yaml:"priority,omitempty"`
}

// MarshalYAML emits "@" for apex records (empty name); UnmarshalYAML converts
// it back so apex records always use "" internally.
func (r Record) MarshalYAML() (interface{}, error) {
	type raw Record
	out := raw(r)
	if out.Name == "" {
		out.Name = "@"
	}
	return out, nil
}

func (r *Record) UnmarshalYAML(value *yaml.Node) error {
	type raw Record
	var out raw
	if err := value.Decode(&out); err != nil {
		return err
	}
	if out.Name == "@" {
		out.Name = ""
	}
	*r = Record(out)
	return nil
}

func (r Record) Resolve(domain string) Record {
	return Record{
		Name:     strings.ReplaceAll(r.Name, "{domain}", domain),
		Type:     r.Type,
		Content:  strings.ReplaceAll(r.Content, "{domain}", domain),
		TTL:      r.TTL,
		Priority: r.Priority,
	}
}
