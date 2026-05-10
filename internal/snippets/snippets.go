package snippets

import (
	"strings"
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

func (r Record) Resolve(domain string) Record {
	return Record{
		Name:     strings.ReplaceAll(r.Name, "{domain}", domain),
		Type:     r.Type,
		Content:  strings.ReplaceAll(r.Content, "{domain}", domain),
		TTL:      r.TTL,
		Priority: r.Priority,
	}
}
