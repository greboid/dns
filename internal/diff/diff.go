package diff

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/greboid/dns-dashboard/internal/dns"
	"github.com/greboid/dns-dashboard/internal/snippets"
)

type Record struct {
	Name     string
	Type     string
	Content  string
	TTL      *int
	Priority *int
	ID       int
}

type Diff struct {
	Domain  string
	Extra   []Record
	Missing []Record
}

func Compare(desired []snippets.Record, actual []dns.Record) Diff {
	desiredMap := make(map[string]snippets.Record)
	for _, r := range desired {
		key := recordKey(r.Name, r.Type, r.Content)
		desiredMap[key] = r
	}

	actualMap := make(map[string]dns.Record)
	for _, r := range actual {
		key := recordKey(r.Name, r.Type, r.Content)
		actualMap[key] = r
	}

	var extra []Record
	for _, r := range actual {
		key := recordKey(r.Name, r.Type, r.Content)
		if _, ok := desiredMap[key]; !ok {
			extra = append(extra, Record{
				Name:     r.Name,
				Type:     r.Type,
				Content:  r.Content,
				TTL:      r.TTL,
				Priority: r.Priority,
				ID:       r.ID,
			})
		}
	}

	var missing []Record
	for _, r := range desired {
		key := recordKey(r.Name, r.Type, r.Content)
		if _, ok := actualMap[key]; !ok {
			missing = append(missing, Record{
				Name:     r.Name,
				Type:     r.Type,
				Content:  r.Content,
				TTL:      r.TTL,
				Priority: r.Priority,
			})
		}
	}

	return Diff{Extra: extra, Missing: missing}
}

func (d Diff) Clean() bool {
	return len(d.Extra) == 0 && len(d.Missing) == 0
}

func PrintAll(w io.Writer, diffs []Diff) {
	clean := 0
	for _, d := range diffs {
		if d.Clean() {
			clean++
		}
	}

	fmt.Fprintf(w, "%d domains: %d clean, %d with differences\n\n", len(diffs), clean, len(diffs)-clean)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, d := range diffs {
		if d.Clean() {
			continue
		}
		fmt.Fprintf(tw, "=== %s ===\n", d.Domain)
		if len(d.Extra) > 0 {
			fmt.Fprintf(tw, "  EXTRA (on server, not in config):\n")
			for _, r := range d.Extra {
				fmt.Fprintf(tw, "  +\t%s\t%s\t%s\n", r.Name, r.Type, r.Content)
			}
		}
		if len(d.Missing) > 0 {
			fmt.Fprintf(tw, "  MISSING (in config, not on server):\n")
			for _, r := range d.Missing {
				fmt.Fprintf(tw, "  -\t%s\t%s\t%s\n", r.Name, r.Type, r.Content)
			}
		}
		fmt.Fprintln(tw)
	}
	tw.Flush()

	if clean > 0 {
		fmt.Fprintf(w, "Clean domains:")
		for _, d := range diffs {
			if d.Clean() {
				fmt.Fprintf(w, " %s", d.Domain)
			}
		}
		fmt.Fprintln(w)
	}
}

func recordKey(name, rtype, content string) string {
	return name + "\x00" + rtype + "\x00" + content
}
