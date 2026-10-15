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
	desiredByKey := make(map[string]snippets.Record, len(desired))
	for _, r := range desired {
		desiredByKey[recordKey(r.Name, r.Type, r.Content)] = r
	}
	actualByKey := make(map[string]dns.Record, len(actual))
	for _, r := range actual {
		actualByKey[recordKey(r.Name, r.Type, r.Content)] = r
	}
	return Diff{
		Extra:   extraRecords(actual, desiredByKey),
		Missing: missingRecords(desired, actualByKey),
	}
}

func extraRecords(actual []dns.Record, desired map[string]snippets.Record) []Record {
	var extra []Record
	for _, r := range actual {
		if _, ok := desired[recordKey(r.Name, r.Type, r.Content)]; ok {
			continue
		}
		extra = append(extra, Record{
			Name:     r.Name,
			Type:     r.Type,
			Content:  r.Content,
			TTL:      r.TTL,
			Priority: r.Priority,
			ID:       r.ID,
		})
	}
	return extra
}

func missingRecords(desired []snippets.Record, actual map[string]dns.Record) []Record {
	var missing []Record
	for _, r := range desired {
		if _, ok := actual[recordKey(r.Name, r.Type, r.Content)]; ok {
			continue
		}
		missing = append(missing, Record{
			Name:     r.Name,
			Type:     r.Type,
			Content:  r.Content,
			TTL:      r.TTL,
			Priority: r.Priority,
		})
	}
	return missing
}

func (d Diff) Clean() bool {
	return len(d.Extra) == 0 && len(d.Missing) == 0
}

func PrintAll(w io.Writer, diffs []Diff) {
	clean, dirty := partitionClean(diffs)

	fmt.Fprintf(w, "%d domains: %d clean, %d with differences\n\n", len(diffs), len(clean), len(dirty))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, d := range dirty {
		printDiff(tw, d)
	}
	tw.Flush()

	if len(clean) > 0 {
		printCleanDomains(w, clean)
	}
}

func partitionClean(diffs []Diff) (clean, dirty []Diff) {
	for _, d := range diffs {
		if d.Clean() {
			clean = append(clean, d)
		} else {
			dirty = append(dirty, d)
		}
	}
	return clean, dirty
}

func printDiff(tw *tabwriter.Writer, d Diff) {
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

func printCleanDomains(w io.Writer, clean []Diff) {
	fmt.Fprintf(w, "Clean domains:")
	for _, d := range clean {
		fmt.Fprintf(w, " %s", d.Domain)
	}
	fmt.Fprintln(w)
}

func recordKey(name, rtype, content string) string {
	return name + "\x00" + rtype + "\x00" + content
}
