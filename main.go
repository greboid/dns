package main

import (
	"bufio"
	"cmp"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/greboid/dns-dashboard/internal/config"
	"github.com/greboid/dns-dashboard/internal/diff"
	"github.com/greboid/dns-dashboard/internal/dns"
	"github.com/greboid/dns-dashboard/internal/pull"
	"gopkg.in/yaml.v3"
)

func main() {
	apiUser := flag.String("api-user", "", "mydnshost API user (email)")
	apiKey := flag.String("api-key", "", "mydnshost API key")
	configPath := flag.String("config", "domains.yaml", "path to domain config YAML")
	pullMode := flag.Bool("pull", false, "pull all domains and records from the remote and generate the config")
	force := flag.Bool("force", false, "with -pull, overwrite an existing config")
	minShared := flag.Int("min-shared", 2, "with -pull, minimum domains sharing a record before it becomes a snippet")
	wildcardTypes := flag.String("wildcard-types", "A,RRCLONE", "with -pull, comma-separated record types eligible for wildcard (names-list) snippets")
	mergeSnippets := flag.Bool("merge-snippets", true, "with -pull, also combine snippets referenced by the same set of domains into one")
	flag.Parse()

	if *apiUser == "" || *apiKey == "" {
		log.Fatal("both -api-user and -api-key flags are required")
	}

	client := dns.NewClient(*apiUser, *apiKey)
	ctx := context.Background()

	if *pullMode {
		if err := runPull(ctx, client, *configPath, *force, *minShared, parseTypes(*wildcardTypes), *mergeSnippets); err != nil {
			log.Fatalf("pull: %v", err)
		}
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	diffs := collectDiffs(ctx, cfg, client)

	slices.SortFunc(diffs, func(a, b diff.Diff) int {
		return cmp.Compare(a.Domain, b.Domain)
	})

	diff.PrintAll(os.Stdout, diffs)

	hasDiff := slices.ContainsFunc(diffs, func(d diff.Diff) bool {
		return !d.Clean()
	})
	if !hasDiff {
		return
	}

	if !promptConfirm(os.Stdin, os.Stdout, "Apply these changes?") {
		return
	}

	applyChanges(ctx, cfg, client, diffs)
}

func runPull(ctx context.Context, client *dns.Client, path string, force bool, minShared int, wildcardTypes map[string]bool, mergeSnippets bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use -force to overwrite)", path)
		}
	}

	domains, err := client.ListDomains(ctx)
	if err != nil {
		return fmt.Errorf("listing domains: %w", err)
	}

	records := make(map[string][]dns.Record)
	disabled := 0
	for _, d := range domains {
		rs, err := client.GetRecords(ctx, d.Name)
		if err != nil {
			return fmt.Errorf("fetching records for %s: %w", d.Name, err)
		}
		for _, r := range rs {
			if r.Disabled {
				disabled++
			}
		}
		records[d.Name] = rs
		fmt.Fprintf(os.Stderr, "pulled %s (%d records)\n", d.Name, len(rs))
	}

	cfg, err := pull.Generate(records, pull.Options{MinShared: minShared, WildcardTypes: wildcardTypes, MergeSnippets: mergeSnippets})
	if err != nil {
		return fmt.Errorf("generating config: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("verifying generated config: %w", err)
	}
	for _, name := range loaded.DomainNames() {
		if _, err := loaded.ExpandRecords(name); err != nil {
			return fmt.Errorf("verifying generated config: expanding %s: %w", name, err)
		}
	}

	total := 0
	for _, rs := range records {
		total += len(rs)
	}
	fmt.Fprintf(os.Stdout, "wrote %s: %d domains, %d snippets, %d records\n", path, len(domains), len(cfg.Snippets), total)
	if disabled > 0 {
		fmt.Fprintf(os.Stdout, "warning: %d disabled records were pulled as normal records; the config format cannot represent the disabled state\n", disabled)
	}
	return nil
}

func parseTypes(s string) map[string]bool {
	types := make(map[string]bool)
	for t := range strings.SplitSeq(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			types[strings.ToUpper(t)] = true
		}
	}
	return types
}

func collectDiffs(ctx context.Context, cfg *config.File, client *dns.Client) []diff.Diff {
	return collectDomainDiffs(ctx, cfg, client, cfg.DomainNames())
}

func collectDomainDiffs(ctx context.Context, cfg *config.File, client *dns.Client, domains []string) []diff.Diff {
	var diffs []diff.Diff
	for _, name := range domains {
		desired, err := cfg.ExpandRecords(name)
		if err != nil {
			log.Fatalf("expanding domain %s: %v", name, err)
		}
		records, err := client.GetRecords(ctx, name)
		if err != nil {
			log.Printf("error fetching records for %s: %v", name, err)
			continue
		}
		dr := diff.Compare(desired, records)
		dr.Domain = name
		diffs = append(diffs, dr)
	}
	return diffs
}

func applyChanges(ctx context.Context, cfg *config.File, client *dns.Client, diffs []diff.Diff) {
	touched := applyDomainChanges(ctx, client, diffs)
	if len(touched) == 0 {
		return
	}
	verifyDomains(ctx, cfg, client, touched)
}

func applyDomainChanges(ctx context.Context, client *dns.Client, diffs []diff.Diff) []string {
	var touched []string
	for _, d := range diffs {
		if d.Clean() {
			continue
		}
		touched = append(touched, d.Domain)
		fmt.Fprintf(os.Stdout, "Processing %s...\n", d.Domain)
		removeExtraRecords(ctx, client, d)
		addMissingRecords(ctx, client, d)
	}
	return touched
}

func removeExtraRecords(ctx context.Context, client *dns.Client, d diff.Diff) {
	for _, r := range d.Extra {
		fmt.Fprintf(os.Stdout, "  Removing %s %s %s\n", r.Name, r.Type, r.Content)
		if err := client.RemoveRecord(ctx, d.Domain, r.ID); err != nil {
			log.Printf("    error removing record: %v", err)
		}
	}
}

func addMissingRecords(ctx context.Context, client *dns.Client, d diff.Diff) {
	for _, r := range d.Missing {
		fmt.Fprintf(os.Stdout, "  Adding %s %s %s\n", r.Name, r.Type, r.Content)
		id, err := client.AddRecord(ctx, d.Domain, dns.Record{
			Name:     r.Name,
			Type:     r.Type,
			Content:  r.Content,
			TTL:      r.TTL,
			Priority: r.Priority,
		})
		if err != nil {
			log.Printf("    error adding record: %v", err)
			continue
		}
		if id != nil && *id != 0 {
			fmt.Fprintf(os.Stdout, "    created as record %d\n", *id)
		}
	}
}

func verifyDomains(ctx context.Context, cfg *config.File, client *dns.Client, touched []string) {
	fmt.Fprintln(os.Stdout, "Verifying changes...")
	still := 0
	for _, d := range collectDomainDiffs(ctx, cfg, client, touched) {
		if d.Clean() {
			fmt.Fprintf(os.Stdout, "  %s: clean\n", d.Domain)
			continue
		}
		still++
		fmt.Fprintf(os.Stdout, "  %s: STILL DIFFERS\n", d.Domain)
		for _, r := range d.Extra {
			fmt.Fprintf(os.Stdout, "    + %s %s %s\n", r.Name, r.Type, r.Content)
		}
		for _, r := range d.Missing {
			fmt.Fprintf(os.Stdout, "    - %s %s %s\n", r.Name, r.Type, r.Content)
		}
	}
	if still > 0 {
		log.Printf("%d domain(s) still differ from the config after applying", still)
	}
}

func promptConfirm(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprintf(out, "%s (y/N): ", prompt)
	reader := bufio.NewReader(in)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}
