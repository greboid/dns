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
)

func main() {
	apiUser := flag.String("api-user", "", "mydnshost API user (email)")
	apiKey := flag.String("api-key", "", "mydnshost API key")
	configPath := flag.String("config", "domains.yaml", "path to domain config YAML")
	flag.Parse()

	if *apiUser == "" || *apiKey == "" {
		log.Fatal("both -api-user and -api-key flags are required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	client := dns.NewClient(*apiUser, *apiKey)
	ctx := context.Background()

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

	applyChanges(ctx, client, diffs)
}

func collectDiffs(ctx context.Context, cfg *config.File, client *dns.Client) []diff.Diff {
	var diffs []diff.Diff
	for _, name := range cfg.DomainNames() {
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

func applyChanges(ctx context.Context, client *dns.Client, diffs []diff.Diff) {
	for _, d := range diffs {
		if d.Clean() {
			continue
		}
		fmt.Fprintf(os.Stdout, "Processing %s...\n", d.Domain)
		for _, r := range d.Extra {
			fmt.Fprintf(os.Stdout, "  Removing %s %s %s\n", r.Name, r.Type, r.Content)
			if err := client.RemoveRecord(ctx, d.Domain, r.ID); err != nil {
				log.Printf("    error removing record: %v", err)
			}
		}
		for _, r := range d.Missing {
			fmt.Fprintf(os.Stdout, "  Adding %s %s %s\n", r.Name, r.Type, r.Content)
			if err := client.AddRecord(ctx, d.Domain, dns.Record{
				Name:     r.Name,
				Type:     r.Type,
				Content:  r.Content,
				TTL:      r.TTL,
				Priority: r.Priority,
			}); err != nil {
				log.Printf("    error adding record: %v", err)
			}
		}
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
