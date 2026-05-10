package dns

import (
	"cmp"
	"context"
	"slices"

	mydnshost "github.com/mydnshost/mydnshost-go-api"
)

type Record struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Content   string `json:"content"`
	TTL       *int   `json:"ttl,omitempty"`
	Priority  *int   `json:"priority,omitempty"`
	Disabled  bool   `json:"disabled"`
	ChangedAt int    `json:"changedAt,omitempty"`
}

type Domain struct {
	Name        string    `json:"name"`
	AccessLevel string    `json:"accessLevel"`
	Records     []Record  `json:"records,omitempty"`
}

type Client struct {
	api *mydnshost.Client
}

func NewClient(user, apiKey string) *Client {
	return &Client{
		api: &mydnshost.Client{
			Authenticator: &mydnshost.ApiKeyAuthenticator{
				User: user,
				Key:  apiKey,
			},
		},
	}
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	domains, err := c.api.Domains(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]Domain, 0, len(domains))
	for name, level := range domains {
		result = append(result, Domain{
			Name:        name,
			AccessLevel: string(level),
		})
	}
	slices.SortFunc(result, func(a, b Domain) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return result, nil
}

func (c *Client) GetRecords(ctx context.Context, domain string) ([]Record, error) {
	resp, err := c.api.Records(ctx, domain)
	if err != nil {
		return nil, err
	}

	records := make([]Record, 0, len(resp.Records))
	for _, r := range resp.Records {
		records = append(records, Record{
			ID:        r.Id,
			Name:      r.Name,
			Type:      r.Type,
			Content:   r.Content,
			TTL:       &r.TTL,
			Priority:  r.Priority,
			ChangedAt: r.ChangedAt,
		})
		if r.Disabled != nil {
			records[len(records)-1].Disabled = *r.Disabled
		}
	}
	slices.SortFunc(records, func(a, b Record) int {
		if c := cmp.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return records, nil
}

func ptrTo[T any](v T) *T { return &v }

func (c *Client) AddRecord(ctx context.Context, domain string, record Record) error {
	_, err := c.api.ModifyRecords(ctx, domain, mydnshost.CreateRecord(mydnshost.Record{
		Name:     record.Name,
		Type:     record.Type,
		Content:  record.Content,
		TTL:      *cmp.Or(record.TTL, ptrTo(0)),
		Priority: record.Priority,
	}))
	return err
}

func (c *Client) RemoveRecord(ctx context.Context, domain string, recordID int) error {
	_, err := c.api.ModifyRecords(ctx, domain, mydnshost.DeleteRecord(recordID))
	return err
}
