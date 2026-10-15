package dns

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	Name        string   `json:"name"`
	AccessLevel string   `json:"accessLevel"`
	Records     []Record `json:"records,omitempty"`
}

type Client struct {
	auth    mydnshost.ClientAuthenticator
	api     *mydnshost.Client
	apiBase string
}

const defaultAPIBase = "https://api.mydnshost.co.uk/1.0"

func NewClient(user, apiKey string) *Client {
	auth := &mydnshost.ApiKeyAuthenticator{User: user, Key: apiKey}
	return &Client{
		auth:    auth,
		api:     &mydnshost.Client{Authenticator: auth},
		apiBase: defaultAPIBase,
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

type createRecordOp struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority,omitempty"`
}

type modifyResponse struct {
	Serial  uint64                    `json:"serial"`
	Changed []mydnshost.ChangedRecord `json:"changed"`
}

type apiEnvelope struct {
	Error     *string           `json:"error"`
	ErrorData map[string]string `json:"errorData"`
	Response  json.RawMessage   `json:"response"`
}

func (c *Client) modifyRecords(ctx context.Context, domain string, ops ...mydnshost.RecordOperation) (*modifyResponse, []byte, error) {
	payload, err := marshalRecordOps(ops)
	if err != nil {
		return nil, nil, err
	}
	raw, status, err := c.postRecords(ctx, domain, payload)
	if err != nil {
		return nil, nil, err
	}
	res, err := decodeModifyResponse(raw, status)
	if err != nil {
		return nil, raw, err
	}
	return res, raw, nil
}

func marshalRecordOps(ops []mydnshost.RecordOperation) ([]byte, error) {
	rawOps := make([]json.RawMessage, len(ops))
	for i, op := range ops {
		rawOps[i] = json.RawMessage(op)
	}
	return json.Marshal(struct {
		Data struct {
			Records []json.RawMessage `json:"records"`
		} `json:"data"`
	}{Data: struct {
		Records []json.RawMessage `json:"records"`
	}{Records: rawOps}})
}

func (c *Client) postRecords(ctx context.Context, domain string, payload []byte) (raw []byte, status int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiBase+"/domains/"+domain+"/records", bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	if c.auth != nil {
		c.auth.AddHeaders(req)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return raw, resp.StatusCode, nil
}

func decodeModifyResponse(raw []byte, status int) (*modifyResponse, error) {
	envelope := &apiEnvelope{}
	if err := json.Unmarshal(raw, envelope); err != nil {
		return nil, fmt.Errorf("unexpected API response (status %d): %s", status, raw)
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("API error: %s %v", *envelope.Error, envelope.ErrorData)
	}

	out := &modifyResponse{}
	if err := json.Unmarshal(envelope.Response, out); err != nil {
		return nil, fmt.Errorf("unexpected API response (status %d): %s", status, raw)
	}
	return out, nil
}

func (c *Client) AddRecord(ctx context.Context, domain string, record Record) (*int, error) {
	op, err := createRecordPayload(record)
	if err != nil {
		return nil, err
	}
	res, raw, err := c.modifyRecords(ctx, domain, op)
	if err != nil {
		return nil, err
	}
	if id, ok := findCreatedID(res, record); ok {
		return &id, nil
	}
	return nil, fmt.Errorf("server did not confirm creating %s record %q on %s (response: %s)", record.Type, record.Content, domain, raw)
}

func createRecordPayload(record Record) ([]byte, error) {
	ttl := 0
	if record.TTL != nil {
		ttl = *record.TTL
	}
	return json.Marshal(createRecordOp{
		Name:     record.Name,
		Type:     record.Type,
		Content:  record.Content,
		TTL:      ttl,
		Priority: record.Priority,
	})
}

func findCreatedID(res *modifyResponse, record Record) (int, bool) {
	for _, changed := range res.Changed {
		if changed.Deleted || changed.Type != record.Type || changed.Content != record.Content {
			continue
		}
		return changed.Id, true
	}
	return 0, false
}

func (c *Client) RemoveRecord(ctx context.Context, domain string, recordID int) error {
	res, raw, err := c.modifyRecords(ctx, domain, mydnshost.DeleteRecord(recordID))
	if err != nil {
		return err
	}
	for _, changed := range res.Changed {
		if changed.Id == recordID {
			return nil
		}
	}
	return fmt.Errorf("server did not confirm deleting record %d on %s (response: %s)", recordID, domain, raw)
}
