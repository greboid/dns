package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mydnshost "github.com/mydnshost/mydnshost-go-api"
)

func newTestClient(base string) *Client {
	auth := &mydnshost.ApiKeyAuthenticator{User: "user@example.com", Key: "test-key"}
	return &Client{auth: auth, apiBase: base}
}

func respond(w http.ResponseWriter, envelope string) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(envelope))
}

func TestAddRecordSendsExplicitNameAndVerifiesCreation(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		respond(w, `{"response":{"serial":1,"changed":[{"id":42,"name":"","type":"TXT","content":"hi","ttl":3600}]}}`)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	id, err := client.AddRecord(context.Background(), "x.test", Record{
		Name: "", Type: "TXT", Content: "hi", TTL: new(3600),
	})
	if err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	if id == nil || *id != 42 {
		t.Fatalf("expected created id 42, got %v", id)
	}

	records := gotBody["data"].(map[string]any)["records"].([]any)
	op := records[0].(map[string]any)
	if _, ok := op["name"]; !ok {
		t.Errorf("create op is missing the name field: %v", op)
	}
	if op["type"] != "TXT" || op["content"] != "hi" || op["ttl"] != float64(3600) {
		t.Errorf("unexpected create op: %v", op)
	}
}

func TestAddRecordRejectsUnconfirmedCreation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"response":{"serial":1,"changed":[]}}`)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.AddRecord(context.Background(), "x.test", Record{
		Name: "", Type: "TXT", Content: "hi", TTL: new(3600),
	})
	if err == nil {
		t.Fatal("expected error for unconfirmed creation")
	}
	if !contains(err.Error(), "did not confirm") || !contains(err.Error(), `"changed":[]`) {
		t.Errorf("error should describe the failure and include the raw response, got: %v", err)
	}
}

func TestAddRecordSurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"error":"Access denied","errorData":{"scope":"domains_write"}}`)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.AddRecord(context.Background(), "x.test", Record{Type: "TXT", Content: "hi"})
	if err == nil {
		t.Fatal("expected error for API error response")
	}
	if !contains(err.Error(), "Access denied") || !contains(err.Error(), "domains_write") {
		t.Errorf("error should include API error details, got: %v", err)
	}
}

func TestRemoveRecordVerifiesDeletion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"response":{"serial":2,"changed":[{"id":7,"delete":true}]}}`)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	if err := client.RemoveRecord(context.Background(), "x.test", 7); err != nil {
		t.Fatalf("RemoveRecord: %v", err)
	}

	if err := client.RemoveRecord(context.Background(), "x.test", 99); err == nil {
		t.Fatal("expected error for unconfirmed deletion")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
