package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func graphqlOK(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// useMythicEndpoint points the hardcoded client at an httptest server for the
// duration of a test and restores it afterwards.
func useMythicEndpoint(t *testing.T, endpoint string) {
	t.Helper()
	previous := mythicAPIEndpoint
	mythicAPIEndpoint = endpoint
	t.Cleanup(func() { mythicAPIEndpoint = previous })
}

func TestDefaultMythicAPIEndpoint(t *testing.T) {
	if defaultMythicAPIEndpoint != "https://mythic_nginx:7443/graphql/" {
		t.Fatalf("unexpected default endpoint: %q", defaultMythicAPIEndpoint)
	}
}

func TestDomainAllowed(t *testing.T) {
	if !domainAllowed("example.com", []string{"example.com"}) {
		t.Fatal("exact domain should be allowed")
	}
	if !domainAllowed("Example.COM", []string{"example.com"}) {
		t.Fatal("domain matching should ignore case")
	}
	if !domainAllowed("anything.example", []string{"*"}) {
		t.Fatal("wildcard should allow any domain")
	}
	if domainAllowed("evil-example.com", []string{"example.com"}) {
		t.Fatal("only the whole domain should match")
	}
	if domainAllowed("example.com", nil) {
		t.Fatal("an empty allow list must deny provisioning")
	}
}

func TestEnsureOperatorDisabledDoesNotCallAPI(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer srv.Close()
	useMythicEndpoint(t, srv.URL+"/graphql/")

	got, err := ensureOperator(context.Background(), &Config{}, "  user@example.com  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "user@example.com" {
		t.Fatalf("got %q, want trimmed email", got)
	}
	if called {
		t.Fatal("the Mythic API must not be called when auto_provision is disabled")
	}
}

func TestEnsureOperatorReturnsStoredEmailForExistingUser(t *testing.T) {
	var created bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "createOperator") {
			created = true
			graphqlOK(w, map[string]any{"createOperator": map[string]any{"status": "success", "error": ""}})
			return
		}
		graphqlOK(w, map[string]any{"operator": []any{
			map[string]any{"id": 1, "email": "User@Example.com"},
		}})
	}))
	defer srv.Close()
	useMythicEndpoint(t, srv.URL+"/graphql/")

	cfg := &Config{
		MythicAPIToken:      "token",
		AutoProvision:       true,
		AllowedEmailDomains: []string{"example.com"},
	}
	got, err := ensureOperator(context.Background(), cfg, "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "User@Example.com" {
		t.Fatalf("got %q, want the email stored in Mythic", got)
	}
	if created {
		t.Fatal("an existing operator must not be created again")
	}
}

func TestEnsureOperatorCreatesMissingUser(t *testing.T) {
	var mutation string
	var mutationVars map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.Contains(req.Query, "createOperator") {
			mutation = req.Query
			mutationVars = req.Variables
			graphqlOK(w, map[string]any{"createOperator": map[string]any{"status": "success", "error": ""}})
			return
		}
		graphqlOK(w, map[string]any{"operator": []any{}})
	}))
	defer srv.Close()
	useMythicEndpoint(t, srv.URL+"/graphql/")

	cfg := &Config{
		MythicAPIToken:      "token",
		AutoProvision:       true,
		AllowedEmailDomains: []string{"example.com"},
	}
	got, err := ensureOperator(context.Background(), cfg, "new@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "new@example.com" {
		t.Fatalf("got %q, want the provisioned email", got)
	}
	if !strings.Contains(mutation, "createOperator(input:") {
		t.Fatalf("mutation must pass the Hasura action input object, got:\n%s", mutation)
	}
	if mutationVars["u"] != "new@example.com" || mutationVars["e"] != "new@example.com" {
		t.Fatalf("unexpected mutation variables: %v", mutationVars)
	}
	if pw, _ := mutationVars["p"].(string); len(pw) < 12 {
		t.Fatalf("generated password is too short: %q", pw)
	}
}

func TestEnsureOperatorFailsOpenOnLookupError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer srv.Close()
	useMythicEndpoint(t, srv.URL+"/graphql/")

	cfg := &Config{
		MythicAPIToken:      "token",
		AutoProvision:       true,
		AllowedEmailDomains: []string{"example.com"},
	}
	got, err := ensureOperator(context.Background(), cfg, "user@example.com")
	if err != nil {
		t.Fatalf("a lookup failure must not block the login: %v", err)
	}
	if got != "user@example.com" {
		t.Fatalf("got %q, want the original email", got)
	}
}

func TestEnsureOperatorRejectsDisallowedDomain(t *testing.T) {
	var created bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "createOperator") {
			created = true
		}
		graphqlOK(w, map[string]any{"operator": []any{}})
	}))
	defer srv.Close()
	useMythicEndpoint(t, srv.URL+"/graphql/")

	cfg := &Config{
		MythicAPIToken:      "token",
		AutoProvision:       true,
		AllowedEmailDomains: []string{"example.com"},
	}
	_, err := ensureOperator(context.Background(), cfg, "user@evil.example")
	if err == nil {
		t.Fatal("expected a domain error")
	}
	if !strings.Contains(err.Error(), "allowed_email_domains") {
		t.Fatalf("unexpected error: %v", err)
	}
	if created {
		t.Fatal("a disallowed domain must not be provisioned")
	}
}

func TestEnsureOperatorReturnsCreateError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.Contains(req.Query, "createOperator") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errors": []any{map[string]any{"message": "permission denied"}},
			})
			return
		}
		graphqlOK(w, map[string]any{"operator": []any{}})
	}))
	defer srv.Close()
	useMythicEndpoint(t, srv.URL+"/graphql/")

	cfg := &Config{
		MythicAPIToken:      "token",
		AutoProvision:       true,
		AllowedEmailDomains: []string{"example.com"},
	}
	_, err := ensureOperator(context.Background(), cfg, "user@example.com")
	if err == nil {
		t.Fatal("expected the GraphQL error to be returned")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("GraphQL error detail was lost: %v", err)
	}
}

func TestEnsureOperatorAcceptsUntrustedMythicCertificate(t *testing.T) {
	// httptest.NewTLSServer uses a self-signed certificate. Provisioning must
	// accept it because the Mythic API client intentionally skips verification
	// for the private Docker network.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.Contains(req.Query, "createOperator") {
			graphqlOK(w, map[string]any{"createOperator": map[string]any{"status": "success", "error": ""}})
			return
		}
		graphqlOK(w, map[string]any{"operator": []any{}})
	}))
	defer srv.Close()
	useMythicEndpoint(t, srv.URL+"/graphql/")

	cfg := &Config{
		MythicAPIToken:      "token",
		AutoProvision:       true,
		AllowedEmailDomains: []string{"example.com"},
	}
	got, err := ensureOperator(context.Background(), cfg, "user@example.com")
	if err != nil {
		t.Fatalf("self-signed Mythic certificate must be accepted: %v", err)
	}
	if got != "user@example.com" {
		t.Fatalf("got %q, want the provisioned email", got)
	}
}

func TestValidateProvisioningConfig(t *testing.T) {
	problems := validateProvisioningConfig(&Config{
		MythicAPIToken:      "token",
		AllowedEmailDomains: []string{"example.com"},
	})
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}

	problems = validateProvisioningConfig(&Config{})
	if len(problems) < 2 {
		t.Fatalf("expected missing token and domain problems, got: %v", problems)
	}
}
