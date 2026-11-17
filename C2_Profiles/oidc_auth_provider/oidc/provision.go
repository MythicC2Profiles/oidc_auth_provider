package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MythicMeta/MythicContainer/logging"
)

// Serializes provisioning so two simultaneous first logins don't both create.
var provisionMu sync.Mutex

const defaultMythicAPIEndpoint = "https://mythic_nginx:7443/graphql/"

// mythicAPIEndpoint is Mythic's GraphQL API on the internal Docker network.
// The default assumes the standard NGINX_HOST and NGINX_PORT. Tests replace it
// with the URL of an httptest server.
var mythicAPIEndpoint = defaultMythicAPIEndpoint

// mythicHTTPClient builds a client for the Mythic API.
//
// TLS certificate verification is intentionally disabled. The API is reached
// over the private Docker network at mythic_nginx, the auth container does not
// have Mythic's Caddy CA, and the internal service name is not necessarily
// present in the certificate Mythic serves. This is only safe while that
// network is a trusted boundary: every request carries a full Mythic admin API
// token, so the endpoint must never point at an untrusted network or the
// public internet. Revisit this if the API becomes reachable from anywhere
// else.
func mythicHTTPClient() *http.Client {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// #nosec G402 -- the Docker network is the trust boundary by design.
		InsecureSkipVerify: true,
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// gql posts one GraphQL operation and decodes data into out.
func gql(ctx context.Context, client *http.Client, cfg *Config, query string, vars map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mythicAPIEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.MythicAPIToken)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap response size
	if err != nil {
		return err
	}

	// GraphQL reports errors with HTTP 200, and Hasura uses HTTP 400 for
	// validation errors, so check the errors array before the status code.
	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	parseErr := json.Unmarshal(raw, &envelope)
	if parseErr == nil && len(envelope.Errors) > 0 {
		return fmt.Errorf("graphql error: %s", envelope.Errors[0].Message)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mythic returned HTTP %d", resp.StatusCode)
	}
	if parseErr != nil {
		return fmt.Errorf("decode mythic response: %w", parseErr)
	}
	if len(envelope.Data) == 0 {
		return errors.New("mythic returned an empty GraphQL response")
	}
	return json.Unmarshal(envelope.Data, out)
}

// lookupOperator returns the email stored in Mythic for the given address and
// whether a matching operator exists. The stored value is returned so the
// login can use it for Mythic's case-sensitive lookup even if the provider
// reports the address with different capitalisation.
func lookupOperator(ctx context.Context, client *http.Client, cfg *Config, email string) (string, bool, error) {
	var out struct {
		Operator []struct {
			ID    int     `json:"id"`
			Email *string `json:"email"`
		} `json:"operator"`
	}
	err := gql(ctx, client, cfg,
		`query($e:String!){ operator(where:{email:{_eq:$e}}, limit:1){ id email } }`,
		map[string]any{"e": email}, &out)
	if err != nil {
		return "", false, err
	}
	if len(out.Operator) == 0 {
		return "", false, nil
	}
	if out.Operator[0].Email != nil && strings.TrimSpace(*out.Operator[0].Email) != "" {
		return strings.TrimSpace(*out.Operator[0].Email), true, nil
	}
	return email, true, nil
}

// randomPassword: Mythic requires a password (min 12 chars), but OIDC users
// never use it. Generate a high-entropy one and discard it.
func randomPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func emailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 1 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

// domainAllowed reports whether emailDomain is in allowed. An entry of "*"
// allows every domain.
func domainAllowed(domain string, allowed []string) bool {
	for _, d := range allowed {
		d = strings.TrimSpace(d)
		if d == "*" {
			return true
		}
		if strings.EqualFold(domain, d) {
			return true
		}
	}
	return false
}

func createOperator(ctx context.Context, client *http.Client, cfg *Config, email, password string) error {
	var out struct {
		CreateOperator struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"createOperator"`
	}
	err := gql(ctx, client, cfg,
		`mutation($u:String!, $p:String!, $e:String!) {
			createOperator(input: {username: $u, password: $p, email: $e}) {
				status
				error
			}
		}`,
		map[string]any{"u": email, "p": password, "e": email}, &out)
	if err != nil {
		return err
	}
	if out.CreateOperator.Status != "success" {
		if out.CreateOperator.Error == "" {
			return errors.New("createOperator did not report success")
		}
		return errors.New(out.CreateOperator.Error)
	}
	return nil
}

// validateProvisioningConfig returns a list of problems that prevent JIT
// provisioning from working. It is used by the startup reporter so a bad
// configuration is visible before the first login attempt.
func validateProvisioningConfig(cfg *Config) []string {
	var problems []string
	if strings.TrimSpace(cfg.MythicAPIToken) == "" {
		problems = append(problems, "mythic_api_token is empty")
	}
	if len(cfg.AllowedEmailDomains) == 0 {
		problems = append(problems, "allowed_email_domains is empty (set at least one domain, or \"*\" to allow every domain)")
	}
	return problems
}

// checkMythicAPI verifies that the URL and token work. It performs a read-only
// lookup for an address that cannot exist.
func checkMythicAPI(ctx context.Context, cfg *Config) error {
	_, _, err := lookupOperator(ctx, mythicHTTPClient(), cfg, "startup-probe@provisioning.invalid")
	return err
}

// ensureOperator guarantees a Mythic operator exists for email and returns the
// address Mythic should use for its own lookup. Provisioning is opt-in; when it
// is disabled the email is returned unchanged so logins behave exactly as
// before.
//
// JIT provisioning is best-effort: if the Mythic API cannot be reached or the
// lookup fails, the login continues and Mythic's own operator lookup decides.
// A failure to create a definitively missing operator is returned to the
// caller because that login cannot succeed anyway.
func ensureOperator(ctx context.Context, cfg *Config, email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", errors.New("provider returned an empty email address")
	}
	if !cfg.AutoProvision {
		return email, nil
	}

	client := mythicHTTPClient()

	storedEmail, exists, err := lookupOperator(ctx, client, cfg, email)
	if err != nil {
		logging.LogWarning("OIDC provisioning: operator lookup failed; continuing without provisioning", "email", email, "error", err.Error())
		return email, nil
	}
	if exists {
		return storedEmail, nil
	}

	domain := emailDomain(email)
	if domain == "" {
		return email, errors.New("provider returned a malformed email address")
	}
	if !domainAllowed(domain, cfg.AllowedEmailDomains) {
		return email, fmt.Errorf("email domain %q is not listed in allowed_email_domains", domain)
	}

	provisionMu.Lock()
	defer provisionMu.Unlock()

	// Another login may have created the account while we waited for the lock.
	storedEmail, exists, err = lookupOperator(ctx, client, cfg, email)
	if err != nil {
		logging.LogWarning("OIDC provisioning: operator re-check failed; continuing without provisioning", "email", email, "error", err.Error())
		return email, nil
	}
	if exists {
		return storedEmail, nil
	}

	password, err := randomPassword()
	if err != nil {
		return email, err
	}
	if err := createOperator(ctx, client, cfg, email, password); err != nil {
		// A creator in another process may have won the race; check again
		// before failing the login.
		if storedEmail, exists, qerr := lookupOperator(ctx, client, cfg, email); qerr == nil && exists {
			return storedEmail, nil
		}
		return email, err
	}

	fmt.Printf("[oidc] auto-provisioned Mythic operator for %s\n", email)
	return email, nil
}
