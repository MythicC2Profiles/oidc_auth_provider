package oidc

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MythicMeta/MythicContainer/authstructs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/utils/sharedStructs"
	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"
)

const version = "1.1.0"
const name = "oidc"

const cookieStateName = "oidc_state"

type Config struct {
	// Issuer is the URL identifier for the service. For example: "https://accounts.google.com"
	// or "https://login.salesforce.com".
	Issuer string `json:"issuer"`

	// ClientID is the identifier issued to the client during the registration process.
	ClientID string `json:"client_id"`

	// ClientSecret is the secret issued to the client during the registration process.
	ClientSecret string `json:"client_secret"`

	// RedirectURL is the URL to which the authorization server will send the user after granting authorization.
	// <MYTHIC_URL>/auth_acs/OIDC/OIDC
	RedirectURL string `json:"redirect_url"`

	// MTLSCertFile is the filename of the client certificate uploaded through
	// the auth container's file browser. Leave empty to disable client auth.
	MTLSCertFile string `json:"mtls_cert_file"`

	// MTLSKeyFile is the filename of the client private key uploaded through
	// the auth container's file browser.
	MTLSKeyFile string `json:"mtls_key_file"`

	// MTLSCAFile is the filename of the CA bundle uploaded through the auth
	// container's file browser. Certificates in this file are added to the
	// system trust store for OIDC requests.
	MTLSCAFile string `json:"mtls_ca_file"`

	// MythicAPIToken is a Mythic API token belonging to an admin account. It is
	// required to create operators through the GraphQL API at mythic_nginx.
	MythicAPIToken string `json:"mythic_api_token"`

	// AutoProvision creates a Mythic operator on first successful login when no
	// operator with the provider's email address exists.
	AutoProvision bool `json:"auto_provision"`

	// AllowedEmailDomains restricts which addresses may be auto-provisioned.
	// An entry of "*" allows every domain. Existing operators are not affected.
	AllowedEmailDomains []string `json:"allowed_email_domains"`
}

func randomString(length int) string {
	res := make([]byte, length)
	_, _ = rand.Read(res)
	return fmt.Sprintf("%x", res)
}

// configPath returns the config.json that belongs to this container. The file
// browser writes files next to the executable, so prefer that directory and
// fall back to the working directory for local development.
func configPath() string {
	if dir, err := containerDir(); err == nil {
		candidate := filepath.Join(dir, "config.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join(".", "config.json")
}

func loadConfig() (*Config, error) {
	path := configPath()
	configBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	var cfg Config

	err = json.Unmarshal(configBytes, &cfg)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	logging.LogDebug("OIDC: loaded config", "path", path, "issuer", cfg.Issuer)
	return &cfg, nil
}

// startupReporter collects startup validation output. Each line is printed to
// stdout so it is always visible in the container log (Mythic containers
// default to the "warning" log level, which hides informational logging), and
// the collected lines are also returned to Mythic so they appear in the
// operation event log.
type startupReporter struct {
	infoLines  []string
	errorLines []string
}

func (r *startupReporter) info(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	fmt.Printf("[oidc] %s\n", line)
	r.infoLines = append(r.infoLines, line)
}

func (r *startupReporter) err(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	fmt.Printf("[oidc] ERROR: %s\n", line)
	r.errorLines = append(r.errorLines, line)
}

func (r *startupReporter) response() sharedStructs.ContainerOnStartMessageResponse {
	return sharedStructs.ContainerOnStartMessageResponse{
		EventLogInfoMessage:  strings.Join(r.infoLines, "\n"),
		EventLogErrorMessage: strings.Join(r.errorLines, "\n"),
	}
}

// logStartupStatus loads the configuration and validates the mTLS settings
// every time the container starts. This makes certificate and trust problems
// visible in the container log and the Mythic event log even before someone
// tries to log in.
func logStartupStatus() sharedStructs.ContainerOnStartMessageResponse {
	report := &startupReporter{}

	cfg, err := loadConfig()
	if err != nil {
		logging.LogError(err, "OIDC: failed to load configuration at startup")
		report.err("failed to load configuration: %v", err)
		return report.response()
	}
	logging.LogDebug("OIDC: configuration loaded",
		"issuer", cfg.Issuer,
		"redirect_url", cfg.RedirectURL,
		"mtls_cert_file", cfg.MTLSCertFile,
		"mtls_key_file", cfg.MTLSKeyFile,
		"mtls_ca_file", cfg.MTLSCAFile)

	var missing []string
	if cfg.Issuer == "" {
		missing = append(missing, "issuer")
	}
	if cfg.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if cfg.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if cfg.RedirectURL == "" {
		missing = append(missing, "redirect_url")
	}
	if len(missing) > 0 {
		report.err("missing required configuration value(s): %s", strings.Join(missing, ", "))
		return report.response()
	}

	provisionStatus := "disabled"
	provisionReady := false
	if cfg.AutoProvision {
		provisionStatus = "enabled"
		logging.LogWarning("OIDC provisioning: TLS certificate verification is disabled for the Mythic API")
		if problems := validateProvisioningConfig(cfg); len(problems) > 0 {
			report.err("auto-provisioning is not ready: %s (logins are unaffected; new operators will not be created until this is fixed)", strings.Join(problems, "; "))
		} else {
			provisionReady = true
		}
	}

	client, err := idpClient(cfg)
	if err != nil {
		logMTLSFailure("startup", err)
		report.err("mTLS configuration is invalid: %v", err)
		return report.response()
	}
	mtlsStatus := "disabled"
	if client != nil {
		mtlsStatus = "enabled"
		logging.LogDebug("OIDC: mTLS enabled", "details", getMTLSDiagnostics())
	} else {
		logging.LogDebug("OIDC: mTLS disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		logIdPFailure("startup discovery", err)
		report.err("discovery against %s failed: %v", cfg.Issuer, err)
		if hint := tlsFailureHint(err); hint != "" {
			report.err("hint: %s", hint)
		}
		return report.response()
	}
	endpoint := provider.Endpoint()
	logging.LogDebug("OIDC: startup discovery succeeded",
		"issuer", cfg.Issuer,
		"auth_url", endpoint.AuthURL,
		"token_url", endpoint.TokenURL)

	if provisionReady {
		apiCtx, apiCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer apiCancel()
		if err := checkMythicAPI(apiCtx, cfg); err != nil {
			report.err("auto-provisioning API check failed: %v", err)
		}
	}

	// Keep the event log to one line on success; failures above already explain
	// themselves and more detail is available with DEBUG_LEVEL=debug.
	if len(report.errorLines) == 0 {
		report.info("OIDC ready: issuer=%s mTLS=%s auto-provision=%s", cfg.Issuer, mtlsStatus, provisionStatus)
	}
	return report.response()
}

func oauth2Config(ctx context.Context, config *Config) (*oidc.Provider, *oauth2.Config, error) {
	oidcProvider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, nil, err
	}

	return oidcProvider, &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  config.RedirectURL,

		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}, nil
}

func Initialize() {
	auth := authstructs.AuthDefinition{
		Name:           name,
		SemVer:         version,
		Description:    "Integration with OpenID Connect (OIDC) identity provider for user authentication",
		IDPServices:    []string{name},
		NonIDPServices: nil,
		OnContainerStartFunction: func(message sharedStructs.ContainerOnStartMessage) sharedStructs.ContainerOnStartMessageResponse {
			// Reload config.json and validate the mTLS files on every start. The
			// returned response surfaces the validation result in Mythic's event log.
			return logStartupStatus()
		},
		GetIDPMetadata: func(message authstructs.GetIDPMetadataMessage) authstructs.GetIDPMetadataMessageResponse {
			response := authstructs.GetIDPMetadataMessageResponse{
				Success: false,
			}

			cfg, err := loadConfig()
			if err != nil {
				response.Error = fmt.Sprintf("Failed to load config: %v", err)
				logging.LogError(err, "OIDC metadata: failed to load config")
				return response
			}

			ctx, err := withIdPClient(context.Background(), cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to configure mTLS: %v", err)
				logMTLSFailure("metadata", err)
				return response
			}

			oidcProvider, _, err := oauth2Config(ctx, cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to create OAuth2 config: %v", err)
				logIdPFailure("metadata discovery", err)
				return response
			}

			endpoint := oidcProvider.Endpoint()
			metadata := fmt.Sprintf("Issuer: %s, AuthURL: %s, TokenURL: %s", cfg.Issuer, endpoint.AuthURL, endpoint.TokenURL)
			logging.LogDebug("OIDC metadata: fetched provider metadata",
				"issuer", cfg.Issuer,
				"auth_url", endpoint.AuthURL,
				"token_url", endpoint.TokenURL)

			response.Success = true
			response.Metadata = metadata
			return response
		},
		GetIDPRedirect: func(message authstructs.GetIDPRedirectMessage) authstructs.GetIDPRedirectMessageResponse {
			response := authstructs.GetIDPRedirectMessageResponse{
				Success: false,
			}

			cfg, err := loadConfig()
			if err != nil {
				response.Error = fmt.Sprintf("Failed to load config: %v", err)
				logging.LogError(err, "OIDC redirect: failed to load config")
				return response
			}

			ctx, err := withIdPClient(context.Background(), cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to configure mTLS: %v", err)
				logMTLSFailure("redirect", err)
				return response
			}

			_, oauth2Config, err := oauth2Config(ctx, cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to create OAuth2 config: %v", err)
				logIdPFailure("redirect discovery", err)
				return response
			}

			state := randomString(16)
			cookies := make(map[string]string)
			cookies[cookieStateName] = state

			response.Success = true
			response.RedirectURL = oauth2Config.AuthCodeURL(state)
			response.RedirectCookies = cookies

			logging.LogDebug("OIDC redirect: created authorization redirect", "issuer", cfg.Issuer, "redirect_url", cfg.RedirectURL)
			return response
		},
		ProcessIDPResponse: func(message authstructs.ProcessIDPResponseMessage) authstructs.ProcessIDPResponseMessageResponse {
			response := authstructs.ProcessIDPResponseMessageResponse{
				SuccessfulAuthentication: false,
			}

			cfg, err := loadConfig()
			if err != nil {
				response.Error = fmt.Sprintf("Failed to load config: %v", err)
				logging.LogError(err, "OIDC login: failed to load config")
				return response
			}

			stateCookie, ok := message.RequestCookies[cookieStateName]
			if !ok {
				response.Error = "Missing state cookie"
				logging.LogWarning("OIDC login: missing state cookie; the browser may have blocked cookies or the redirect was replayed")
				return response
			}

			stateCookie = strings.Replace(stateCookie, cookieStateName+"=", "", 1)

			if stateCookie != message.RequestQuery["state"] {
				response.Error = "Invalid state parameter"
				logging.LogWarning("OIDC login: invalid state parameter; the cookie did not match the callback (expired login or cookies cleared)")
				return response
			}

			ctx, err := withIdPClient(context.Background(), cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to configure mTLS: %v", err)
				logMTLSFailure("login", err)
				return response
			}

			oidcProvider, oauth2Config, err := oauth2Config(ctx, cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to create OAuth2 config: %v", err)
				logIdPFailure("login discovery", err)
				return response
			}

			verifier := oidcProvider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

			oauth2Token, err := oauth2Config.Exchange(ctx, message.RequestQuery["code"])
			if err != nil {
				response.Error = fmt.Sprintf("Failed to exchange code: %v", err)
				logIdPFailure("token exchange", err)
				return response
			}
			logging.LogDebug("OIDC login: token exchange succeeded", "issuer", cfg.Issuer)

			// Extract the ID Token from OAuth2 token.
			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				response.Error = "Missing ID Token"
				logging.LogError(nil, "OIDC login: token response did not include an id_token; check the scopes requested from the provider")
				return response
			}

			// Parse and verify ID Token payload.
			idToken, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to verify ID Token: %v", err)
				logIdPFailure("id_token verification", err)
				return response
			}

			// Extract custom claims
			var claims struct {
				Email    string `json:"email"`
				Verified bool   `json:"email_verified"`
			}

			if err := idToken.Claims(&claims); err != nil {
				response.Error = fmt.Sprintf("Failed to extract claims: %v", err)
				logging.LogError(err, "OIDC login: failed to extract email claims from the id_token")
				return response
			}

			if !claims.Verified {
				response.Error = "Email not verified"
				logging.LogWarning("OIDC login: rejected because the provider did not mark the email as verified", "email", claims.Email)
				return response
			}

			email := strings.TrimSpace(claims.Email)
			if email == "" {
				response.Error = "Provider did not return an email address"
				logging.LogWarning("OIDC login: the id_token has no email claim", "email_verified", claims.Verified)
				return response
			}

			provCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			email, err = ensureOperator(provCtx, cfg, email)
			if err != nil {
				// Generic message to the browser; details stay in the container log.
				response.Error = "Unable to provision account"
				logging.LogError(err, "OIDC login: provisioning failed", "email", email)
				return response
			}

			response.SuccessfulAuthentication = true
			response.Email = email

			logging.LogDebug("OIDC login: authentication succeeded", "email", email)
			return response
		},
		GetNonIDPMetadata: func(message authstructs.GetNonIDPMetadataMessage) authstructs.GetNonIDPMetadataMessageResponse {
			return authstructs.GetNonIDPMetadataMessageResponse{
				Success:  false,
				Metadata: "Not Supported",
			}
		},
		GetNonIDPRedirect: func(message authstructs.GetNonIDPRedirectMessage) authstructs.GetNonIDPRedirectMessageResponse {
			return authstructs.GetNonIDPRedirectMessageResponse{
				Success:       false,
				RequestFields: nil,
			}
		},
		ProcessNonIDPResponse: func(message authstructs.ProcessNonIDPResponseMessage) authstructs.ProcessNonIDPResponseMessageResponse {
			return authstructs.ProcessNonIDPResponseMessageResponse{
				SuccessfulAuthentication: false,
			}
		},
	}
	authstructs.AllAuthData.Get(name).AddAuthDefinition(auth)
}
