package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MythicMeta/MythicContainer/logging"
	"golang.org/x/oauth2"
)

// The last mTLS configuration that was loaded is kept for failure logging so
// an "unknown authority" error in the container log also shows which CAs were
// actually trusted. It is refreshed on every login, never cached for use.
var (
	mtlsDiagnosticsMu sync.RWMutex
	mtlsDiagnostics   = "mTLS disabled (no mtls_*_file entries in config.json)"
)

func setMTLSDiagnostics(summary string) {
	mtlsDiagnosticsMu.Lock()
	defer mtlsDiagnosticsMu.Unlock()
	mtlsDiagnostics = summary
}

func getMTLSDiagnostics() string {
	mtlsDiagnosticsMu.RLock()
	defer mtlsDiagnosticsMu.RUnlock()
	return mtlsDiagnostics
}

// containerDir returns the directory that contains the running executable.
// Mythic's auth container file browser reads and writes files in this same
// directory, so anything uploaded there is available to this service.
func containerDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate container directory: %w", err)
	}
	return filepath.Dir(exe), nil
}

// readMTLSFile reads a file from the container directory exposed by the auth
// container's file browser. Only plain filenames are accepted.
func readMTLSFile(name string) ([]byte, error) {
	if name == "" {
		return nil, nil
	}
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, fmt.Errorf("mTLS filename %q must be a plain filename in the container directory", name)
	}

	dir, err := containerDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mTLS file %q from %q: %w", name, path, err)
	}
	logging.LogDebug("OIDC mTLS: read file", "file", name, "path", path, "bytes", len(contents))
	return contents, nil
}

// parsePEMCertificates decodes every CERTIFICATE block in a PEM bundle.
func parsePEMCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			logging.LogWarning("OIDC mTLS: ignoring non-certificate PEM block", "type", block.Type)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logging.LogError(err, "OIDC mTLS: failed to parse a certificate in the uploaded bundle")
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}

func certSummary(cert *x509.Certificate) string {
	return fmt.Sprintf("subject=%q issuer=%q not_before=%s not_after=%s is_ca=%t",
		cert.Subject.String(),
		cert.Issuer.String(),
		cert.NotBefore.UTC().Format(time.RFC3339),
		cert.NotAfter.UTC().Format(time.RFC3339),
		cert.IsCA,
	)
}

// buildClient assembles the HTTP client from PEM bytes read from the
// container's runtime directory (the key never leaves this container).
func buildClient(certPEM, keyPEM, caPEM []byte) (*http.Client, error) {
	// Half a keypair is always a mistake; refuse rather than silently
	// connecting without client auth.
	if (len(certPEM) == 0) != (len(keyPEM) == 0) {
		return nil, fmt.Errorf("configure both mtls_cert_file and mtls_key_file (only one is set)")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} // no InsecureSkipVerify, by design
	var diagnostics []string

	if len(caPEM) > 0 {
		// Start from the system roots so public IdPs keep working, then add
		// the uploaded bundle. Caddy's local CA works as a trust anchor even
		// if only the intermediate is uploaded, but Go cannot fetch a missing
		// intermediate itself (it does not follow AIA), so a bundle containing
		// both the root and intermediate is the most reliable option.
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			if err != nil {
				logging.LogWarning("OIDC mTLS: could not load the system trust store; using only uploaded certificates", "error", err.Error())
			}
			pool = x509.NewCertPool()
		}
		certs := parsePEMCertificates(caPEM)
		if len(certs) == 0 {
			return nil, fmt.Errorf("mtls_ca_file does not contain any valid PEM certificates")
		}
		diagnostics = append(diagnostics, fmt.Sprintf("%d CA certificate(s) loaded from mtls_ca_file", len(certs)))
		for _, cert := range certs {
			pool.AddCert(cert)
			diagnostics = append(diagnostics, "trusted CA: "+cert.Subject.String())
			logging.LogDebug("OIDC mTLS: trusting CA certificate", "certificate", certSummary(cert))
			if !cert.IsCA {
				logging.LogWarning("OIDC mTLS: certificate in mtls_ca_file is not a CA certificate; it cannot sign a server certificate", "certificate", certSummary(cert))
			}
			if time.Now().After(cert.NotAfter) {
				logging.LogWarning("OIDC mTLS: CA certificate has expired", "certificate", certSummary(cert))
			}
		}
		logging.LogDebug("OIDC mTLS: CA bundle loaded",
			"certificates_in_file", len(certs),
			"trust_store", "system roots plus uploaded certificates")
		tlsCfg.RootCAs = pool
	}

	if len(certPEM) > 0 {
		pair, err := tls.X509KeyPair(certPEM, keyPEM) // also verifies key matches cert
		if err != nil {
			return nil, fmt.Errorf("client cert/key: %w", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse client cert: %w", err)
		}
		now := time.Now()
		if now.After(leaf.NotAfter) {
			return nil, fmt.Errorf("client cert expired %s (subject %q)", leaf.NotAfter, leaf.Subject.String())
		}
		if now.Before(leaf.NotBefore) {
			return nil, fmt.Errorf("client cert not valid until %s (subject %q, clock skew?)", leaf.NotBefore, leaf.Subject.String())
		}
		if time.Until(leaf.NotAfter) < 14*24*time.Hour {
			logging.LogWarning("OIDC mTLS: client certificate expires soon", "certificate", certSummary(leaf))
		}
		logging.LogDebug("OIDC mTLS: client certificate loaded",
			"certificate", certSummary(leaf),
			"chain_length", len(pair.Certificate))
		diagnostics = append(diagnostics, "client certificate: "+leaf.Subject.String())
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	setMTLSDiagnostics(strings.Join(diagnostics, "; "))

	// Logged after the handshake succeeds; failures are logged by the caller
	// with tlsFailureHint so the container log explains what to check.
	tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
		logging.LogDebug("OIDC mTLS: TLS connection verified",
			"tls_version", tls.VersionName(cs.Version),
			"server_name", cs.ServerName,
			"peer_certificates", len(cs.PeerCertificates),
			"verified_chains", len(cs.VerifiedChains))
		return nil
	}

	// Clone the default transport to keep proxy env vars, keepalives, etc.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

// idpClient returns an HTTP client built from the files named in config.json.
// (nil, nil) means no mTLS files are configured, so behaviour is unchanged.
// Files are read on each call so uploads and rotations take effect without a
// container restart, and the settings are always applied after a fresh start.
func idpClient(config *Config) (*http.Client, error) {
	if config.MTLSCertFile == "" && config.MTLSKeyFile == "" && config.MTLSCAFile == "" {
		setMTLSDiagnostics("mTLS disabled (no mtls_*_file entries in config.json)")
		logging.LogDebug("OIDC mTLS: disabled (no mtls_*_file entries in config.json)")
		return nil, nil
	}

	logging.LogDebug("OIDC mTLS: loading configuration",
		"mtls_cert_file", config.MTLSCertFile,
		"mtls_key_file", config.MTLSKeyFile,
		"mtls_ca_file", config.MTLSCAFile)

	certPEM, err := readMTLSFile(config.MTLSCertFile)
	if err != nil {
		setMTLSDiagnostics(fmt.Sprintf("mTLS configuration failed: %v", err))
		return nil, err
	}
	keyPEM, err := readMTLSFile(config.MTLSKeyFile)
	if err != nil {
		setMTLSDiagnostics(fmt.Sprintf("mTLS configuration failed: %v", err))
		return nil, err
	}
	caPEM, err := readMTLSFile(config.MTLSCAFile)
	if err != nil {
		setMTLSDiagnostics(fmt.Sprintf("mTLS configuration failed: %v", err))
		return nil, err
	}

	client, err := buildClient(certPEM, keyPEM, caPEM)
	if err != nil {
		setMTLSDiagnostics(fmt.Sprintf("mTLS configuration failed: %v", err))
		return nil, fmt.Errorf("configure mTLS: %w", err)
	}
	return client, nil
}

// withIdPClient attaches the client to ctx (no-op when no mTLS files are
// configured). oauth2.Config.Exchange and go-oidc's NewProvider both read the
// client from the oauth2.HTTPClient context key. Safe to apply more than once.
func withIdPClient(ctx context.Context, config *Config) (context.Context, error) {
	c, err := idpClient(config)
	if err != nil || c == nil {
		return ctx, err
	}
	return context.WithValue(ctx, oauth2.HTTPClient, c), nil
}

// logMTLSFailure writes an mTLS configuration failure (missing file, bad PEM,
// mismatched keypair, expired client cert, ...) to the container log.
func logMTLSFailure(stage string, err error) {
	logging.LogError(err, "OIDC mTLS configuration failed",
		"stage", stage,
		"mtls", getMTLSDiagnostics(),
		"hint", "check that mtls_*_file values in config.json match files shown in the auth container's file browser, and that they contain PEM data")
}

// logIdPFailure writes an OIDC request failure to the container log together
// with a hint that explains the most common certificate problems. Returned
// errors are also surfaced in the Mythic UI.
func logIdPFailure(stage string, err error) {
	fields := []interface{}{
		"stage", stage,
		"mtls", getMTLSDiagnostics(),
	}
	if hint := tlsFailureHint(err); hint != "" {
		fields = append(fields, "hint", hint)
	}
	logging.LogError(err, "OIDC request failed", fields...)
}

// tlsFailureHint translates common x509/TLS errors into actionable advice for
// the container log.
func tlsFailureHint(err error) string {
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return "the server certificate is not signed by a trusted CA: upload the CA certificate(s) that sign the leaf certificate and set mtls_ca_file to that filename. For Caddy's local CA this is usually both pki/authorities/local/root.crt and pki/authorities/local/intermediate.crt in one PEM file"
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return "the issuer hostname is not present in the server certificate's SANs: check the issuer URL in config.json and the certificate Caddy is serving for that name"
	}

	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return "a certificate is invalid or outside its validity period: check the server certificate dates and the container clock"
	}

	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return "the server did not reply with TLS: check that the issuer URL uses https:// and points at the correct port"
	}

	if strings.Contains(err.Error(), "tls: internal error") {
		return "the server aborted the TLS handshake: usually the server has no certificate for the requested name or cannot complete the handshake"
	}
	return ""
}
