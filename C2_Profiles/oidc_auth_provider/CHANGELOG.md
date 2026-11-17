# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0]

### Added

- Support for mutual TLS and custom CA trust using certificate files uploaded
  through the auth container's file browser. Filenames are configured with
  `mtls_cert_file`, `mtls_key_file`, and `mtls_ca_file` in `config.json`.
- Startup validation that reloads `config.json`, validates the mTLS files, and
  performs an OIDC discovery request, with the result written to the container
  log and to the Mythic operation event log.
- Detailed logging for OIDC and mTLS failures, including the loaded CA
  certificates and hints for common certificate problems.
- Optional just-in-time user provisioning (`auto_provision`). When enabled, a
  Mythic operator is created on first successful login if no operator with the
  provider's email address exists. Provisioning uses the Mythic GraphQL API
  (`mythic_api_token`) and is restricted by
  `allowed_email_domains` (`"*"` allows every domain). Provisioning failures
  are written to the container log, and an unreachable Mythic API or failed
  lookup does not block existing users from logging in.
- TLS certificate verification is disabled for the Mythic API client so the
  private Docker network can be used without distributing Mythic's CA or
  matching the internal service name to its certificate. The endpoint is
  hardcoded to `https://mythic_nginx:7443/graphql/`, so the Docker network must
  stay a trusted boundary because requests carry an admin API token.

### Changed

- Certificates in `mtls_ca_file` are now added to the system trust store
  instead of replacing it, so public providers continue to work.
- Startup event log output is reduced to a single `OIDC ready` line on success;
  certificate, discovery, and per-request details moved to container debug
  logging, while failures still include their error and hint.
- `config.json` is resolved next to the running executable first, matching the
  directory used by the auth container's file browser, with a fallback to the
  working directory for local development.

### Fixed

- Send `redirect_url` as the OAuth2 `redirect_uri` in the authorization and
  token exchange requests. It was loaded from `config.json` but never copied
  into the OAuth2 client, so providers such as Authentik rejected the login
  with "Redirect URI Error".
- Startup validation now reports missing required `config.json` values
  (`issuer`, `client_id`, `client_secret`, `redirect_url`).
- Provisioning uses the email address stored in Mythic for the login lookup, so
  providers that return a differently capitalised address no longer fail.
  Configuration and startup checks report provisioning problems before the
  first login, and GraphQL errors are included in the log instead of being
  replaced by the HTTP status code.

## [1.0.0] - 12 April 2026

### Changed

- Initial implementation

