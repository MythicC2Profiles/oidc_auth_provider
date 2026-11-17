# oidc_auth_provider

oidc_auth_provider is an authentication container that provides support for OpenID Connect (OIDC) authentication to Mythic.

## Installation

```
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/oidc_auth_provider
```

## Configuration

After installing the provider, navigate to Installed Services → AUTH tab, then click the paperclip icon:

![](.assets/step-1.png)

Edit `config.json` file:

![](.assets/step-2.png)

Example configuration:

```json
{
    "issuer": "https://oidc.example.com",
    "client_id": "<client-id>",
    "client_secret": "<client-secret>",
    "redirect_url": "https://<mythic-domain>:7443/auth_acs/oidc/oidc",
    "mtls_cert_file": "",
    "mtls_key_file": "",
    "mtls_ca_file": "",
    "mythic_api_token": "",
    "auto_provision": false,
    "allowed_email_domains": []
}
```

`issuer` - The base URL of the OpenID Connect provider.  
`client_id` - The unique identifier assigned to your Mythic application by the OIDC provider.  
`client_secret` - A secret key issued alongside the `client_id`.  
`redirect_url` - The callback URL where the OIDC provider will send the user after authentication. Must be `https://<mythic-domain>:7443/auth_acs/oidc/oidc`.  
`mtls_cert_file` - Optional client certificate filename for mTLS.  
`mtls_key_file` - Optional client private key filename for mTLS.  
`mtls_ca_file` - Optional CA bundle filename used to trust the OIDC provider.  
`mythic_api_token` - Mythic API token used to create operators. Only used when `auto_provision` is enabled.  
`auto_provision` - Create a Mythic operator on first login when no operator with the provider's email exists. Defaults to `false`.  
`allowed_email_domains` - Email domains that may be auto-provisioned. Only used when `auto_provision` is enabled.  

Once the configuration is saved, users can log in to Mythic via the configured OIDC provider.

> **Note:** By default the user must already exist in Mythic, and their Mythic email address must match the one registered with the OIDC provider. Enable `auto_provision` to create operators automatically.

## Just-in-time user provisioning

By default the OIDC provider only authenticates users who already have a Mythic operator; an unknown email is rejected. `auto_provision` changes that: after the provider authenticates a user, the provider checks Mythic for an operator with that email address and creates one if it is missing.

This is opt-in. When `auto_provision` is `false` (the default) the auth container makes no Mythic API calls and logins behave exactly as before.

1. Log in to Mythic as an **admin**.
2. Open Settings → API Tokens and create a token. Name it something recognisable, for example `oidc-auth-provider`.
3. Set the provisioning fields in `config.json`:

```json
{
    "issuer": "https://authentik.example.com/application/o/mythic/",
    "client_id": "<client-id>",
    "client_secret": "<client-secret>",
    "redirect_url": "https://mythic.example.com:7443/auth_acs/oidc/oidc",
    "mtls_cert_file": "",
    "mtls_key_file": "",
    "mtls_ca_file": "",
    "mythic_api_token": "<admin-api-token>",
    "auto_provision": true,
    "allowed_email_domains": ["example.com"]
}
```

- Provisioning always calls `https://mythic_nginx:7443/graphql/`, Mythic's internal nginx endpoint on the Docker network. This assumes the default `NGINX_HOST=mythic_nginx` and `NGINX_PORT=7443`; change the constant in `provision.go` if you renamed them.
- `mythic_api_token` - The token from step 2. Creating operators requires an **admin** token; a bot or operator token is rejected.
- TLS certificate verification is **disabled** for the Mythic API call. This lets the auth container reach Mythic over the private Docker network without distributing Mythic's Caddy CA or matching the internal service name to the certificate. The token is still sent over an encrypted connection, but the container does not verify who is on the other end. Keep the Docker network as a trusted boundary.
- `allowed_email_domains` - Required when `auto_provision` is enabled.
  - `["example.com"]` provisions only `*@example.com` addresses. Matching is case-insensitive and applies to the whole domain, so subdomains must be listed separately.
  - `["*"]` provisions any domain the OIDC provider authenticates.
  - An empty list denies all provisioning. Existing operators can still log in.
- The allow list is checked only when an operator is about to be created, so changing it never locks out users who already have accounts.

New operators are created with the email address as both username and email, a random unused password, the regular `user` account type, and **no operation membership**. Assign them to operations through the Mythic UI after their first login. If an operator with that email already exists but is deactivated or deleted, it is not recreated; reactivate it in the Mythic UI instead.

Provisioning is best-effort. If the Mythic API is unreachable or the lookup fails, the login continues and Mythic's own operator lookup decides. The login fails only when the operator is confirmed missing and creation does not succeed, or when the email domain is not allowed. Operator creation, lookup failures, and creation errors are written to the container log:

```sh
sudo ./mythic-cli logs oidc_auth_provider -f
```

At startup the provider validates the provisioning settings, performs an authenticated lookup to confirm the URL and token work, and reports the result to both the container log and the Mythic event log. A failure there means new operators will not be created until the configuration is fixed, but normal logins keep working.

> **Warning:** `createOperator` requires admin privileges, so `mythic_api_token` is a full Mythic admin credential. Anyone who can read `config.json` or the container filesystem can administer Mythic. Use a dedicated admin account, restrict access to the auth container, and rotate the token if it is exposed. Do not commit a filled-in `config.json`.
>
> Because TLS verification is disabled for the Mythic API, the Docker network must remain trusted. If untrusted containers or hosts can reach `mythic_nginx`, switch back to CA verification before continuing to use provisioning.
>
> With provisioning enabled, the OIDC provider's application binding becomes the only gate for creating Mythic accounts. Restrict the Authentik application to a group or policy, keep MFA enabled, and limit who can change email addresses. See the `email_verified` note below.

## Authentik example

A minimal Authentik setup needs one OAuth2/OpenID Connect provider and one application.

1. In Authentik, create an application (Applications → Applications → Create) and note its **slug**. The slug becomes part of the issuer URL.
2. Create an OAuth2/OpenID Connect provider with:
   - **Client type:** Confidential
   - **Redirect URI:** type `Strict`, value `https://<mythic-domain>:7443/auth_acs/oidc/oidc`. Use the exact URL users open Mythic with; the path is case-sensitive.
   - **Scopes:** `openid`, `email`, `profile`
   - **Include claims in id_token:** enabled (the default)
   - A signing key selected
3. Bind the application to the provider and note the Client ID and Client Secret.
4. Fill in `config.json`:

```json
{
    "issuer": "https://authentik.example.com/application/o/mythic/",
    "client_id": "<client-id>",
    "client_secret": "<client-secret>",
    "redirect_url": "https://mythic.example.com:7443/auth_acs/oidc/oidc",
    "mtls_cert_file": "",
    "mtls_key_file": "",
    "mtls_ca_file": "",
    "mythic_api_token": "",
    "auto_provision": false,
    "allowed_email_domains": []
}
```

The issuer must end with `/`; Authentik includes the trailing slash in the `iss` claim and the issuer configured here must match it exactly. The provider always requests the `openid`, `profile`, and `email` scopes.

## mTLS

If the OIDC provider requires mutual TLS (or a private certificate authority), upload the certificate files through the auth container's file browser and reference their filenames from `config.json`.

1. Install the auth container.
2. Open the provider's file browser using the paperclip icon, then upload:
   - the client certificate, for example `oidc_mtls_client.pem`
   - the client private key, for example `oidc_mtls_client.key`
   - optionally, the CA bundle used to trust the provider, for example `oidc_mtls_ca.pem`
3. Edit `config.json` and set the corresponding filenames:

```json
{
    "issuer": "https://oidc.example.com",
    "client_id": "<client-id>",
    "client_secret": "<client-secret>",
    "redirect_url": "https://<mythic-domain>:7443/auth_acs/oidc/oidc",
    "mtls_cert_file": "oidc_mtls_client.pem",
    "mtls_key_file": "oidc_mtls_client.key",
    "mtls_ca_file": "oidc_mtls_ca.pem"
}
```

The fields are optional:

- **All empty** – mTLS is disabled and behaviour is unchanged.
- **`mtls_ca_file` only** – certificates from the uploaded bundle are added to the system trust store for OIDC requests.
- **`mtls_cert_file` + `mtls_key_file`** – mutual TLS is used, with or without a custom CA.
- **Only one of the certificate/key fields set** – treated as a configuration error. Both are required for client authentication.

The files are read from the container's runtime directory on every login, so changes take effect without restarting the container. On startup the provider also reloads `config.json`, validates the mTLS files, and performs a discovery request; the result is written to the container log.

Filenames must be plain filenames (no directories), matching the files shown in the file browser.

> **Note:** Files uploaded through the file browser live inside the container. Re-upload them if the container is recreated, for example during an update.

![](.assets/step-3.png)
