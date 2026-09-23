# IDAuth service

IDAuth service

## Built with Azugo Go Web Framework

This project is built using the [Azugo Go Web Framework](https://azugo.io), a powerful and flexible framework for building modern web applications in Go. Check out the [Azugo GitHub page](https://github.com/azugo) for more information and documentation.

<!-- TOC -->

- [IDAuth service](#idauth-service)
  - [Built with Azugo Go Web Framework](#built-with-azugo-go-web-framework)
  - [Setup on a local machine](#setup-on-a-local-machine)
    - [Build and run the project](#build-and-run-the-project)
    - [Before commit](#before-commit)
  - [Environments](#environments)
    - [Description of environment variables](#description-of-environment-variables)
  - [EDIM verifier flows (cross\_device vs same\_device)](#edim-verifier-flows-cross_device-vs-same_device)
  - [Request system token](#request-system-token)
  - [License](#license)

<!-- /TOC -->

## Setup on a local machine

### Build and run the project

Run the following commands to prepare the project for building:

```sh
go mod download
go generate ./...
```

Then you can build and run the project by using vscode build task (Ctrl+Shift+B). It will build the project with according to current OS.

After that you can run the project by using vscode launch task (F5). It will run the project with the default configuration.

### Before commit

> CI requires linted, formatted code

You should run:

```sh
gofmt -s -w ./..
```

or

```sh
gofumpt -w ./..
```

and fix any errors reported by

```sh
golangci-lint run
```

## Environments

In order to run the project, you need to create a `.env` file in the root of the project. `.env` file example:

```bash
    ENVIRONMENT: "production"
    BASE_PATH: "/idauth"
    REVERSE_PROXY_TRUSTED_IPS: "*"
    REVERSE_PROXY_LIMIT: "3"

    CACHE_TYPE: redis
    CACHE_CONNECTION: rediss://edimdev@example.lv:6379/9?skip\_verify=true
    CACHE_PASSWORD_FILE: /secret/edim-redis-pw
    CACHE_KEY_PREFIX: edimdev-idauth

    SESSION_COUNTDOWN: "5m"
    SESSION_TIMEOUT: "60m"

    IDAUTH_STORE_CLIENTS_FILE: /secret/edim-idauth-clients

    EPARAKSTS_AUTH_URL: https://eidas-demo.eparaksts.lv/trustedx-authserver/oauth/lvrtc-eipsign-as
    EPARAKSTS_TOKEN_URL: https://eidas-demo.eparaksts.lv/trustedx-authserver/oauth/lvrtc-eipsign-as/token
    EPARAKSTS_USERINFO_URL: https://eidas-demo.eparaksts.lv/trustedx-resources/openid/v1/users/me
    EPARAKSTS_CLIENT_ID: edim-idauth
    EPARAKSTS_CLIENT_SECRET_FILE: /secret/edim-idauth-eparaksts-secret
    EPARAKSTS_PROMPT: login
    EPARAKSTS_SCOPE: urn:lvrtc:fpeil:aa

    AUDIT_ENDPOINT: http://api-audit.local:8080/audit/1.0
    VERIFIER_BACKEND_URL: "http://demo-verifier-backend.local:8080"
    VERIFIER_BACKEND_PRESENT_RETRIES: 24
    VERIFIER_BACKEND_VERIFY_WAIT_IN_SECONDS: 10
    VERIFIER_CACHE_TTL: "10m"
    EDIM_TEMPLATE_PATH: /pid-template.json

    VERIFIER_ENGINE: v2
    VERIFIER_V2_URL: "http://management-api.local:8080"
    VERIFIER_V2_API_KEY_FILE: /secret/edim-verifier-v2-api-key
```

### Description of environment variables

| Variable | Description | Example |
| --- | --- | --- |
|  | **Environment Configuration** |  |
| `ENVIRONMENT` | Deployment environment | "production" |
| `BASE_PATH` | Base URL path for the service | "/idauth" |
| `REVERSE_PROXY_TRUSTED_IPS` | Trusted IP addresses for reverse proxy | "\*" |
| `REVERSE_PROXY_LIMIT` | Maximum number of proxy hops | "3" |
|  | **Cache Configuration** |  |
| `CACHE_TYPE` | Type of cache system | "redis" |
| `CACHE_CONNECTION` | Redis connection string | "rediss://edimdev@example.lv:6379/9?skip\_verify=true" |
| `CACHE_PASSWORD_FILE` | Path to file containing Redis password | "/secret/edim-redis-pw" |
| `CACHE_KEY_PREFIX` | Prefix for cache keys | "edimdev-idauth" |
|  | **Session Configuration** |  |
| `SESSION_COUNTDOWN` | Time before session expiration warning | "5m" |
| `SESSION_TIMEOUT` | Total session duration | "60m" |
|  | **Store Configuration** |  |
| `IDAUTH_STORE_CLIENTS_FILE` | Path to clients configuration file | "/secret/edim-idauth-clients" |
|  | **eParaksts Authentication Configuration** |  |
| `EPARAKSTS_AUTH_URL` | eParaksts OAuth authorization endpoint | "https://eidas-demo.eparaksts.lv/trustedx-authserver/oauth/lvrtc-eipsign-as" |
| `EPARAKSTS_TOKEN_URL` | eParaksts Token exchange endpoint | "https://eidas-demo.eparaksts.lv/trustedx-authserver/oauth/lvrtc-eipsign-as/token" |
| `EPARAKSTS_USERINFO_URL` | eParaksts User information endpoint | "https://eidas-demo.eparaksts.lv/trustedx-resources/openid/v1/users/me" |
| `EPARAKSTS_CLIENT_ID` | eParaksts Client identifier | "edim-idauth" |
| `EPARAKSTS_CLIENT_SECRET_FILE` | Path to file containing eParaksts client secret | "/secret/edim-idauth-eparaksts-secret" |
| `EPARAKSTS_PROMPT` | Authentication prompt type | "login" |
| `EPARAKSTS_SCOPE` | Requested OAuth scope | "urn:lvrtc:fpeil:aa" |
|  | **Audit Configuration** |
| `AUDIT_ENDPOINT` | Audit endpoint | "http://api-audit.local:8080/audit/1.0" |
|  | **Edim Configuration** |
| `VERIFIER_ENGINE` | Which verifier backend `github.com/digimaks/go-verifier` talks to: `v1` (the reference EUDI backend, `VERIFIER_BACKEND_*`, cross_device only) or `v2` (the mgmt-api backend, `VERIFIER_V2_*`, adds same_device/webhooks). Default `v1`. **`edim:same_device` requires `v2`.** | "v2" |
| `VERIFIER_BACKEND_URL` | Edim verifier endpoint (v1 only) | "https://verifier.example.com/verifier-backend" |
| `VERIFIER_BACKEND_PRESENT_RETRIES` | How many times we try to get verifier backend response (v1 only) | "24" |
| `VERIFIER_BACKEND_VERIFY_WAIT_IN_SECONDS` | How long we wait in seconds for the next retry (v1 only) | "10" |
| `VERIFIER_CACHE_TTL` | v1 offer cache TTL | "10m" |
| `EDIM_TEMPLATE_PATH` | Path to the JSON template describing which credential(s)/claims to request from the verifier (`go-verifier`'s `Configuration.TemplatePath`, required). See `edim/pid-template.json`. | "/pid-template.json" |
| `EDIM_DEEP_LINK_SCHEME` | Wallet deep-link scheme used when the v1 backend's response has no ready-made link. Default `eudi-openid4vp`. | "eudi-openid4vp" |
| `VERIFIER_V2_URL` | mgmt-api base URL (v2 only, required when `VERIFIER_ENGINE=v2`) | "http://management-api:8080" |
| `VERIFIER_V2_API_KEY` / `VERIFIER_V2_API_KEY_FILE` | mgmt-api client API key, or a mounted secret file (v2 only) | "/secret/edim-verifier-v2-api-key" |
| `VERIFIER_V2_WEBHOOK_JWKS_URL` | Verifier's public JWKS endpoint, enables `VerifyWebhook` (v2 only, optional — same_device works without it). | "https://verifier.example.com/.well-known/verifier-jwks.json" |
| `VERIFIER_V2_SAME_DEVICE_TX_TTL` | How long an unredeemed `edim:same_device` tx is kept in memory before being dropped. Default `5m`. | "5m" |
| `IDAUTH_CODE_STATE_TTL` | Cache duration for authorization code flow state | "5m" |
| `IDAUTH_CODE_TTL` | Cache duration for authorization code data | "1m" |
| `SMARTID_ENDPOINT` |  | "https://sid.demo.sk.ee/smart-id-rp/v2" |
| `SMARTID_RELYING_PARTY_NAME` | RP friendly name, one of those configured for particular RP. | "DEMO" |
| `SMARTID_RELYING_PARTY_UUID` | UUID of Relying Party | "00000000-0000-0000-0000-000000000000" |
| `SMARTID_CERT_LEVEL` | Level of certificate requested. `ADVANCED/QUALIFIED/QSCD` | "QUALIFIED" |
| `SMARTID_HASH_TYPE` | Hash algorithm | "SHA512" |
| `SMARTID_INTERACTION` | Interaction flow | "displayTextAndPIN" |
| `SMARTID_TEXT` | Interaction text. Max 60 characters | "Custom text" |
| `SMARTID_CREATE_TIMEOUT` | Create session request poll timeout in seconds | "90" |
| `SMARTID_CHECK_TIMEOUT` | Check session request poll timeout in seconds | "1" |
| `SMARTID_PRESENT_RETRIES` | How many times we try to get verifier backend response | "24" |
| `SMARTID_WAIT_IN_SECONDS` | How long we wait in seconds for the next retry | "5" |
| `SMARTID_CACHE_TTL` | Cache duration for authorization code flow state | "5m" |
|  | **DPoP Configuration** |  |
| `DPOP_ACCEPTED_HTU` | Space-separated additional token endpoint URLs that DPoP proofs may be bound to. Add the wallet-facing proxy URL when a reverse proxy sits in front of idauth (wallets bind the proof to the URL they called, not idauth's internal URL). Defaults to the internal token endpoint only. | "https://api-wallet.example.com/token" |
| `DPOP_IAT_WINDOW` | Accepted clock skew / age window for DPoP proof `iat` claim. Default `1m`. | "1m" |
|  | **Authorization Code Flow Configuration** |  |
| `IDAUTH_CODE_SCOPES` | Comma-separated scopes accepted at `/authorizationV3` and `/par`. Must match the credential-configuration scopes advertised by issuer-go exactly. Defaults to `openid,profile` if unset. | "openid,profile,eu.europa.ec.eudi.pid_vc_sd_jwt,eu.europa.ec.eudi.pid_mdoc" |
| `IDAUTH_CODE_STATE_TTL` | Cache duration for the browser authorize flow's correlation state. | "5m" |
| `IDAUTH_CODE_TTL` | Cache duration (single-use) for a minted authorization code. | "1m" |
| `PRE_AUTH_TTL` | Cache duration for pre-authorized_code items. | "5m" |
|  | **Client Attestation Configuration (`attest_jwt_client_auth`)** |  |
| `CLIENT_ATTESTATION_TRUST_ANCHORS_FILE` | Path to a PEM file containing the EC public key(s) (`PUBLIC KEY` or `CERTIFICATE` blocks only — never a private key) trusted to sign Wallet Instance Attestations (WIA). Attestation-based client auth is disabled if unset. | "/app/config/attestation_trust.pem" |
| `CLIENT_ATTESTATION_ACCEPTED_AUD` | Additional `aud` values accepted on the attestation PoP JWT, besides idauth's own `/api/1.0/token` and `/par` endpoints. Comma-separated. Include the bare AS issuer identifier (e.g. `https://idauth.example.com`) — the EUDI reference wallet binds the PoP `aud` to the issuer identifier from AS metadata, not the token endpoint URL. Add the wallet-facing proxy's token URL when wallets still go through api-wallet-digimaks. | "https://api-wallet.example.com/token,https://idauth.example.com" |
| `CLIENT_ATTESTATION_IAT_WINDOW` | Accepted clock skew / age window for the attestation PoP `iat` claim; also the freshness window when the PoP carries no `exp` (the EUDI reference wallet sends only `iat`/`nbf`). Default `1m`. | "1m" |
| `CLIENT_ATTESTATION_REQUIRE_KEY_BINDING` | Enforces the WIA `cnf`/DPoP key binding at the token endpoints. Added in TS3 v1.5.1, rolled back in TS3 v1.5.2 (2026-05-26, §2.2.1.1) — no longer normative. Opt-in only; default `false`. | "false" |
| `IDAUTH_REQUIRE_CLIENT_ATTESTATION_PREAUTH` | When `true`, the `pre-authorized_code` grant rejects token requests without `OAuth-Client-Attestation` headers. Default `false` (verify-if-present) — flip once all app versions send WIA on the direct token call. | "false" |
|  | **Introspection** |  |
| `IDAUTH_REQUIRE_INTROSPECTION_AUTH` | When `true`, `POST /introspection` requires `client_secret_basic` authentication; when `false` (staged default), unauthenticated introspection is accepted. Enable in every environment where issuer-go relies on introspection for issuance decisions. | "true" |
|  | **Pushed Authorization Requests (PAR, RFC 9126)** |  |
| `IDAUTH_PAR_TTL` | How long a `POST /par` request_uri stays redeemable at `/authorizationV3`. Default `90s`. | "90s" |
| `IDAUTH_REQUIRE_PAR` | When `true`, `/authorizationV3` rejects any request that does not carry a `request_uri` from a prior `POST /par`. Leave `false` until all wallet clients are confirmed to push via PAR first. Default `false`. | "false" |
|  | **Refresh tokens (DPoP-bound, rotating)** |  |
| `IDAUTH_REFRESH_TOKEN_TTL` | How long a rotating refresh token stays valid without being used. Default `720h` (30 days). | "720h" |
|  | **Public URL & app links** |  |
| `IDAUTH_API_PUBLIC_URL` | idauth's wallet-reachable public base URL — used in AS metadata (`token_endpoint`, `pushed_authorization_request_endpoint`), DPoP accepted `htu`, and attestation PoP audiences. | "https://idauth.example.com" |
| `ANDROID_APP_PACKAGE` | Android application package for `/.well-known/assetlinks.json` (app-link verification). | "lv.example.wallet" |
| `ANDROID_APP_FINGERPRINTS` | SHA-256 signing-certificate fingerprints for `assetlinks.json`. Comma-separated. | "AA:BB:..." |
| `APPLE_APP_IDS` | Apple app identifiers for `/.well-known/apple-app-site-association`. Comma-separated. | "TEAMID.lv.example.wallet" |
| `OTEL_SERVICE_NAME` | APM service name| `"digimaks-api-idauth"`| No |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | APM endpoint server| `"https://apm.server:8200"`| No |
| `OTEL_EXPORTER_OTLP_INSECURE_SKIP_VERIFY` | APM skip insecure https| `"true"`| No |
| `ELASTIC_APM_SECRET_TOKEN` | APM credentials| `"generated_credentials"`| No |

## EDIM verifier flows (cross_device vs same_device)

`/authorizationV3` (and `/par`) select which edim flow to run via `acr_values`
(or `auth_type`), same as the existing `eparaksts:mobileid:cross_device`
pattern:

- `acr_values=edim` (default) — cross_device: renders a QR-code page, the
  wallet is scanned from another device.
- `acr_values=edim:same_device` — same_device: idauth 302s straight to the
  wallet's deep link (no QR), and the wallet's own browser redirect lands on
  `/edim/verifier/same-device/return?tx=...&response_code=...` to finish the
  OAuth code exchange. **Requires `VERIFIER_ENGINE=v2`** — go-verifier's
  same-device support (`GenerateSameDeviceOffer`/`HandleWalletReturn`) has no
  v1 equivalent.

A client must opt in via its `metadata` in `clients.yaml` before it's allowed
to request `edim:same_device`:

```yaml
- client_id: some-native-app
  redirect_uri:
    - https://some-native-app.example.com/cb
  metadata:
    same_device: "true"
```

Requesting `edim:same_device` from a client without this metadata is
rejected. A client can still use plain `edim` (cross_device) regardless of
this flag — the choice is made per-request by whichever `acr_values` the
client sends, not fixed per client.

**Operational prerequisite:** the verifier mgmt-api's `allowedOrigins` for
this client must include idauth's public host (the same list that gates
`GenerateSameDeviceOffer`'s `redirectUri`), or same-device offer creation is
rejected at runtime.

## License

EUPL-1.2 — see [LICENSE](./LICENSE).
