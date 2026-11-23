# Router-initiated polling: Python compatibility protocol v1

The compatibility endpoint lets a registered router authenticate to Flask and receive validated no-action JSON. Actual MikroTik RouterOS clients use the separately documented V2 protocol.

This document retains the **v1 HMAC-SHA256** Python contract. Native
RouterOS 7.21.4 installations now use [protocol v2](routeros-v2-protocol.md),
which adds HMAC-SHA512, integer timestamps and signed response receipts.
Use [the installation guide](routeros-setup.md) for actual router setup;
v1 remains available for existing clients and the local simulator.

The current endpoint always returns `action: "none"` with an empty configuration. There is no implemented optimizer or SNMP collector in this project copy. This layer leaves traffic-storage interfaces, configured sampling/averaging settings, and existing calculations unchanged; it does not create a replacement optimization algorithm.

## 1. Components and direction

```text
Router or simulated client
  → signed POST /api/controller/v1/poll
  → request validation and per-router authentication
  → expiry, replay, and rate-limit checks
  → versioned no-action JSON response
```

The server does not log in to RouterOS for this process. The existing RouterOS API diagnostic remains an optional, separate read-only check.

| Component | Responsibility |
| --- | --- |
| `device_app.py` | Device-only Flask application and transport/error handling. |
| `serve_devices.py` | Separate Waitress listener; loopback binding only in this stage. |
| `controllers/router_poll_controller.py` | Accept and validate the HTTP polling request. |
| `services/router_protocol.py` | Strict request/response fields, timestamps, IDs, and signature canonicalization. |
| `services/router_auth_service.py` | Verify current per-router credentials and signed request freshness. |
| `services/router_poll_service.py` | Persist rate limits and replay protection, update accepted check-ins, and issue no-action responses. |
| `services/router_communication_state.py` | Validate bounded communication-state JSON. |

## 2. Automated protocol checks

```sh
.venv/bin/python -m pytest -q tests/test_router_auth.py tests/test_router_polling.py
```

Protocol tests use isolated temporary fixtures and make no router connections.
Runtime simulated-router scripts are removed. Actual routers use their
provisioned authenticated client and the approved HTTPS controller listener.

## 3. Separate listener and configuration

The browser application starts with `python serve.py` on loopback port `8000`. Start the device listener separately:

```sh
.venv/bin/python serve_devices.py
```

Its default is `127.0.0.1:8001`. It exposes no dashboard, router-management forms, browser login, static assets, or legacy configuration route.

| Environment setting | Default | Meaning |
| --- | --- | --- |
| `CONTROLLER_HOST` | `127.0.0.1` | Device listener bind address. The launcher currently rejects non-loopback addresses. |
| `CONTROLLER_PORT` | `8001` | Device listener TCP port. |
| `CONTROLLER_BASE_URL` | Unset | Approved external HTTPS origin; does not configure TLS or discover a server address. |
| `CONTROLLER_TRUSTED_PROXY` | Unset | One explicit loopback proxy IP, configured only after installing its approved TLS proxy. |
| `SIMULATION_MODE` | `true` | Allows plain HTTP only for loopback clients using a loopback host. Authentication is still required. |
| `LIVE_ROUTING_ENABLED` | `false` | Must remain false. True is rejected at device-app startup. |
| `ROUTER_POLL_INTERVAL` | `60` | Suggested delay between polls, in seconds. |
| `ROUTER_REQUEST_MAX_AGE_SECONDS` | `120` | Maximum accepted request age. |
| `ROUTER_CLOCK_SKEW_SECONDS` | `30` | Maximum accepted future timestamp offset. |
| `ROUTER_RESPONSE_TTL_SECONDS` | `60` | Response validity period; supported range is 1–300 seconds. |
| `ROUTER_RATE_LIMIT_ATTEMPTS` | `30` | Maximum polling authentication attempts per source in a window. |
| `ROUTER_RATE_LIMIT_WINDOW_SECONDS` | `60` | Source rate-limit window. |

These settings are loaded from the environment/local `.env`; secrets must stay outside source control. Copy needed examples from `.env.example` without overwriting an existing `.env`, then restart affected processes. Environment changes do not alter an already-running process.

The sketch's address and port are examples and are not used as deployment settings.

New `automation_settings.json` files start in simulation mode; startup preserves an existing mode. The stored automation mode and the device transport `SIMULATION_MODE` are separate settings. Neither permits live routing changes in this stage.

## 4. Router registry and credentials

Both **Add router** buttons open `/routers/connect`, which displays the device polling endpoint rather than a registration form. Manual browser registration and `POST /routers/add` are disabled. The endpoint URL is derived only from server configuration, never from browser Host or forwarded headers. The page advertises a loopback test address until an approved `CONTROLLER_BASE_URL` origin is configured. A configured URL is not evidence of network reachability; the current launcher still permits only loopback binding.

Authentication requires an already-registered router with:

- `router_id`: its exact registry identity.
- `controller_auth_ref`: an uppercase environment-variable prefix, up to 64 characters.
- `controller_auth_enabled`: explicitly `true` after provisioning.
- `controller_auth_key_ids`: a nonempty list of unique active key IDs.

Key IDs contain uppercase letters, digits, and underscores, start with a letter, and have at most 32 characters. The environment name for a secret is:

```text
{controller_auth_ref}_{key_id}_SECRET
```

The secret must contain 32–4096 characters. Use distinct cryptographically generated secrets per router/key; do not reuse the RouterOS management password. The ordinary router form accepts only a reference. It does not accept a controller secret, enable authentication, or choose active key IDs.

Changing a reference through the inventory form clears enablement and its active IDs until reprovisioned. Editing other fields preserves existing authentication and communication metadata. Public projection excludes unknown private registry fields.

Multiple active IDs allow an overlap during key rotation. Removing a key ID or disabling authentication in the registry revokes that authorization on the next request. Actual environment-secret changes require a process restart. Local private provisioning is now available through `manage.py provision-router`; it generates a v2 client for an existing identity. The v1 simulator still sets up only its isolated temporary identity.

## 5. Request contract

Send `POST /api/controller/v1/poll` with `Content-Type: application/json`. The raw UTF-8 body must be at most 8192 bytes and contain exactly these fields:

```json
{
  "protocol_version": "1.0",
  "router_id": "SIMULATED-ROUTER",
  "request_id": "36becb7e-17c5-4dd7-8c96-d5c1de359ab4",
  "timestamp": "2026-11-19T10:00:00Z",
  "request_type": "poll"
}
```

This is an illustrative simulated identity and timestamp, not a company record or a reusable request. Each real request needs a newly generated canonical lowercase UUID4 and a current UTC timestamp ending in `Z`. Fractional seconds up to six digits are accepted. Router IDs may contain letters, digits, underscores, and hyphens; they start with a letter or digit and have at most 64 characters.

Duplicate JSON properties, unknown/missing fields, non-finite values, wrong types, query strings, content encodings, and unsupported versions/request types are rejected.

Required authentication headers:

| Header | Value |
| --- | --- |
| `X-SDR-Key-Id` | One active key ID for the registered router. |
| `X-SDR-Signature` | 64 lowercase hexadecimal characters: HMAC-SHA256 described below. |

The canonical signing text is the following five lines, with no trailing newline:

```text
SDR-POLL-V1
POST
/api/controller/v1/poll
<key ID>
<lowercase SHA256 hex digest of the exact body bytes>
```

Compute HMAC-SHA256 over the ASCII canonical text using the UTF-8 secret as the key. Encode the result as lowercase hexadecimal. Use the same exact body bytes for signing and transmission: even a whitespace change alters the digest. Both the request timestamp and request ID are inside that signed body.

The timestamp must not be older than the configured request age or farther in the future than the clock-skew allowance. Accepted router/request-ID pairs remain recorded until their signed timestamps are no longer acceptable. A retry must use a fresh request ID and signature; an accepted request cannot be submitted twice.

## 6. Response contract

A successful authenticated poll returns HTTP `200` and exactly these fields:

```json
{
  "protocol_version": "1.0",
  "router_id": "SIMULATED-ROUTER",
  "request_id": "36becb7e-17c5-4dd7-8c96-d5c1de359ab4",
  "response_id": "97e4d389-e6d1-4d35-88db-ad89d64df02b",
  "status": "authenticated",
  "mode": "dry_run",
  "action": "none",
  "configuration": {},
  "reason": "optimization_unavailable",
  "issued_at": "2026-11-19T10:00:00Z",
  "expires_at": "2026-11-19T10:01:00Z",
  "poll_after_seconds": 60
}
```

The timestamps and IDs above are illustrative. Expiry must be later than issue time and at most 300 seconds after it. Poll delay must be a whole number from 1 to 86400 seconds. The configuration must be empty: interface changes, OSPF costs, arbitrary commands, and executable text are not supported by this contract.

A receiving client must validate the full schema, its own router ID, the request ID it sent, the protocol version, issue/expiry times against a correct clock, the allowed action, and whether a response has already been handled. It must not execute response text as script code. The current Python simulator checks schema, matching identity/request, and expiry, and tests request-replay rejection. Real-device response tracking and signed receipts are implemented separately in v2.

## 7. Persisted state and status meanings

`data/router_communication.json` contains:

- `routers`: last accepted request, successful authentication, response ID, response-issued time, and dry-run mode per router.
- `seen_requests`: accepted router/request-ID pairs and their expiry.
- `rate_limits`: bounded, hashed-source attempt buckets.

Nonce consumption and accepted check-in are one locked, validated atomic JSON update. State and rate limits survive process restart. The state is bounded; exhausted replay capacity fails closed rather than evicting unexpired accepted IDs. Source identity is the address observed by the server; forwarded headers are not trusted. Shared source addresses share a rate budget.

Relevant events are recorded through the activity service. Logs contain safe event/reason codes and registered identities where appropriate; raw request bodies, authentication headers, signatures, and secrets are not logged.

The accepted-request timestamp is not a record of every rejected request. Authentication failures and rate-limit events are separate security activity.

**An authenticated request and a server-issued response do not prove that a device received or applied a configuration.** V1 has no acknowledgment endpoint. V2 adds signed response receipts, which still do not mean that a routing change was applied. API diagnostic state, controller authentication, SNMP readings, and applied configuration are distinct concepts.

## 8. Error results

| HTTP result | Meaning |
| --- | --- |
| `400` | Invalid JSON/contract, query, or encoding. |
| `401` | Generic authentication failure, including unknown/revoked routers, bad credentials/signatures, and expired/future requests. |
| `403` | Protected transport required; non-loopback plain HTTP is rejected. |
| `404` / `405` | Unknown endpoint or unsupported method. |
| `409` | The authenticated request ID was already accepted. |
| `413` / `415` | Oversized body or unsupported content type. |
| `429` | Source request budget exceeded; observe `Retry-After`. |
| `503` | Storage, response validation, or request-capacity failure. |

Clients should wait appropriately, create a fresh request ID/timestamp, and avoid retry loops that exhaust the source budget. Failed authentication or replay does not replace a previous successful check-in.

## 9. Transport, recovery, and remaining work

HMAC authenticates the signed request; it does not encrypt traffic or authenticate the response. Non-local deployment needs verified HTTPS, correct device time, restricted network access, and explicit proxy/TLS handling. Waitress clears untrusted forwarding headers; only a specifically configured local TLS proxy may supply HTTPS/source information. A base URL alone does not implement TLS. Keep the browser administration interface private.

Back up `data/` and `output/` while stopped. Replay/rate-limit state is part of that backup. Restoring stale communication state can re-enable acceptance of recently consumed IDs; perform recovery only while requests are stopped and after the request-validity window has elapsed. No router rollback is needed for this no-action stage because no router configuration is applied.

The repository now includes a native RouterOS 7.21.4 HMAC-SHA512 client, private provisioning, and a source-restricted TLS proxy setup. See the separate [native test evidence](routeros-native-notes.md) and [setup guide](routeros-setup.md). Company network access still requires an assigned approved controller address. Do not disable certificate validation to make a test pass.

The optimizer integration, constrained interface/cost proposals, application acknowledgements, live application, and rollback belong to later approved stages. V2's communication receipt does not implement them. A stored legacy proposal is never delivered by this no-action endpoint.

## 10. Tests

From the project terminal:

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
```

`tests/test_router_auth.py` checks the independent signature vector, strict schema, freshness, identity binding, rotation, and revocation. `tests/test_router_polling.py` checks the endpoint, replay/restart/concurrency behaviour, source limits, safe logging, transport, and device-route isolation. `tests/test_router_registration_pull.py` checks registration without a management IP, metadata preservation, reference changes, and separation from API diagnostics. These tests use temporary storage and require no company credentials or production router access.
