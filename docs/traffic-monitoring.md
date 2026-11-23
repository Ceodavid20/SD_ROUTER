# Outbound traffic monitoring

The device app accepts a separate authenticated
`POST /api/controller/v2/traffic`. The browser app displays status and
history at `/monitoring`. V1 polling, V2 polling and V2 receipt contracts
remain unchanged. Traffic requests never issue or acknowledge routing
instructions and never update polling check-in or receipt metadata.

Monitoring is disabled for new routers. Existing operator settings are
preserved. The Flask applications do not contact routers during startup,
page rendering, ingestion or tests. Those operations install no scheduler
and do not change router configurations or the installed TLS proxy.
An operator-authorized installation is recorded below.
Keep `SIMULATION_MODE=true` and `LIVE_ROUTING_ENABLED=false` during development.

## Components

| Component | Responsibility |
| --- | --- |
| `controllers/traffic_controller.py` | Dedicated device HTTP boundary. |
| `services/traffic_protocol.py` | Strict TX-only JSON request validation. |
| `services/routeros_poll_service.py` | Reused V2 credential and timestamp verifier. |
| `services/traffic_service.py` | Interface authorization, counter calculation, replay handling and status projection. |
| `services/traffic_state.py` | Strict persistent baseline, replay, rate-limit and pending-write validation. |
| `services/json_storage.py` | Locked JSON state and recoverable append to existing segmented history. |
| `controllers/monitoring_controller.py` | Explicit browser enable/disable with existing administrator/CSRF protection. |
| `services/traffic_setup_service.py` | Optional private disabled client preparation using an existing key. |
| `scripts/routeros/controller_traffic_v2.rsc` | Separate disabled single-interface TX collector template. |

The device blueprint is registered only in `device_app.py`. The existing
transport guard applies: verified HTTPS for network requests, or the
existing loopback-only simulation exception. Testing mode does not bypass
authentication. Untrusted forwarded headers do not establish HTTPS.

## Exact request contract

Send `Content-Type: application/json`, no query parameters or
`Content-Encoding`, and at most 8192 UTF-8 bytes. The JSON object has exactly:

| Field | Type/value |
| --- | --- |
| `protocol_version` | String `"2.0"`. |
| `router_id` | Exact authorized registered router ID. |
| `request_id` | Fresh canonical lowercase UUID4 for each sample. |
| `timestamp` | Positive integer UTC Unix seconds when the counter was sampled. |
| `request_type` | String `"traffic"`. |
| `interface` | Exact configured `interface_name`, 1–128 characters, trimmed, without control characters. |
| `tx_octets` | Cumulative unsigned integer counter, `0 <= value < 2**64`. |

The timestamp is both the sample time and the signed freshness timestamp;
do not retimestamp an old sample as if it were current. Strings, floats
and booleans cannot substitute for integer timestamps or counters.
Duplicate, missing and extra properties, nested metrics, non-finite
numbers and invalid UTF-8 are rejected. RX fields and client-calculated
rates are not accepted. This endpoint does not enumerate interfaces.

Use existing per-router `X-SDR-Key-Id` and `X-SDR-Signature` headers. The
signature is standard HMAC-SHA512, encoded as 128 lowercase hex characters,
over these five ASCII lines, with literal newlines and no trailing newline:

```text
SDR-POLL-V2
POST
/api/controller/v2/traffic
KEY_ID
LOWERCASE_SHA512_HEX_OF_EXACT_RAW_BODY
```

The shared secret is used as UTF-8 text, including when provisioning
represents it as hexadecimal characters; it is not hex-decoded. The
method, path, key ID and exact body bytes are bound to the signature.
Poll and ACK signatures do not authenticate traffic requests.

The V2 verifier checks the current registry authorization, active key IDs,
environment-referenced secret and signature using constant-time comparison.
It applies `ROUTER_REQUEST_MAX_AGE_SECONDS` (default 120) and
`ROUTER_CLOCK_SKEW_SECONDS` (default 30). Unknown/revoked keys, unknown or
disabled identities and freshness failures return generic `401` errors.
The registry authorization, interface and monitoring generation are
rechecked under the commit lock before accepting a sample.

## Measurement and reply

For consecutive samples on the same enabled router/interface:

```text
tx_mbps = (new_tx_octets - previous_tx_octets) * 8 / elapsed_seconds / 1_000_000
```

For example, an increase of 15,625,000 octets over 10 seconds measures
12.5 Mbps. Equal counters with increasing timestamps measure actual zero.
Counter values remain integers until after subtraction.

The first sample establishes a baseline. A decreasing counter, including
an observed wrap, establishes a new baseline without a rate. A gap longer
than `max(180, 3 * monitoring_interval_seconds)` also establishes a new
baseline. Interface changes or an explicit disable/re-enable start a new
series. Repeating enable while already enabled does not reset a series.
Samples at or before the preceding sample timestamp return `409` and do
not replace the baseline or consume a nonce.

Each successful response contains exactly:

```json
{
  "protocol_version": "2.0",
  "router_id": "EXAMPLE-R1",
  "request_id": "36becb7e-17c5-4dd7-8c96-d5c1de359ab4",
  "status": "traffic_recorded",
  "sample_state": "measured",
  "tx_mbps": 12.5,
  "mode": "dry_run",
  "action": "none",
  "configuration": {}
}
```

`sample_state` is `baseline`, `measured`, `counter_reset` or `gap_reset`.
`tx_mbps` is `null` for all baseline states. These states do not create
fabricated zero readings in history. Traffic replies need no poll ACK.
Only real measured deltas are appended to existing `traffic_history.json`
segments, with their TX counter, interval, interface, router and request ID.

Cumulative counters alone cannot identify a reset that overtakes the old
counter before the next sample. Select an interval appropriate to the
link and verify the chosen interface's accounting on the target device.
The collector reads the documented `tx-byte` property only. See the
[MikroTik interface reference](https://manual.mikrotik.com/docs/cli-reference/interface/)
for counter semantics and hardware-offload accounting limits. Native
validation on RouterOS 7.25.1 is recorded below. Other releases still
require their own native validation.

## Persistent security and interrupted writes

`router_traffic_v2.json` contains baselines, accepted-request replay IDs,
separate source rate-limit buckets and at most one pending history append.
The configured attempt/window limits are the same as polling, but the
traffic budget is separate so a traffic retry loop cannot consume poll/ACK
quota. Malformed, oversized and rejected POST attempts count before JSON
parsing or authentication. Routers behind a source NAT share that source's
traffic budget. Source identities are stored as hashes.

Replay IDs are retained through the inclusive signed timestamp expiry,
including permitted future skew. Live replay entries are bounded at
10,000; source buckets at 1024. Full capacity fails closed instead of
evicting live protection. Replay and limits survive application restart.

One process/thread lock covers current registry checks, nonce consumption,
counter state and history placement. A pending append records its exact
segment, byte offset and expected reading in the atomic state update.
History flushing compares existing bytes with the expected line, completes
an absent/partial write and clears the pending record. A fully appended
line is not appended again. Startup and subsequent traffic/history writers
finish pending writes before proceeding. Conflicting unrelated bytes fail
closed and require repair; they are not discarded.

A `503` during disk failure can mean a sample was committed with its
history write pending. Once storage is restored, restarting or retrying
finishes that write; replaying the original accepted request then returns
`409`. Never change request IDs simply to force acceptance of old samples.
Stop the controller before backup recovery. Back up all data documents and
segments together, including `router_traffic_v2.json`. Do not delete replay
state to clear an error or restore it separately from traffic history.

## Explicit enablement and optional client preparation

1. Save exactly one outbound interface in the router inventory. Provision
   controller authentication using the existing approved private workflow.
2. Open **Traffic monitoring** and explicitly enable that router when ready.
   This saves a local registry setting only. Existing authentication mode
   applies; CSRF is required even while browser login is paused for local work.
3. Obtain approval before any target-router command, collector installation,
   scheduler change or installed proxy change. These operations are separate
   from normal Flask requests and startup.

An optional local preparation command reuses an existing active generated
key and creates a new private bundle. It neither rotates credentials nor
enables monitoring. Replace the example values before using it locally:

```sh
.venv/bin/python manage.py prepare-traffic-client \
  --router-id APPROVED_ROUTER_ID \
  --key-id EXISTING_ACTIVE_KEY_ID \
  --controller-url https://APPROVED_CONTROLLER_ORIGIN \
  --output-dir private/traffic-client
```

The generated `controller-traffic.rsc` contains a key and must never be
printed, pasted into chat, published or imported verbosely. Its own
`sdrTrafficEnabled` flag defaults to `false`, so it reads no counters and
makes no requests until an administrator explicitly enables it after
approval. It performs one sample/POST per approved execution, reads only
the selected interface's `tx-byte`, requires certificate-checked HTTPS and
disables redirects. It does not create a script entry or scheduler, change
an interface, reset counters or call the poll/ACK endpoints. Review the
new script on the actual target release before deployment; Python tests
do not establish RouterOS execution or interoperability.

The TLS configuration generator includes the new path for future bundles.
An already installed proxy may deny it until an approved administrator
   adds **only** `/api/controller/v2/traffic` under the existing source and
body-size restrictions. Do not regenerate private TLS material or restart
the live proxy just to bypass that review.

## Frontend and errors

The monitoring page shows each router's configured interface, enablement,
current state, last sample time and current TX rate, plus the latest 100
historical measurements. A stale or disabled rate is unavailable. The
dashboard shows a network total only when every enabled router has a
current measured rate; the count of reporting routers stays visible.
Historical readings survive disablement. GET requests do not collect data
or change state. The monitoring page refreshes every 15 seconds. Small
nonzero rates retain visible precision in both the current reading and
history; a measured zero remains zero. Monitoring tables show Kbps, and
the dashboard uses Kbps below 1 Mbps. One Mbps equals 1,000 Kbps. Stored
measurements and JSON API fields continue to use Mbps.

| Status | Meaning |
| --- | --- |
| `200` | Counter accepted; inspect `sample_state`. |
| `400` | Invalid JSON/schema, query or encoding. |
| `401` | Generic authentication or signed freshness failure. |
| `403` | Transport policy, disabled monitoring, invalid configuration or wrong interface. |
| `409` | Accepted nonce replay, non-increasing sample time or concurrent authorization change. |
| `413` | Body exceeds 8192 bytes. |
| `415` | Content type is not `application/json`. |
| `429` | Traffic source budget exhausted; includes `Retry-After`. |
| `503` | Storage or bounded replay capacity unavailable. |

Errors and activity logs do not include raw bodies, signatures or secrets.
The backend tests use temporary storage, synthetic keys and forbidden
outbound network connections. They exercise HMAC path/body binding, strict
schemas, timestamp boundaries, independent rate limits, key revocation,
replay after restart, concurrency, interrupted append recovery, TX math,
counter resets, interface/enablement changes and browser auth/CSRF behavior.

## Approved native commissioning on November 23, 2026

The existing `SDR-CHR-LAB-01` router, running RouterOS **7.25.1**, was
commissioned after operator authorization. Its collector reads only the
cumulative `tx-byte` counter on **ether1** and posts signed samples to
`https://192.168.56.1:18443/api/controller/v2/traffic`.

- Native import dry-run reported no syntax errors before installation.
- The `sdr-controller-traffic` script and scheduler use only `read,test`
  permissions. The scheduler invokes the script with
  `use-script-permissions` every 60 seconds.
- Real RouterOS Fetch requests passed certificate verification and the
  controller's HMAC, timestamp, interface and opt-in checks. Native
  execution was verified independently from Python test results.
- The first sample established a baseline. Subsequent scheduler samples
  produced measured Mbps, persisted history and a frontend `receiving`
  status. A monitoring disable/re-enable correctly began a new series.
- The existing HTTPS proxy was reused without edits or restarts. Its
  original `SDR Controller CA 996AFD18` trust remained in place, and the
  working API-SSL certificate set was preserved.
- Poll/ACK clients, interface configuration, OSPF, routing, firewall and
  counter values were not changed or reset. No RX counter was read.
  `SIMULATION_MODE=true` and `LIVE_ROUTING_ENABLED=false` remain set.

The native collector and its rendered source contain an authentication
key. Keep that source private; do not export it verbosely or commit it.
The Flask applications continue to require a separate, explicitly enabled
collector for any additional router. No routers or example traffic were
added during commissioning.
