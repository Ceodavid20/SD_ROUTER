# Lagos–Abuja SDR Controller

The controller stores router and operational settings in JSON files. Its intended optimization scope is outbound traffic on the MTN and Glo Lagos–Abuja trunks. Aggregation handoffs and operating limits are entered by the operator.

The controller implements authenticated polling and receipts, opt-in outbound TX monitoring, moving-average inputs and advisory adaptive traffic allocation. The native RouterOS 7.21.4 polling client uses verified HTTPS and protocol v2. Polling still returns a versioned **no-action** JSON response. A separate traffic endpoint calculates Mbps from cumulative TX counters on explicitly authorized outbound interfaces. Live routing changes remain disabled.

## Start the application

Use Python 3.12–3.15. From the project folder in the VS Code terminal:

```sh
source .venv/bin/activate
python serve.py
```

Open <http://127.0.0.1:8000/>. Sign-in is paused for local development. Router forms retain CSRF validation. The server binds to localhost. Press **Ctrl+C** in its terminal to stop it.

To create the virtual environment and install dependencies for a new checkout:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
cp -n .env.example .env
python serve.py
```

Administrator sign-in can be re-enabled later by running `python manage.py configure-admin`, setting `SDR_AUTH_ENABLED=true` in the local `.env`, and restarting.

## Router-to-controller communication

The application uses registered MikroTik routers and their authenticated RouterOS clients. Runtime simulators and the demo server have been removed. Automated tests keep their fixtures in temporary storage.

To start the separate device listener in another project terminal:

```sh
.venv/bin/python serve_devices.py
```

It defaults to `127.0.0.1:8001`. The browser application remains on `127.0.0.1:8000`. The device application exposes polling, receipt, traffic and opt-in enrollment routes. Its backend binds to loopback. An approved device-only TLS proxy provides the router-facing HTTPS address, with source restrictions and explicit local proxy trust. Use the approved origin already configured in the private environment file.

`CONTROLLER_HOST`, `CONTROLLER_PORT`, `CONTROLLER_BASE_URL`, and the polling settings are environment configuration. The sketch's address and port are not applied. Keep `SIMULATION_MODE=true` and `LIVE_ROUTING_ENABLED=false` during development. Setting live routing to true raises a startup error because this stage has no live execution capability.

Follow [RouterOS connection setup](docs/routeros-setup.md) for private provisioning, verified HTTPS, and the first router exchange. The [v2 contract](docs/routeros-v2-protocol.md) documents the native protocol; [Router polling v1](docs/router-pull.md) retains the Python compatibility contract. [Native test notes](docs/routeros-native-notes.md) separate real RouterOS results from Python tests.

## Monitoring and recommendations

The main application supports authenticated TX collection, moving averages, utilization/share calculations, estimated volume costs and constrained advisory allocations. It uses only saved router inventory and actual received readings. Missing measurements or settings remain unavailable.

Enter confirmed WAN capacities, explicitly select each path's TX measurement source, configure limits and choose an objective. Cost minimization also needs confirmed carrier prices in a shared currency; utilization balancing does not require prices. Then calculate from a full fresh window. [Workflow documentation](docs/local-workflow.md) explains formulas, assumptions, setup and persistence.

## Zero-touch provisioning

After initial connectivity and a trusted bootstrap delivery, routers can enroll
and start authenticated TX monitoring without per-router code changes, WinBox
steps, API diagnostic clicks or controller restarts. Identities, interfaces,
carrier labels, intervals and optional fixed-source restrictions are policy
data. Router IDs can be assigned automatically.

Enable `SDR_ENROLLMENT_ENABLED=true` once on the controller, set the approved
HTTPS `CONTROLLER_BASE_URL`, and restart the device backend. Authorize one
device with a short-lived, single-use bootstrap bundle:

```sh
.venv/bin/python manage.py create-enrollment-token \
  --interface APPROVED_OUTBOUND_INTERFACE \
  --ca-file /approved/controller-ca.pem \
  --enable-monitoring \
  --output-dir private/new-router-bootstrap
```

The command prints paths and expiry, never the token. Deliver its private
`bootstrap.rsc` and public CA through a trusted initial setup process, such
as the existing authenticated management channel or a controlled Netinstall
workflow. Initial network connectivity, a valid clock and installation
privileges are prerequisites. A completely unconfigured device cannot
securely acquire trust from an unknown server by itself.

The bootstrap verifies the controller's TLS certificate, consumes its token
at `POST /api/controller/v2/enroll`, receives a distinct HMAC identity, and
installs a TX-only collector and retrying scheduler with `read,test`
permissions. Routing is never configured or executed. Monitoring is disabled
unless the authorization explicitly uses `--enable-monitoring`. Incoming
API-SSL access is optional for push monitoring; normal collection needs no
interactive API login.

Use `--router-id`, `--name`, `--carrier`, `--management-ip`,
`--management-interface`, `--interval-seconds` and `--chr-lab` for optional
inventory policy. `--bind-source` is opt-in for fixed sources; it is omitted
for NAT or dynamic addresses. `--replace-existing` explicitly authorizes
re-enrollment of an existing active identity. `revoke-enrollment-token`
revokes an unused authorization. No bootstrap token or device secret belongs
in command arguments, source control, logs or public inventory JSON.

The enrollment endpoint requires verified HTTPS even in simulation mode,
strict JSON, fresh timestamps, independent persistent rate limits, expiry
and atomic single-use consumption. Token hashes are stored in
`router_enrollment.json`; HMAC secrets use owner-only environment storage
and load on demand. A small journal recovers interrupted registry commits
without making a used token valid again. If the initial response is lost
after a successful claim, authorize a fresh trusted bootstrap rather than
reusing the consumed token. Backup and restore the enrollment ledger,
registry and private environment at the same stopped restore point.

Future TLS configurations can expose the enrollment path explicitly with
`setup-controller-tls --allow-enrollment`. Existing proxies need their own
approved route configuration. The browser application never exposes the
enrollment endpoint.

## Current focus

Existing registered routers are preserved. New storage starts with an empty inventory: startup creates no example carrier or aggregation routers. This workspace monitors the original `SDR-CHR-LAB-01` plus the separately enrolled `SDR-MTN-01` and `SDR-GLO-01`, each using `ether1` (TX only). MTN and Glo represent virtual carrier links, but their measurements come from actual CHR counters. The operator confirmed MTN at 8 Gbps, Glo at 4 Gbps, and their ability to carry the same outbound traffic. These limits, names and interfaces are inventory settings, not runtime defaults. Fresh complete TX windows are required for recommendations.

In **Routers**, check **Confirmed WAN capacity** only after establishing the real WAN limit. Unconfirmed entries remain editable and do not drive utilization or recommendations, even if a routing path already has an entered limit. A virtual Ethernet adapter's link speed does not establish WAN capacity.

The **Add router** button opens **Router connection** at `/routers/connect`. It shows the configured device polling endpoint, request method, authentication requirements, and setup status. Manual browser registration and the old `POST /routers/add` route are removed. Opening this page does not register or authenticate a device.

Authorized identities are provisioned outside the browser. A registry record does not require a management IP or successful RouterOS API diagnostic. Existing records remain editable. Controller polling has its own authentication reference, enablement, and active key IDs; editing a reference cannot provision secrets or enable authentication. API diagnostic credentials and SNMP credentials remain separate references.

The optional RouterOS API diagnostic requires a management IP, API port, TLS/network settings, and its API credential reference. It logs in and reads basic resources only. Its failure does not prevent a valid router from authenticating to the device polling endpoint.

For the existing MikroTik, run `.venv/bin/python manage.py configure-router-api --router-id SDR-CHR-LAB-01` in the project terminal to save its API login. Both username and password prompts are hidden. The command writes an owner-only `.env`, generates and saves the credential reference automatically, and does not contact or configure the router. Refresh **Routers** afterward; managed API credentials reload without a server restart. Saving router settings preserves the managed reference, including when the form was opened before credential setup or rotation. Use the same terminal command to change that login. No credentials are accepted as command-line arguments or returned in HTML/JSON/logs. The API port and API-SSL checkbox must match **WinBox → IP → Services**; selecting the checkbox does not enable TLS on RouterOS. The page lists missing local requirements together before enabling the optional diagnostic button.

Open **Routing paths** to create the links used by your network. Select the aggregation router and carrier router from the inventory, then enter their interfaces, the confirmed path capacity and any applicable limits. For carrier-side dry-run analysis, an unknown aggregation interface can remain blank; it must be established before any future routing deployment. Carrier labels come from the configured inventory. Paths can be edited or removed. No connections or congestion thresholds are assumed at startup.

**Optimization** displays the current allocation automatically, with the same read-only result at `GET /api/optimization`. Saved snapshots remain separate and optional. Signed fresh TX measurements establish readiness independently of optional API diagnostics. This workspace uses Adaptive MLU with a configurable 80% soft operating target and a 120-second hold-down. No financial price is invented and no routing change is executed.

The supplied network PDF is a reference for entering these settings. The application does not embed a topology image or derive executable router changes from the drawing. Saving routers or paths changes local settings only; it does not contact a device or alter its configuration.

Outbound monitoring accepts cumulative TX counters through the separate authenticated `POST /api/controller/v2/traffic` endpoint. Configure one outbound interface per router and explicitly enable it on **Traffic monitoring**. New routers remain disabled. The frontend displays current TX rates and existing measured history; first samples, resets and stale data are not shown as fabricated zero traffic. RX is never collected. See [traffic monitoring](docs/traffic-monitoring.md) for authentication, calculation, recovery and an optional disabled collector template. No SNMP collector or router-side installation is run by the application. Adaptive MLU calculates congestion-aware routing costs separately from observed OSPF metrics and connection weights. See the adaptive guide below for the approved main-side interface requirements.

Passwords, controller authentication secrets, and SNMP keys do not belong in registry JSON or HTML forms. Use separate environment references. `python manage.py provision-router --help` describes local private client provisioning for an existing identity. It generates a new key, writes a private RouterOS bundle, and preserves existing settings under a file lock. It never contacts or installs anything on a router.

Plaintext API connections are blocked by default. API port 8728 is unencrypted; do not enable it unless the network team approves the protected management path. Prefer certificate-verified API-SSL.

TX measurement, moving averages, utilization/share calculations, estimated volume costs and constrained local allocation are implemented. Recommendations are advisory dry-run snapshots. Executable routing command generation, authorized application and rollback remain disabled. The separate optimization-result endpoint records rejected/failed/not-applied reports; an applied claim is refused without execution authorization. Protocol v2 ACKs record response receipts only. Real calculations require confirmed operator settings and fresh readings. The application does not generate traffic, prices or recommendations from demonstration data. Polling stays no-action even when a local recommendation exists. The new documented allocation model does not replace an existing optimization engine.

New storage starts in simulation mode. Existing saved automation modes are preserved rather than changed at startup. Regardless of a legacy mode label, routing changes and automation remain off. Device `SIMULATION_MODE` controls the existing loopback HTTP transport allowance; it does not create simulated routers, generate traffic or enable routing execution.

## JSON storage

No database is used. The JSON storage service validates documents, locks concurrent access, writes files atomically, and keeps prior versions as `.json.bak`.

```text
data/
├── routers.json
├── routing_paths.json
├── router_communication.json
├── router_communication_v2.json
├── router_traffic_v2.json
├── router_enrollment.json
├── traffic_history.json
├── traffic_segments/
├── averages.json
├── optimization_results.json
├── routing_costs.json
├── automation_settings.json
└── activity_logs.json
output/
└── router_config.json
```

Traffic readings use append-only dated JSON Lines segments that roll over at 8 MiB; the controller does not rewrite the growing traffic history each cycle. Other JSON documents have a 16 MiB size limit.

`router_communication.json` stores v1 check-ins/replay records and the shared source rate-limit buckets. `router_communication_v2.json` stores native v2 check-ins, replay records, issued response references and received-response metadata. Accepted request IDs are consumed atomically with the check-in update. Do not delete or restore these documents casually while polling is active, because they contain replay history.

`router_traffic_v2.json` holds TX baselines, traffic replay records, a separate source rate-limit budget, and a recoverable pending history append. It reuses the existing segmented traffic history. Include this state and all traffic segments in a consistent stopped backup. Preparing a disabled traffic client uses an existing active key without changing polling scripts or credentials; the new client still requires approved target-device validation and installation. The installed proxy configuration is not changed automatically.

Use persistent local disk, not a shared network filesystem. Stop the controller before restoring a backup or repairing a partially written traffic record. Back up `data/` and `output/` together while stopped; keep `.env` separate as a secret.

## Tests

```sh
python -m pytest -q
python -m pip check
```

Tests use temporary JSON storage and mocked router requests. They do not need company credentials or contact real routers.

Router authentication and polling tests cover signatures, per-router authorization, expiry, replay after restart, concurrent duplicate requests, source rate limits, JSON validation, isolated device routes, transport restrictions, no-action responses and signed receipts. Traffic tests add TX math, counter resets, interface enforcement, opt-in/CSRF, independent quotas and interrupted history recovery. Setup tests exercise credential rotation/revocation, concurrent secret-file updates, real certificate generation and strict TLS verification. See [native validation notes](docs/routeros-native-notes.md) for checks executed on RouterOS 7.21.4 itself; those results apply to the existing polling client, not the new disabled traffic collector. Company network reachability must be verified separately after an address is assigned.

### Adaptive MLU optimization

Optimization now supports capacity-weighted min-max utilization, bounded feedback,
congestion-aware **routing** costs, and a live TX graph with click-to-inspect readings. The separate
Traffic analysis page has been retired. Select **Adaptive MLU** in Settings and run
`.venv/bin/python serve_optimizer.py` alongside the existing browser/device servers
for automatic advisory calculations. Routing execution remains disabled.

Each carrier path requires a distinct, authorized **main-router outbound TX interface**.
Carrier-side TX is health telemetry and cannot substitute for main-to-carrier demand.
The approved lab VLAN handoffs now provide separate main-router TX channels
(`sdr-to-mtn` and `sdr-to-glo`); each must have a full fresh measurement window. The single TX graph updates in the background; selections remain pinned.
Optimization shows advisory targets in a compact table and recorded actions in
Recent changes.

See [the implementation and operating guide](docs/adaptive-optimization.txt) for the
math, defaults, authenticated pull/result contracts, startup commands, and remaining
router-side work. A disabled, read/report-only advisory client can be prepared with
`manage.py prepare-optimization-client`; no installation or routing changes are made.

Use the **Optimization On/Off** switch to pause or resume advisory calculations.
Off keeps TX monitoring and the graph running, blocks new recommendation delivery,
and persists across restarts. Routing execution remains disabled in both states.
