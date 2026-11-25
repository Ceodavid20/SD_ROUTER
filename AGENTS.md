# SD_ROUTER architecture boundary

User-mandated architecture: **Flask makes decisions; MikroTik fetches and executes them.**

Current monitoring preference: second-by-second TX and jitter. The user cancelled
the proposed one-minute change; preserve the active one-second cadence unless
the user explicitly requests a different interval later.

- Controller-to-router access is strictly read-only monitoring. Do not implement
  Flask API/SSH/SNMP writes, configuration pushes, routing actuators or remote
  execution of optimization commands.
- Flask monitors TX and authorized timing probes, detects congestion, computes
  routing costs and traffic distributions, and publishes declarative JSON.
  Algorithms must not return executable RouterOS code or command strings.
- Routers initiate authenticated pulls and validate controller trust, identity,
  scope, timestamps/expiry, version/replay rules and permitted value ranges.
  Only separately authorized, preinstalled router-side logic applies changes.
- The current advisory client fetches/validates and reports `not_applied`.
  Router-side application/rollback is unfinished. Do not describe recommendations
  or receipt acknowledgements as applied changes or verified traffic relief.
- Keep `SIMULATION_MODE=true` and `LIVE_ROUTING_ENABLED=false` unless a later
  explicit user instruction changes the approved stage. Do not enable execution
  while implementing monitoring, graph or advisory changes.
- Keep router identities, addresses, interfaces, capacities, carrier labels and
  protocol mappings configurable. Support CHR and physical routers through
  capability discovery and validation; do not assume hardware has been tested.
- Preserve existing V1/V2 polling, ACK, HMAC-SHA512, TLS, strict JSON validation,
  timestamp/rate/replay controls, storage and history. Never collect RX counters
  or print credentials/secrets.
- Private operator tools and explicitly approved lab setup are separate from the
  Flask runtime. Never repurpose their management access for an optimization
  push path. Live router configuration changes require explicit authorization
  through a separate operator/bootstrap workflow; that approval never implies
  permission to add a Flask optimization push path.

## VDT Plain Rev3 baseline

- Follow docs/vdt-rev3-implementation-spec.txt and the planning-only register
  docs/vdt-rev3-decisions.json. User confirmed OSPF interface/template cost;
  production measurement remains undecided. Do not treat unresolved mathematical
  definitions, outage choices or lab values as production approvals. MySQL is
  user-confirmed; the local sdr instance is MariaDB 10.4.28 (XAMPP).
- Production must not store RouterOS login passwords or log in to routers.
  Existing API-SSL lab monitoring remains intact until its approved password-free
  replacement is implemented. Read-only lab access is not production compliance.
- Production scheduled decisions (5/10/15 minutes) and router cost pulls (about
  60 seconds) are independent of the current one-second lab chart/sampling.
- Keep calculated, released and router-reported applied costs distinct. Test
  publishes normal costs; Manual requires exact proposal approval; Automatic
  requires staged authorization. Receipt ACKs are not application evidence.
- rev3-readiness is an assessment only. It must not initialize/migrate storage,
  contact routers, disclose secrets, change settings or authorize execution.
- Stage 2 database operations are explicit operator CLI actions, separate from
  Flask/workers. Keep the running JSON backend and every replay ledger intact.
  The MySQL/MariaDB import is an inactive compatibility archive, not business
  records or a cutover. Never silently activate it or reset deduplication state.
  Follow docs/vdt-rev3-database.txt; migration/restore destinations must be new,
  private and separate from active storage. Never print private SQL payloads.
