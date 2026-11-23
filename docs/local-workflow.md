# Local monitoring, analysis and optimization

The application runs the complete local workflow:

```text
Signed V2 poll and receipt
  -> authenticated cumulative TX samples
  -> measured Mbps in existing traffic history
  -> moving averages, utilization, shares and estimated costs
  -> constrained dry-run allocation
  -> browser review and read-only JSON
```

Results always have `mode: "dry_run"`, `action: "none"` and
`routing_changes_enabled: false`. Polling/ACK responses stay unchanged.
Keep `SIMULATION_MODE=true` and `LIVE_ROUTING_ENABLED=false`.

## Use the registered MikroTik

Start the browser and device backend in separate project terminals:

```sh
.venv/bin/python serve.py
.venv/bin/python serve_devices.py
```

Open <http://127.0.0.1:8000/routers>. The application reads the existing
operational registry. Runtime demonstrations, example carrier routers and
simulated traffic generators have been removed. New storage starts empty;
existing router records, credentials and communication history are preserved.

The selected device in this workspace is `SDR-CHR-LAB-01`, with outbound
TX monitoring bound to `ether1`. Its existing RouterOS polling and receipt
client remains unchanged. The separate traffic collector requires approved
installation and explicit enablement before actual TX samples can arrive.
No inbound RX counters are requested or accepted.

The browser app listens on loopback port 8000 and the device backend on
loopback port 8001. The existing approved TLS proxy supplies the router-facing
HTTPS origin. Starting a backend does not change that proxy or the router.

Until a collector sends actual measurements, traffic rates and optimization
results remain unavailable. No example prices, capacities or extra routers
are supplied by the runtime application.

## Configure approved real inputs

The normal application retains its existing inventory and monitoring flags.

1. In **Routers**, set the selected outbound interface. Enter confirmed
   interface capacity, carrier marginal price per decimal GB, and currency.
   Prices belong on the path's carrier router. Use the same currency for all
   compared paths; currency conversion is not performed.
2. In **Routing paths**, configure both endpoints, their interfaces and the
   confirmed path capacity. Select the endpoint measuring TX in the intended
   outbound direction. Its path interface must exactly match that router's
   selected outbound interface. One measurement can supply one path only.
3. Confirm participating paths and assign primary, alternate or standby roles.
   Set the utilization ceiling, hold-down time and congestion policy.
   Standby paths receive zero recommended allocation.
4. In **Settings**, choose the objective, averaging window and expected
   sample interval. These settings do not change a collector or its schedule.
5. Explicitly enable desired interfaces in **Traffic monitoring**. Actual
   collector validation/installation and installed proxy changes still
   require the previously established operational approval.
6. Collect a full fresh window, then click **Calculate analysis** or
   **Calculate dry-run recommendation**. Review calculations, allocation and
   costs. **Router output** displays the local JSON snapshot.

Missing settings, incomplete/warming/stale measurements, mismatched
interfaces or mixed currencies produce explicit requirements on the
Optimization page. No default real prices or traffic are invented.

## Calculations and model scope

For each current uninterrupted counter series:

```text
average_mbps = sum(latest N measured TX rates) / N
previous_average_mbps = sum(the N rates ending one sample earlier) / N
change_percent = (average - previous_average) / previous_average * 100
utilization_percent = average_mbps / capacity_mbps * 100
traffic_share_percent = average_mbps / aggregation_group_demand_mbps * 100
estimated_cost_per_hour = average_mbps * 0.45 * price_per_decimal_GB
```

A full window is required. The previous average needs one additional
reading. A zero previous average has no percentage change. Measured zero
traffic is valid and can produce a zero-demand recommendation.

Costs use `1 GB = 1,000,000,000 octets` and project the average over 3600
seconds. Window volume is integrated separately using actual sample
intervals. Contract commitments, flat-rate bandwidth pricing, billing tiers,
taxes and traffic predictions require a different confirmed business model
before real financial decisions rely on them.

Every baseline/reset/gap or monitoring enablement cycle receives a distinct
counter-series ID. Different series are never mixed into the same average.
Legacy history and pending writes remain readable. History without a
provable current series cannot seed an optimization window after upgrading;
collect fresh readings first.

Within each aggregation router, demand is the sum of averages from its
explicit path measurement sources. Demand stays inside that group. Effective
path capacity is the minimum of confirmed path capacity and configured
measured/carrier interface capacities, multiplied by the utilization ceiling.

- **Minimize estimated financial cost:** fill lower-priced eligible paths
  first up to effective capacity. Equal prices use a deterministic order
  preferring the path already carrying more traffic.
- **Balance utilization:** distribute demand in proportion to eligible
  effective capacities.

This is a parallel-path allocation model. Shared physical bottlenecks,
per-flow hashing, end-to-end reachability and OSPF cost/weight mapping are
outside it. Review recommendations against the actual network before
designing a routing implementation.

Demand exceeding effective capacity produces **infeasible**, with no partial
recommendation or discarded demand. Hold-down withholds a new recommendation
until the configured interval after the previous ready calculation elapses.
Changing policy starts a new policy context.

## Persistence, freshness and security

Calculation uses consistent current router/settings/counter snapshots and
history windows under the existing thread/process storage lock. Memory is
bounded to one segment plus the required per-router windows.

| Existing document | Contents |
| --- | --- |
| `traffic_history.json` / segments | Measured TX rates and counter-series IDs. |
| `averages.json` | Calculation projections linked by evaluation ID. |
| `routing_costs.json` | Compared path cost/allocation projections. |
| `optimization_results.json` | Authoritative committed calculation snapshots. |

Projections are written before the committed result. Readers use committed
snapshots, so interrupted publication cannot present orphan projections as
a successful recommendation. Identical retries replace their projections
and publish once. Existing legacy records are preserved. New records have
strict field/numerical validation and ready allocations must conserve group
demand and respect capacity/standby constraints.

GETs never collect traffic or write JSON. Fresh samples, revoked
authorization, changed prices/interfaces/settings or aged measurements mark
an earlier result as historical. Recalculate for a current view. Fingerprints
bind results to input state.

Browser actions retain administrator policy and CSRF checks.
`GET /api/workflow` returns the committed public result and `is_current`
under browser authentication. Device endpoints do not expose these actions.
Raw HMAC headers, secrets and unknown registry fields never enter results.
Live routing, automation and command delivery remain disabled.

## Validation

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
```

Tests use temporary data and synthetic keys. They cover an independent
small-integer cost oracle, demand conservation, capacity/standby constraints,
independent aggregation groups, missing/stale inputs, series resets, zero
traffic, currencies, hold-down, concurrent calculations, interrupted commit
and retry, restart persistence, browser auth/CSRF and preservation of registered routers.
