# Connect RouterOS to the controller

Target release: **RouterOS 7.21.4**. The client initiates an HTTPS
connection to Flask, authenticates its request, validates the JSON reply,
and acknowledges receipt. It does not use the router's API, SSH or Telnet
port and does not send its management username or password to the website.

The current reply contains `action: "none"` and `configuration: {}`.
Traffic collection and optimization are separate implementation stages.
A successful connection does not mean that congestion control is running.

## 1. Assign the controller address

The company has **not assigned a router-reachable controller address**.
The local website at `127.0.0.1:8000` is for the operator; it cannot serve
as the physical router's remote controller address.

The network team needs to provide:

- An approved controller server IP or DNS name and HTTPS port.
- A route from the router's management network to that address.
- The router's source IP as seen by the controller, including any NAT.
- A server certificate trusted by the router, matching that IP or name.

The connection direction is:

```text
RouterOS Fetch
  -> approved HTTPS address /api/controller/v2/poll
  -> device-only TLS proxy
  -> Waitress/Flask on 127.0.0.1:8001
  <- validated no-action JSON
  -> signed POST /api/controller/v2/ack
```

Keep the browser application on `127.0.0.1:8000`. Only the device
endpoints belong on the approved router-facing address. No inbound API
port needs to be opened on RouterOS for this direction of communication.

## 2. Prepare verified HTTPS

Use the company's existing certificate and reverse proxy when available.
The proxy must restrict source addresses, expose only the device paths,
strip client-supplied forwarding headers, and forward the original source
and HTTPS scheme to the loopback backend. Do not trust arbitrary proxies.

For this Mac's existing Apache/OpenSSL installation, the project can
generate a private CA, a 90-day server certificate, and an isolated
Apache configuration. It does not install a service, change the system
Apache configuration, open a firewall, or start a listener.

After replacing the capitalized placeholders with approved values:

```sh
.venv/bin/python manage.py setup-controller-tls \
  --hostname APPROVED_CONTROLLER_HOSTNAME \
  --listen-address APPROVED_SERVER_INTERFACE_IP \
  --port 18443 \
  --backend-port 8001 \
  --allow-source APPROVED_ROUTER_SOURCE_IP \
  --output-dir private/controller-tls
```

The generated configuration uses TLS 1.2, the version exercised with this
Mac's Apache build and RouterOS. Ports here are examples; select an
approved unused port. The helper permits nonprivileged ports only. Repeat
`--allow-source` for more approved addresses or subnets. It refuses an
all-addresses `/0` network and refuses to overwrite an existing bundle.
It is a Mac helper, not an untested Linux deployment installer.

Set the following in the controller's private `.env`, using the actual
approved origin. Do not put an endpoint path in `CONTROLLER_BASE_URL`.

```dotenv
CONTROLLER_HOST=127.0.0.1
CONTROLLER_PORT=8001
CONTROLLER_BASE_URL=https://APPROVED_CONTROLLER_HOSTNAME:18443
CONTROLLER_TRUSTED_PROXY=127.0.0.1
SIMULATION_MODE=false
LIVE_ROUTING_ENABLED=false
```

Only set `CONTROLLER_TRUSTED_PROXY` when that exact local TLS proxy is in
place. Waitress accepts one explicit loopback proxy, never a wildcard.
It clears untrusted forwarding headers. Its own HTTP listener stays on
loopback. Non-local plaintext requests are rejected by the device app.

Start the device backend in one terminal:

```sh
.venv/bin/python serve_devices.py
```

For the generated Mac configuration, an administrator can start its
separate TLS proxy in another terminal, after approving the interface
and source restrictions:

```sh
/usr/sbin/httpd -DFOREGROUND -f "$PWD/private/controller-tls/httpd.conf"
```

Stop it with Ctrl+C. Do not run the TLS proxy as root for this
nonprivileged-port setup. On a company server, use its service manager
and approved equivalent proxy configuration. Certificate issuance,
renewal before expiry, and source restrictions remain operational tasks.

## 3. Provision a router privately

Choose the exact existing identity from the inventory. The website does
not create identities or collect a router management password.

Replace `APPROVED_ROUTER_ID` and the origin before running:

```sh
.venv/bin/python manage.py provision-router \
  --router-id APPROVED_ROUTER_ID \
  --controller-url https://APPROVED_CONTROLLER_HOSTNAME:18443 \
  --ca-file private/controller-tls/ca.pem \
  --output-dir private/router-client
```

Omit `--ca-file` only when the router already trusts the controller's
issuer, for example through an approved company CA. The command:

- Creates a new random secret for this router/key only.
- Writes that secret to a locked, atomically replaced, private `.env`.
- Enables that key for the existing identity in `routers.json`.
- Writes a private `controller-poll.rsc` client, public CA copy, and
  non-secret connection information to a new directory.

The output directory is mode `0700`; files and `.env` are mode `0600`.
The command never prints the secret and cannot register an unknown
router. Restart `serve_devices.py` to load the new environment secret.
It does not connect to, install anything on, or change the company router.

Protect the bundle: the rendered `.rsc` contains the router's controller
key. Do not paste its contents into chat, a browser, terminal history,
screenshots, an issue, or a public repository. Do not use verbose import
or print the script source. The version-controlled template has no keys.

## 4. Check the router before the first run

In the existing approved WinBox/terminal session, inspect:

```routeros
/system/resource/print
/system/clock/print
/system/device-mode/print
```

Confirm RouterOS 7.21.4, correct date/time, and that Fetch is permitted.
If the device is flagged or its mode prohibits Fetch, ask the network
administrator to resolve that prerequisite. Do not change device mode
automatically. The server must be reachable through the correct routing
table/VRF, and DNS must work if the origin uses a hostname.

Transfer `controller-poll.rsc` and the **public** `controller-ca.pem`
through the company's approved private administration channel. Never
copy `ca.key` or `server.key` to the router. Verify the CA fingerprint
through that same trusted channel. On the controller, it is available
with:

```sh
openssl x509 -in private/controller-tls/ca.pem -noout -subject -sha256 -fingerprint
```

Import the public CA into RouterOS Certificates. In WinBox, confirm that
the selected certificate's subject/fingerprint matches, then mark that
CA trusted. This is a public trust certificate, not a client private key.
Do not bypass a trust or hostname failure with `check-certificate=no`.

## 5. Run one exchange

Run the privately transferred client, without verbose output:

```routeros
/import file-name=controller-poll.rsc
```

A successful run prints:

```text
SDR exchange complete: response validated; receipt recorded; no routing action
```

In **Routers**, check the controller polling status, last authenticated
time, and response receipt separately from the optional API diagnostic.
The latter may remain disconnected because API ports are disabled; that
does not prevent this outbound HTTPS connection.

The client stops on a transport, trust, authentication or JSON validation
failure and reports the stage without printing secrets. It never runs
received text as commands. Retry manually after fixing the cause; each
run generates new request IDs. A receipt confirms that the router
validated a particular reply, not that a route was applied.

See [native validation notes](routeros-native-notes.md) for the exact
tests completed on the target release. After the manual receipt succeeds,
an approved administrator can follow the
[tested recurring-poll installation](routeros-native-notes.md#explicit-installation-for-recurring-polling).
Both script and scheduler use the verified `read,test` policies and
`use-script-permissions`; the schedule is created disabled. Match its
interval to the approved polling setting. No scheduler is installed by
importing the one-run client.

## 6. Key rotation and recovery

Provision a new bundle in a new private directory, with a new `--key-id`
if one is specified. Existing active keys stay valid during the change.
After installing and verifying the replacement client, revoke the old ID:

```sh
.venv/bin/python manage.py revoke-router-auth \
  --router-id APPROVED_ROUTER_ID --key-id OLD_KEY_ID
```

Omit `--key-id` to disable all polling authorization for that identity.
Revocation takes effect when the next request reads the registry. The
retained old environment secret cannot be reused under the same key ID.
Use a new ID for rotation. Securely retire obsolete private bundles.

Back up JSON state while the controller is stopped and keep `.env` and
TLS private keys in a separately protected backup. The v1 and v2
communication state files hold replay history. Restoring old state while
requests are active can undo that history; stop requests and wait out
their acceptance window before recovering an older snapshot. Do not
delete state files to clear an authentication failure.

## Protocol and current limits

Version 2 uses a SHA-512 digest of the exact request bytes and standard
HMAC-SHA512, with the provisioned hexadecimal secret used as ASCII text.
Signed timestamps, UUID4 request IDs, per-router authorization, replay
checks, and per-source request limits protect the request boundary.
Verified HTTPS authenticates the server and protects the response.

The API returns only its fixed versioned JSON contract, never an internal
storage file, environment value, router password, or executable script.
The acknowledgment path accepts only a signed receipt for that router's
own known, unexpired response. It cannot report an applied routing change.

The v1 HMAC-SHA256 Python test contract remains available independently;
new native RouterOS installations should use v2. Full v2 details are in
[the native protocol reference](routeros-v2-protocol.md).
