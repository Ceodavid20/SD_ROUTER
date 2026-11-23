# RouterOS native polling implementation notes

Target: RouterOS **7.21.4**. The `.rsc` source is a one-run, no-action
poll/receipt client. It does not install a scheduler or change routing.
Real RouterOS test results must be recorded separately from Python test results.

## Why protocol version 2 exists

The frozen MikroTik scripting reference lists native SHA-512 in `:convert`.
It does not document a SHA-256 or HMAC transform. The existing Python-only
version 1 contract remains separate. Version 2 uses HMAC-SHA512, built from
native SHA-512 with the standard HMAC construction, rather than adding an
unverified SHA-256 implementation to RouterOS.

The script uses SHA-512's 128-byte block, inner pad `0x36`, and outer pad
`0x5c`. An eight-bit arithmetic XOR avoids relying on numeric bitwise
operators: MikroTik documents bitwise operators for IP/IPv6 values. Keys
longer than the block are hashed first. Its provisioning format uses a
64-character random hexadecimal secret as ASCII text, not decoded hex bytes.
Python must use those same ASCII key bytes.

## RouterOS data and transport

- `:convert ... from=raw transform=sha512 to=hex` computes body hashes;
  `to=raw` supplies intermediate HMAC digest bytes.
- `:tonsec [:timestamp]` divided by `1000000000` produces UTC epoch seconds,
  independently of the router's displayed local timezone.
- Request IDs use random hexadecimal UUID4 form with fixed version and
  variant bits. `json.no-string-conversion` preserves identifiers and the
  version string when serializing/deserializing.
- Fetch uses authenticated JSON POSTs, `check-certificate=yes`, zero
  redirects, `output=user as-value`, and a ten-second duration bound.
- Receipt is acknowledged only after response identity, request binding,
  field types/count, no-action state, and expiry validation. Receipt never
  means that a routing change was applied.

Private provisioning must replace the four placeholders; do not put a
rendered secret-bearing script into source control or a public download.
The router needs a trusted controller CA, correct time, DNS/routing to the
approved server, and permissions for Fetch. Do not disable certificate
validation to bypass a failed connection.

## Native validation record

An isolated MikroTik CHR running **RouterOS 7.21.4** was exercised on
November 19, 2026. These checks passed in RouterOS itself:

- SHA-512 of `abc` matched the standard digest.
- Raw-byte and byte-array conversions preserved byte values, including
  zero and `255`.
- Epoch seconds, random strings, and JSON serialization with
  `json.no-string-conversion` worked with the request data types.
- The script's HMAC helper matched RFC 4231 test case 1: a twenty-byte
  `0x0b` key and the message `Hi There` produced the specified SHA-512 HMAC.
- RFC 4231 test case 6 also passed: a 131-byte `0xaa` key exercised the
  required key-hashing branch, and RouterOS matched Python's standard
  HMAC-SHA512 result for the specified message.
- The generated UUIDs had canonical version-4 and variant bits, and an
  empty JSON object decoded to the array type expected by the validator.
- Importing the entire source with `/import ... verbose=yes dry-run`
  reported `No syntax errors found`.
- The response validator accepted a valid fourteen-field poll response.
  It rejected a configuration array, an `apply` action, another router's
  identity, an expired Unix validity time, and an unrelated request ID.
  Its regular-expression quantifiers and object-brace checks executed
  successfully on the target release.
- The complete privately provisioned client made a certificate-checked
  HTTPS request to the isolated Flask device listener. It validated the
  response and sent its authenticated receipt acknowledgement. The
  controller independently recorded matching issued/received response
  IDs. This exchange used RouterOS Fetch and the RouterOS HMAC helper,
  rather than the Python simulator.
- Removing trust from the lab controller CA caused the native client to
  reject the connection at the poll-transport stage. Its previous
  receipt time remained unchanged, and certificate trust was restored
  after the test.
- A temporary lab DNS name absent from the trusted certificate's SAN
  was rejected with `SSL name verification failed`. The temporary DNS
  entry was removed after this exact-version certificate-name check.
- Substituting an incorrect signing key also failed at poll transport.
  The controller independently recorded `authentication_failed`, which
  returns HTTP 401, and its accepted-request count and previous receipt
  remained unchanged.
- Reading the privately provisioned source with `/file/get ... contents`
  returned all 11,080 bytes, so installation into the script repository
  does not depend on an assumed file-size limit.
- Executing the installed script with `policy=read,test`,
  `dont-require-permissions=no`, and `use-script-permissions` completed
  the full poll/receipt exchange. Reducing it to `policy=test` failed
  with `not enough permissions (9)`. Use the proven `read,test` pair.
- A scheduler with the same `read,test` policies completed seven
  successful cycles at a five-second lab interval. RouterOS logged
  seven successful exchanges, and the controller independently stored
  seven distinct poll/acknowledgement pairs with matching response IDs.
  The temporary scheduler and script were disabled/removed afterward.
- Before/after hashes of the lab interfaces, routes, and OSPF interface
  templates were unchanged after the scheduled exchanges.
- A correctly signed fresh native poll was accepted; resending those
  exact bytes was rejected with HTTP 409. A different correctly signed
  request timestamped 600 seconds in the past was rejected with HTTP
  401. The fresh poll in this negative-test fixture intentionally did
  not send a receipt acknowledgement. The controller independently
  recorded `replayed_request` and `expired_request` for those failures.
- After the negative tests, restoring the valid client completed a
  fresh poll and acknowledgement with matching controller response and
  receipt IDs.

These results cover native primitives, HMAC conformance, and parsing of
the entire script, including response validation and an actual HTTPS
poll/receipt exchange. A company router has not been contacted by these
checks; its network reachability, time, trust, and approved provisioning
still need to be checked at installation.

## Installation and permissions

Run `/system/device-mode/print` before installation and check that Fetch
is allowed. Scheduler access matters only when an administrator later
chooses to schedule the client. Do not change device mode automatically:
MikroTik documents physical confirmation and a reboot for such changes.

Import a privately provisioned client once for the initial exchange;
the current source does not create a script repository entry or a
scheduler. Never use verbose import or print a rendered client source:
it contains that router's shared secret. Transfer it through an approved
private administration channel, and protect both the router's stored
copy and the controller's provisioning bundle.

MikroTik documents Fetch under the `test` policy. The native execution
checks established `read,test` for this complete client; `test` alone
was insufficient. This memory-only client does not need routing-write,
reboot, password, or packet-sniffer permissions. Always use
`use-script-permissions` and keep `dont-require-permissions=no`.
An administrator's ordinary interactive run does not establish the
script's reduced permissions. Do not use the built-in `read` user group
as a substitute: it includes broader rights than the two named policies.

## Explicit installation for recurring polling

These commands are for an approved router administrator after the
one-shot exchange and CA verification have succeeded. They install the
private local file into the script repository; recurring execution does
not depend on retaining that loose file. Replace only its file name if
the approved transfer placed it in a different router directory.

The installation refuses existing names so it cannot overwrite another
script or schedule. Keep the private source out of terminal output.

```routeros
{
    :local sourceFile "controller-poll.rsc";
    :if (([:len [/system/script/find where name="sdr-controller-poll"]] != 0) || ([:len [/system/scheduler/find where name="sdr-controller-poll"]] != 0)) do={
        :error "Existing SDR installation requires review";
    };
    :local fileId [/file/find where name=$sourceFile];
    :if ([:len $fileId] != 1) do={
        :error "Expected exactly one private client file";
    };
    :local clientSource [/file/get $fileId contents];
    :if (([:typeof $clientSource] != "str") || ([:len $clientSource] = 0) || ([:len $clientSource] > 60000)) do={
        :error "Client source is unavailable or oversized";
    };
    /system/script/add name="sdr-controller-poll" policy=read,test dont-require-permissions=no source=$clientSource;
    :put ("SDR script installed; source bytes=" . [:len $clientSource]);
}
```

Run it with its reduced permissions and confirm a new controller receipt:

```routeros
/system/script/run sdr-controller-poll use-script-permissions
```

Create a disabled schedule. The one-minute interval below is the normal
deployment example; the native lab used five seconds to exercise seven
cycles promptly. Match the interval to the approved controller polling
setting. The client validates `poll_after_seconds` but does not change
its scheduler interval automatically.

```routeros
/system/scheduler/add name="sdr-controller-poll" interval=1m start-time=[/system/clock/get time] on-event="/system/script/run sdr-controller-poll use-script-permissions" policy=read,test disabled=yes
```

Enable it only after the manual receipt succeeds:

```routeros
/system/scheduler/enable [find where name="sdr-controller-poll"]
```

Confirm its run count and the controller's fresh matching receipts:

```routeros
:put [/system/scheduler/get [find where name="sdr-controller-poll"] run-count]
/log/print where message~"SDR controller response received"
```

Scheduled execution has its own script context. An interactive terminal's
global variables can remain stale while scheduled exchanges succeed;
the scheduler count, safe log messages, and controller receipts are the
verification evidence. Receipt still does not mean a routing action.

Pause polling with the exact scheduler name:

```routeros
/system/scheduler/disable [find where name="sdr-controller-poll"]
```

If intentionally uninstalling this installation, remove its schedule
first and then its script:

```routeros
/system/scheduler/remove [find where name="sdr-controller-poll"]
/system/script/remove [find where name="sdr-controller-poll"]
```

## Primary references

- [MikroTik scripting reference](https://help.mikrotik.com/docs/spaces/ROS/pages/47579229/Scripting)
- [MikroTik Fetch reference](https://help.mikrotik.com/docs/spaces/ROS/pages/8978514/Fetch)
- [MikroTik user and policy reference](https://help.mikrotik.com/docs/spaces/ROS/pages/8978504/User)
- [MikroTik device-mode reference](https://help.mikrotik.com/docs/spaces/ROS/pages/93749258/Device-mode)
- [Corrected scheduler permission documentation](https://manual.mikrotik.com/changelog/changelog-2026-09-25/)
- [RFC 2104: HMAC construction](https://www.rfc-editor.org/rfc/rfc2104.html)
- [RFC 4231: HMAC-SHA512 conformance vectors](https://www.rfc-editor.org/rfc/rfc4231.html)
- [MikroTik CHR requirements and free license](https://help.mikrotik.com/docs/spaces/ROS/pages/18350234/Cloud+Hosted+Router+CHR)

The current online manual can document newer releases. Native syntax and
interoperability must therefore be exercised on the actual target release
before this adapter is described as verified for production installation.
