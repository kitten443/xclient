# ADR-0012 — Connect and disconnect sequencing, and what "connected" means

* **Status:** Accepted
* **Date:** 2026-09-17
* **Supersedes:** —
* **Related:** ADR-0002 (Xray-only), ADR-0003 (geo data), ADR-0005 (privileged helper), ADR-0006 (kill switch), ADR-0007 (process routing)

## Context

Implementing a connect flow looks like plumbing: build a config, start a process, report
success. Almost every way of getting it wrong produces the same user-visible symptom —
"connected, but nothing loads" or "the VPN broke my internet" — and the mistakes are not
in the plumbing, they are in the ordering and in what counts as evidence.

Three specific hazards shaped this decision:

1. **The leak window during connect.** There is a period between "the user asked for a
   tunnel" and "the tunnel carries traffic". If the firewall is armed after the core
   starts, that period is unprotected; if it is armed and the core then fails, the user
   is fenced off from their own network.
2. **A running process is not a working tunnel.** With the native TUN inbound the core
   completes TCP handshakes locally and synthesises ICMP echo replies, so a successful
   `connect()` or `ping` succeeds against a completely dead outbound. Upstream research
   confirmed this is inherent to the design, not a bug that will be fixed.
3. **Partial failure leaves debris that outlives the process.** A route, a firewall
   table, a DNS override or a desktop proxy setting left behind after a crash does not
   go away on restart. A desktop proxy pointing at a port nothing listens on survives a
   reboot and presents as "no internet", with no obvious connection to the VPN.

## Decision

### The order is a security property, and teardown is its exact reverse

```
Preparing     1. validate profile and settings
              2. locate the core, check its version against policy for the requested mode
              3. resolve the server to IP literals
              4. make the geo working copy coherent, then read availability
              5. build the config, omitting any geo rule whose asset is unusable
              6. write the config atomically
              7. assert the core will resolve the same asset directory we validated

Connecting    8. arm the Kill Switch          <-- before the core exists
              9. start the core (argv launch, explicit environment)
             10. point the desktop at the tunnel (system-proxy mode only)

Connected    11. verify with a real request through the tunnel
Disconnecting  reverse of the above
```

Step 8 before step 9 is the deliberate choice. Arming a default-deny rule set first
means the connect window is fail-closed: while the core is coming up, the only permitted
traffic is the core's own connection to the server. The cost is that a failed start must
be rolled back rather than left in place, which is why rollback is not an afterthought.

Step 11 is what makes the state transition to `Connected` meaningful. It is a real
request through the tunnel whose response reports the exit address, compared against the
host's own address measured beforehand. Without it the client cannot distinguish a
working tunnel from a process that merely started.

### A failed first connect returns to `Disconnected`, not `Faulted`

`VpnConnectionState.RequiresKillSwitch` is true in `Faulted`, because losing an
*established* session must not fail open. Applying that same rule to a connection that
never came up would brick the network on a configuration typo. A failed connect therefore
rolls back — disarm, stop, restore, delete — and returns to `Disconnected` with the error
reported through the result and the snapshot. The user ends up exactly where they
started, free to retry.

### Refuse rather than degrade silently

If the user selected a Kill Switch and the server address cannot be pinned to an IP, the
connect **fails** rather than proceeding unprotected. An armed default-deny rule set
without an allow-listed server would cut off the tunnel itself, and connecting without
the requested protection is worse than not connecting.

Where the protection genuinely does not exist — a platform with no executor, or a process
without privileges — the session proceeds but emits a warning naming the real cause. The
two cases are reported separately: "no implementation exists for this platform" and "the
implementation is present but cannot act without privileges" send the user to completely
different actions, and conflating them is actively misleading.

### The desktop proxy is restored before the listener is torn down

Teardown order is not merely the reverse of setup for its own sake. Restoring the proxy
*after* stopping the core leaves a window in which the machine points at a dead port, and
if the process dies in that window the setting persists across a reboot.

### Rollback attempts every step

Each cleanup action runs even if an earlier one failed, and the aggregate result reports
what could not be cleaned. A cleanup that stops at the first error is exactly the
situation the user is trying to escape.

## Consequences

**Good**

* The connect window is fail-closed whenever a Kill Switch is configured.
* "Connected" means verified, so the UI cannot display a reassuring state over a dead
  tunnel.
* A typo cannot leave the machine without a network.
* Every failure path reaches a state the user can retry from.
* Geo-data damage degrades routing policy instead of preventing the connection.

**Costs**

* Connect is slower: a pre-flight, a version probe, a direct-address measurement and a
  real request all happen before the state becomes `Connected`.
* Arm-then-start means the rollback path is load-bearing and must be tested.
* The Kill Switch cannot be armed when the server is a hostname that does not resolve,
  so such a profile cannot be used in Kill Switch mode. This is a deliberate refusal.
* Verification requires an external endpoint, so a fully offline connect is reported as
  unverified rather than as working.

## Alternatives considered

**Start the core first, then arm the firewall.** Rejected: it leaves the connect window
unprotected, which is the leak the Kill Switch exists to prevent.

**Treat "the core process is alive" as connected.** Rejected outright. It is the single
most misleading thing a VPN client can do, and the TUN design makes it specifically
unreliable.

**Verify with `ping` or a TCP handshake to the server.** Rejected: both are answered
locally by the TUN inbound, so they report success against a dead outbound.

**Compare only the exit address without measuring the direct address.** Rejected: without
a baseline the client cannot detect "the tunnel is up but traffic is not moving", which
is the most common real failure. The comparison is what turns a measurement into
evidence.

**Leave the Kill Switch armed after a failed connect (fail-closed on failure).** Rejected
for the first connect only. It converts a configuration mistake into a total outage and
gives the user no path back except the emergency cleanup. Fail-closed remains correct for
losing an established session.

**Arm the Kill Switch lazily, only after verification succeeds.** Rejected: it moves the
leak window to exactly where the traffic first flows.

## Verification

* The full sequence was exercised against a live subscription: connect reported exit
  address `45.133.119.82` against a direct address of `93.113.180.130`, i.e. traffic
  demonstrably moved, across XHttp+TLS, XHttp+REALITY and gRPC+REALITY profiles.
* Reverse order and idempotent teardown are covered by the Linux executor tests, and the
  nftables rule set is verified by installing it into a real kernel network namespace.
* The rollback-on-failure paths are covered by unit tests with injected fakes.
