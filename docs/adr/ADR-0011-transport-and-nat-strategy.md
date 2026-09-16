# ADR-0011 — Transport and NAT strategy

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —
- **Implementation status:** Planned. `MyVpn.Core/Settings/AppSettings.cs`
  implements `TransportStrategy` and `MuxSettings`; the environment probe,
  strategy selector and config emission do not exist. `AppSettings` also encodes
  two decisions this ADR corrects (see "Corrections to the current model").

## Context

"Does MyVpn support UDP?" and "is my NAT full-cone?" are the two questions most
often answered wrongly in this product category, and the research established
verified facts that contradict the common mental model
(`docs/research/04-nat-udp-matrix.md`).

### Cone is a server-side egress property with no JSON key

Two unrelated things are both called "NAT type":

| Concept | Where it lives | Can Xray change it? |
|---|---|---|
| **Local NAT type** | The network the client sits behind (home router, CGNAT, hotel, corporate) | **No** |
| **Xray "cone" / "UDP FullCone"** | How the **proxy server's** UDP egress mapping behaves, and how its inbound keys UDP sessions | **Yes** — one environment variable |

Cone is **global and process-wide**, it is **on by default**, and there is **no
JSON key for it**. It is disabled only by the environment variable
**`XRAY_CONE_DISABLED=true`**. In cone mode the server keys a UDP session by the
client's **source address only** (`id = {src}`) instead of `{src, dest}` and uses
a single egress socket for all destinations; VLESS/VMess additionally rewrite
`Command=UDP` (except ports 53 and 443) into Mux.Cool so one session carries
datagrams to many destinations.

Consequences that must be surfaced honestly:

* With VLESS/VMess/Trojan, the client's only flow is "client → server" over the
  configured transport, so **the local NAT type is almost irrelevant to proxied
  traffic**. A local symmetric NAT does not break proxied UDP.
* Cone cannot create inbound reachability for the client's machine outside the
  tunnel, and does nothing for a local symmetric NAT.
* A NAT-type tester run **through** a cone-capable proxy reports FullCone even
  when the local NAT is symmetric. Xray's own v1.3.0 release notes call this out;
  it is a measured artefact ("false FullCone") that a client can easily repeat as
  a product claim.
* Any doc telling users to set a `"fullcone"` key in the freedom outbound
  describes something that does not exist: the path
  `proxy/freedom/fullcone.go` never existed on Xray's default branch. MyVpn must
  **never** emit such a key.
* Cone widens the server's UDP injection surface: in cone mode one egress port
  is shared across all destinations for a client session and `freedom`'s
  `PacketReader` forwards every received datagram without source filtering. That
  is a user-visible trade-off, not a free win.

### `mux.xudpConcurrency` is inert unless `mux.enabled` is true

The entire mux/XUDP block in the outbound handler sits inside
`if config.Enabled { … }`. A profile that sets `xudpConcurrency: 16` while
leaving `enabled: false` silently gets no XUDP at all. To get XUDP **without**
TCP mux (the interesting combination — UDP aggregation without TCP
head-of-line blocking), the configuration is
`enabled: true, concurrency: -1, xudpConcurrency: 16`.

### Only some `sockopt` fields reach UDP

`isTCPSocket()` gates TFO, congestion control, window clamping, user timeout and
MSS, so those never apply to UDP. What does reach UDP:

| Option | Reaches UDP? | Notes |
|---|---|---|
| `interface` | **Yes** | `SO_BINDTODEVICE` (Linux, needs `CAP_NET_ADMIN`/`CAP_NET_RAW`), `IP_UNICAST_IF`/`IPV6_UNICAST_IF` (Windows, ifindex in network byte order), `IP_BOUND_IF`/`IPV6_BOUND_IF` (macOS) |
| `mark` | **Yes** | `SO_MARK`, **Linux only**, needs `CAP_NET_ADMIN` |
| `customSockopt` with `"network": "udp"` | Yes | escape hatch; `str` values are unsupported on Windows |
| `tproxy` | Yes (in `"tproxy"` mode) | Linux only; applies to the transparent-proxy inbound, **not** TUN |
| `sendThrough` | **No** | The docs state it cannot take effect for UDP because Xray cannot know the original destination |
| `bindAddress` | — | **Does not exist** in the current `SocketConfig` |
| `domainStrategy` | Resolution only | A DNS ↔ proxy infinite loop is documented when the server address is a domain |

The TUN inbound's `autoOutboundsInterface` is the purpose-built loop-prevention
switch and is equivalent to setting `sockopt.interface` on every outbound plus
the built-in DNS local modes; it is preferred in TUN mode (ADR-0002).

### NAT-type results are not authoritative

RFC 4787 §3 states the cone terminology "has been the source of much confusion,
as it has proven inadequate at describing real-life NAT behavior", and defines
two independent axes: **mapping** and **filtering**. RFC 5780 is Experimental and
says it "does not allow an application behind a NAT to make an absolute
determination of the NAT's characteristics … NAT devices do not behave
consistently enough to predict future behavior with any guarantee", and that
"under load NATs may transition to the most restrictive filtering and mapping
behavior". Results are per source port and per destination.

Finally, probes measure the wrong thing if they run through the tunnel: they
would measure the proxy's egress or a NAT64 mapping rather than the local access
network.

## Decision

### 1. Cone is never presented as a JSON option, and never as a local-NAT claim

Cone stays enabled by default (do **not** set `XRAY_CONE_DISABLED`), and it is
controlled as a **process environment variable** on the spawned Xray, or through
the root config `env` object when a config-carried value is wanted. The
environment variable on the child process is preferred because it cannot be lost
in config merging; the config `env` object is verified to work because
`Config.Build()` calls `os.Setenv` for every entry before any module (including
the routing build) runs. There is **no** `fullcone` JSON key, there never will be
one emitted, and the UI labels the feature as **"FullCone for proxied traffic"**,
showing **Local NAT** and **NAT observed through the proxy** as two separate
values. No UI text may imply the user's own NAT changed.

### 2. Mux/XUDP are emitted coherently or not at all

The config generator always writes `mux.enabled` explicitly. The default
recommended plan is UDP aggregation without TCP mux:

```
mux.enabled = true
mux.concurrency = -1            # -1 disables the TCP mux path
mux.xudpConcurrency = 16        # >0 enables XUDP
mux.xudpProxyUDP443 = "reject"  # QUIC/UDP-443 policy
```

A startup assertion reads back the effective plan and refuses a combination in
which `xudpConcurrency` is set while `enabled` is false, because that is silently
inert.

### 3. Local NAT type is never authoritative

* Environment facts are modelled as `{mapping, filtering, confidence}` with
  `Unknown` as a **first-class** value; `Unknown` must never be treated as a
  negative result and must never by itself force or forbid a UDP-based transport.
* Behaviour discovery runs on the **physical** interface, never through the TUN,
  and bootstraps with servers that actually advertise RFC 5780 `OTHER-ADDRESS`
  (for example `stun.voipgate.com:3478`). `stun.l.google.com:19302` is explicitly
  **not** used for behaviour discovery: a plain Binding Request returns only
  `XOR-MAPPED-ADDRESS`, and a `CHANGE-REQUEST` is silently ignored rather than
  answered with 420.
* Two independent servers must agree, otherwise the result is `Unknown`.
* Results are cached with a TTL and re-measured on network change; a NAT type is
  never persisted as a permanent property of the machine.
* Detection is a **five-point cross-check** (STUN on 3478, STUN on 443, a QUIC
  endpoint on 443, the Xray endpoint's real UDP port, and the Xray endpoint over
  TCP) because a single STUN failure must never be read as "UDP is blocked".
* NAT64/DNS64 discovery follows RFC 8781 §5.1 precedence — PCP (RFC 7225) over
  the RA `PREF64` option over RFC 7050 — and the RFC 7050 query is sent with
  **CD=0** (with CD=1 a DNS64 resolver will not synthesise and the test reveals
  nothing). `ipv4only.arpa` is never probed for connectivity.
* A private RFC 1918 IPv4 address plus an IPv4 default route on an otherwise
  IPv6-only access network is detected as a 464XLAT **CLAT**, not as native IPv4
  (RFC 6877 — 464XLAT is client-server only and has no inbound IPv4).

### 4. The fallback chain is bounded, ordered and never cyclic

```
0. Honour an explicit user choice (a manual override always wins and is never
   silently "improved")
1. XUDP + cone over a TLS-shaped TCP transport        (the default)
2. Plain UoT                        if step 1 stalls or the server rejects Mux
3. TCP-only / QUIC-suppressed       if UDP to the server is blocked
4. A UDP transport (mKCP/Hysteria)  ONLY if UDP-to-server is verified Allowed
                                    and the user opted in
5. Address-family overlay           IPv6-first, then NAT64-synthesised IPv6,
                                    applied on top of 1–4
6. A different ServerProfile        last resort, score-ordered
```

The chain is built once as a linked list with a **depth cap (≤ 4)** and a
per-step time budget. The verifier must not re-enter step *n* after moving to
step *n+1* within one connection attempt. A UDP-based transport is only selected
after the reachability probe passes with margin (≥ 4/5 replies, loss < 5 %).

### 5. A silent `sockopt` failure is a hard failure

Xray logs `failed to set SO_MARK` / `failed to set Interface` and then continues
without the binding. In TUN mode the absence of that binding is a routing loop,
so the log pump treats those exact strings as fatal: the tunnel is torn down
rather than left running while the UI claims "connected".

### 6. Local NAT detection is never used to gate a security feature

Because behaviour discovery is inherently non-deterministic (RFC 5780), no
security property may depend on it. The kill switch (ADR-0006), the TUN loop
prevention (ADR-0002) and the DNS takeover (ADR-0003/0006) are all unconditional
or fail-closed, never "NAT-type permitting".

### Corrections to the current model

Two implemented settings are insufficient for the verified Xray schema and must
be corrected when the config generator is written:

1. **`MuxSettings.XudpProxyUdp443` is a `bool`.** Xray's field is the
   tri-state string `"reject" | "allow" | "skip"`. A boolean cannot express
   `"skip"` (let QUIC use the protocol-native UDP path), which is the required
   value when UDP to the server is known to work. The setting must become a
   three-valued enum mapped to those strings; today's `bool` must not be emitted
   as a boolean.
2. **`TransportStrategy` (`Auto`, `UdpAlways`, `UdpOverTcp`, `TcpOnly`) is a
   preference, not a plan.** It cannot express `cone on/off`, `mux.enabled`,
   `concurrency`, `xudpConcurrency`, the interface binding, or the fallback
   order. It is retained as a user preference input and is consumed by the
   strategy selector; the selector's output is a `TransportPlan`, which is what
   the config generator emits.

Additionally, `MyVpn.Core/Domain/Enums.cs` has `TransportKind.Quic` but no
`Hysteria`, and `ProxyProtocol` has neither `Hysteria` nor `WireGuard`. If
UDP-based transports are ever offered as first-class options, those enums need
new members; until then the selector must not reference transports it cannot
represent.

## Consequences

**Positive**

* The client never claims a local NAT change it cannot deliver, and never emits
  a `fullcone` key that Xray does not have.
* The inert `xudpConcurrency`-without-`enabled` trap is caught by an assertion
  rather than by a support ticket.
* A bounded fallback chain with a depth cap makes transport selection
  deterministic and unit-testable with synthetic environment values and no
  network I/O.
* `Unknown` as a first-class confidence value prevents a bad measurement from
  forcing a fragile transport.

**Negative / costs**

* Honest reporting means the UI has two NAT readouts and an `Unknown` state,
  which is more work than one optimistic label.
* Behaviour discovery needs bootstrap STUN servers and is best-effort by nature;
  `stun.l.google.com` cannot be used for it, so the default server list needs
  care and documentation.
* Correcting `XudpProxyUdp443` to a tri-state enum is a breaking change to the
  settings schema and needs a migration (`AppSettings.SchemaVersion`).
* The five-point cross-check and NAT64 detection are a meaningful amount of
  platform code for a feature that mostly produces diagnostics.

**Explicitly refused**

* Any claim that MyVpn improves the **local** NAT type.
* Any promise of direct P2P inbound reachability.
* Any "Full Cone NAT" label without the "for proxied traffic" qualifier and the
  separate local/through-proxy readings.
* Building a decision on a single STUN probe, on a NAT type without a confidence
  value, or on a measurement taken through the tunnel.

## Alternatives considered

* **Emit a `fullcone` JSON key** (as some third-party guides suggest). Rejected:
  the field does not exist; the path that would have implemented it never existed
  upstream, and emitting it produces a config Xray rejects or ignores.
* **Enable mux by default with a TCP concurrency.** Rejected: TCP mux
  head-of-line blocking hurts UDP and can hurt throughput on fast links. The
  default is XUDP *without* TCP mux (`enabled: true, concurrency: -1`).
* **Default `xudpProxyUDP443` to `allow`.** Rejected: `reject` is the documented
  default and the safe choice when UDP/443 is blocked or throttled; `allow` and
  `skip` are opt-in once UDP is verified.
* **Use `sendThrough` for loop prevention.** Rejected: documented as having no
  effect for UDP, which is exactly the traffic that matters here.
* **Use `mark` as the portable loop-prevention mechanism.** Rejected: Linux only.
  `interface`/`autoOutboundsInterface` is the portable knob.
* **Set `XRAY_CONE_DISABLED` per profile.** Rejected: cone is a process-wide
  switch, not per-outbound. A per-profile cone setting is not expressible, and
  pretending otherwise would produce a config whose behaviour does not match the
  UI.
* **Let the local NAT type choose the transport.** Rejected: RFC 5780 explicitly
  cannot support that decision, and the local NAT type is largely irrelevant to
  proxied traffic anyway.
* **Report a single NAT type rather than `{mapping, filtering, confidence}`.**
  Rejected: it collapses two independent axes and hides the non-determinism.
* **Probe NAT type through the tunnel for convenience.** Rejected: it measures
  the server's egress or a NAT64 mapping, which is the "false FullCone" artefact.

## References

* `docs/research/04-nat-udp-matrix.md` — **primary grounding**: §1.1 local NAT
  vs server cone, §1.2 the cone/XUDP/mux mechanism facts and the "no JSON key"
  finding, §1.3 what each mechanism solves and does not, §1.4 `sockopt` fields
  that reach UDP, §1.5 detection-relevant log strings, §1.6 version history
  (Xray abandoned semantic versioning at `v1.8.24`), §1.7 the standards base,
  §2.1 the ordered probes, §2.2 the decision table, §2.3 the C# model, §2.4 the
  fallback ordering and depth cap, §2.5 loop prevention, §3 risks R1–R15,
  §Appendices for the explicit UNVERIFIED list, including the verified fact that
  `stun.l.google.com:19302` does not implement RFC 5780.
* `docs/research/03-xray-tun-inbound.md` §1.4/§1.7 and §2.2 — `dns` is
  Windows-only, `autoOutboundsInterface` is the loop-prevention mechanism, and
  the `autoSystemRoutingTable` asymmetry.
* Existing scaffolding: `src/MyVpn.Core/Settings/AppSettings.cs`
  (`TransportStrategy`, `MuxSettings` with `Enabled`, `Concurrency`,
  `XudpConcurrency`, `XudpProxyUdp443`), `src/MyVpn.Core/Domain/Enums.cs`
  (`TransportKind`, `ProxyProtocol`, `Ipv6Mode`, `DnsMode`),
  `src/MyVpn.Core/Results/ErrorCodes.cs`.
* Standards: RFC 4787 (NAT behavioural requirements and vocabulary), RFC 5780
  (NAT behaviour discovery, Experimental), RFC 8489 (STUN), RFC 6598 and RFC 6888
  (CGNAT), RFC 6146/6147/6052/7050/8781/7225/6877 (NAT64, DNS64, PREF64,
  CLAT/464XLAT), RFC 6886/6887 (NAT-PMP, PCP), RFC 9000 (QUIC), RFC 8305
  (Happy Eyeballs — Xray implements it for TCP only), RFC 3550 (jitter),
  RFC 1928 (SOCKS5).
* Upstream: `proxy/freedom/freedom.go`, `transport/internet/system_dialer.go`,
  `common/xudp/xudp.go`, `app/proxyman/outbound/handler.go`, `core/xray.go`,
  `infra/conf/xray.go` at `XTLS/Xray-core@c412e77a` / `v26.9.9`;
  Xray v1.3.0 and v1.8.24 release notes; the Mux.Cool and Sockopt docs at
  <https://xtls.github.io>.
* Official docs: <https://xtls.github.io/en/config/env.html> (the root `env`
  object and `XRAY_CONE_DISABLED`), <https://xtls.github.io/en/config/outbound.html>
  (`sendThrough` and UDP), <https://xtls.github.io/en/config/transports/sockopt.html>.
* ADR-0002 (Xray-only, native TUN, loop prevention), ADR-0006 (kill switch),
  ADR-0008 (headers that Gate-B into mux/TUN must never apply automatically).
