# ADR-0002 — Use Xray-core only, with the native TUN inbound

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —
- **Implementation status:** Planned. No Xray config builder, process host or
  version gate exists in `src/` yet; only `MyVpn.Core/Xray/XrayVersion.cs` (the
  version policy) is implemented.

## Context

MyVpn needs a network core that can capture traffic at layer 3 on Windows,
Linux and macOS. Historically the available options were:

* a third-party TUN front-end (tun2proxy) driving a SOCKS inbound;
* sing-box, which has its own TUN stack; or
* the native TUN inbound that Xray-core added in 2026.

The project requirement is **Xray-core only** — sing-box is explicitly
forbidden as the network core. The question this ADR settles is whether
Xray-core's own TUN inbound is sufficient, and exactly which version may be
targeted.

The research (`docs/research/03-xray-tun-inbound.md`) verified the feature
timeline directly against upstream tags, and the answer is yes — but only above
specific versions, and only if the generated JSON uses the eight real field
names.

### Verified version facts

Fetching `proxy/tun/config.proto` at each tag:

| Tag | `proxy/tun/config.proto` | What it means |
|---|---|---|
| `v25.12.8` | **HTTP 404** | Native TUN inbound does not exist. |
| **`v26.1.13`** | **HTTP 200** | First release with a native TUN inbound (Windows, Linux, Android). Proto was `name = 1; uint32 MTU = 2; uint32 user_level = 3;` only. Implementation PR `XTLS/Xray-core#5464`. |
| `v26.1.18` | — | macOS/Darwin support (`tun_darwin.go` appears; PR #5559). |
| `v26.4.13` | `repeated uint32 MTU = 2;` | `gateway`, `dns`, `autoSystemRoutingTable`, `autoOutboundsInterface` land — **but `mtu` became an array.** `infra/conf/tun.go` declares `MTU []uint32`, and `tun_linux.go` reads `options.MTU[0]`. A scalar `"mtu": 1500` is therefore **invalid** on this release. **Rejected outright.** |
| **`v26.4.15`** | `uint32 MTU = 2;` | `mtu` restored to a scalar. This is the absolute minimum MyVpn will accept. |
| `v26.7.28` | — | `desc` field added (Windows Wintun adapter description); default TUN name became a random `utunNN`. |
| **`v26.9.9`** | — | Windows refinements (adapter-ready retry loop, default-route interface discovery). **Recommended.** |

The two floors from the research reports both matter and one version satisfies
both: the root-config `env` object needs **≥ v26.7.11**
(`docs/research/02-issue-9765-geodata.md` §1.5, commit `d5bc58d`); the TUN
inbound needs **≥ v26.4.15** and recommends **v26.9.9**
(`docs/research/03-xray-tun-inbound.md` §1.1). This is already encoded in
`MyVpn.Core/Xray/XrayVersion.cs`: `FirstWithTun = 26.1.13`,
`MinimumForTun = 26.4.15`, `Recommended = 26.9.9`, `KnownBroken = [26.4.13]`.

### The authoritative TUN schema is exactly eight fields

From `infra/conf/tun.go` (`TunConfig`) and `proxy/tun/config.proto`, the JSON
field names are:

`name`, `desc`, `mtu`, `gateway`, `dns`, `userLevel`,
`autoSystemRoutingTable`, `autoOutboundsInterface`.

Semantics that are easy to get wrong:

* `gateway` is a list of **address prefixes assigned to the interface**, not a
  next hop. macOS/FreeBSD use only the **first IPv4** prefix, as the utun
  point-to-point *remote* address, with the local address being the next address
  in that prefix (so a `/32` is rejected and a `/31` works).
* `dns` entries are **bare IP addresses**, never CIDR, and the field is
  **Windows-only** — it assigns DNS servers to the Wintun adapter and does
  nothing on Linux or macOS.
* `autoSystemRoutingTable` is a list of CIDRs Xray installs while running. On
  **Linux and Windows** an entry of `0.0.0.0/0` **replaces the physical default
  route**; on macOS Xray expands `0.0.0.0/0` into eight more-specific routes
  (`1.0.0.0/8` … `128.0.0.0/1`) and deliberately leaves `0.0.0.0/8` to the
  pre-existing default, so the physical default is preserved.
* `autoOutboundsInterface` is tri-state: **absent** (Xray implies `"auto"` when
  routes are present), **`""`** (explicitly disabled), or a literal interface
  name / `"auto"`. It binds every Xray outbound socket to a physical interface
  and is the primary loop-prevention mechanism.
* Inbound-level `sniffing` is supported, with the real schema being
  `enabled`, `destOverride`, `domainsExcluded`, `ipsExcluded`, `metadataOnly`,
  `routeOnly`. `routeOnly` exists **only inside `sniffing`**.
* `port`, `listen` and `streamSettings` are validated/skipped: the TUN inbound
  never listens on a port.

### Fields that do NOT exist (stated explicitly)

| Field | Verdict | Evidence |
|---|---|---|
| `address` | **Does not exist.** The address field is `gateway`. | No `json:"address"` in `infra/conf/tun.go`. |
| `autoRoute` / `auto-route` | **Does not exist.** The auto-route field is `autoSystemRoutingTable`. | `infra/conf/tun.go`; no `autoRoute` anywhere in the tree. |
| `strictRoute` / `strict_route` | **Does not exist in Xray-core** (it is a sing-box field). | Case-insensitive grep over `*.go`, `*.proto`, `*.json` → 0 hits. |
| `sniffingOverride` | **Does not exist.** | Grep `sniffingoverride`/`sniffing_override` → 0 hits. |
| TUN-level `routeOnly` | **Does not exist.** It exists only inside `sniffing`. | `infra/conf/xray.go:62`; not in `TunConfig`. |
| `stack`, `autoRedirect`, `includeUid`/`excludeUid`, `endpointIndependentNat`, `udpTimeout`, `interfaceName` | **None exist.** The IP stack is always gVisor; there are no per-inbound redirect toggles. | `proxy/tun/config.proto` (8 fields). |
| A `"dns"` **inbound** protocol | **Does not exist.** `"dns"` is registered only in the *outbound* loader (`infra/conf/xray.go:51`). DNS hijacking is expressed as an `outboundTag` pointing at a `protocol: "dns"` **outbound**. | `docs/research/03-xray-tun-inbound.md` §1.6. |
| `hijack-dns` routing keyword | **No such keyword.** | Routing schema fields are `inboundTag`, `outboundTag`, `domain`, `ip`, `port`, `network`, `protocol`, `processName`, … |

Two `MyVpn.Core` settings deserve an explicit note because their names coincide
with non-existent Xray fields: `TunSettings.AutoRoute`, `TunSettings.StrictRoute`
and `TunSettings.RouteOnly` are **MyVpn's own policy**, implemented by MyVpn's
route manager and sniffing generator. They must **never** be emitted as Xray TUN
JSON keys; `AutoRoute` maps to `autoSystemRoutingTable`, and `StrictRoute` is a
MyVpn-side "refuse to leak if a route cannot be installed" policy. The Xray JSON
schema contract is enforced by the golden-JSON tests described below.

### What Xray does not do (MyVpn must implement it)

Xray owns the interface and the capture. It provides **no** host route or loop
detection for the VPN server itself (`proxy/tun/README.md`: *"You can't just
route 0.0.0.0/0 through xray0 … resulting infinite network loop"*), **no**
firewalling, **no** DNS interception on Linux/macOS, **no** DNS leak prevention
anywhere, and **no** IPv6 teardown. MyVpn owns all of that.

## Decision

1. **Xray-core is the sole network core.** sing-box is not used, not linked, and
   not named in `src/` or `tests/`; ADR-0009 and the CI provenance guard enforce
   this.
2. **The native Xray TUN inbound (`"protocol": "tun"`) is the TUN mechanism.**
   No third-party TUN front-end, no `XRAY_TUN_FD` handoff for v1.
3. **Version policy** (`MyVpn.Core/Xray/XrayVersionPolicy`): reject `< 26.4.15`;
   reject `26.4.13` by **exact version** (not by a range, because only that
   release has the `repeated uint32 MTU` regression); recommend `26.9.9` and
   warn below it. Parse `xray version` with the existing tolerant, date-based
   parser (`XrayVersion.TryParse`), never a `1.x` comparison — Xray abandoned
   semantic versioning after `v1.8.24`.
4. **Emit only the eight real JSON keys, with documented casing** — lower-case
   `mtu`, not `MTU`. Go's `encoding/json` happens to match case-insensitively,
   but that tolerance is an implementation detail, not a contract; the
   documented spelling is what we emit. `autoOutboundsInterface` preserves its
   tri-state (absent ≠ empty).
5. **Validate before writing the config, not by letting Xray fail.** Malformed
   `gateway`/`dns`/`autoSystemRoutingTable` values reach
   `netip.MustParsePrefix`/`MustParseAddr` on Windows, which **panics the
   process** (`tun_windows.go`). Client-side validation is mandatory.
6. **Require loop protection whenever a default route is auto-installed.**
   On Linux/Windows, `0.0.0.0/0` in `autoSystemRoutingTable` requires a
   non-empty `autoOutboundsInterface`; otherwise the config is rejected as
   invalid. An uplink host route is installed *before* the default-route flip as
   a second, independent layer, and `no usable outbound interface found` in the
   Xray log is treated as a hard start failure.
7. **Validate the generated config with the real core before launching it**:
   `xray run -test -c <file>` (`-test` is defined in `main/run.go`). A non-zero
   exit maps to `ErrorCodes.ConfigRejectedByCore`.
8. **Split-tunnel is the first shipped TUN mode.** Full-tunnel (`0.0.0.0/0`,
   `::/0`) is opt-in until the loop and DNS behaviour is proven in the platform
   test tier.
9. **Never treat `connect()` success or `ping` as a health signal.** The gVisor
   stack completes TCP handshakes locally and synthesises ICMP echo replies;
   readiness is proven by an application-level request through the tunnel.
10. **The UI exposes a MyVpn-owned model, not Xray's JSON.** Rejecting invented
    Xray fields is a compile-time/test-time property: a golden-JSON test asserts
    that no key outside the eight ever appears, per platform.

## Consequences

**Positive**

* One process, one config format, one version gate, across all three OSes; no
  second network stack to license, audit or keep in sync.
* Upstream loop-prevention (`autoOutboundsInterface`) and IPv4/IPv6 support come
  for free once configured correctly.
* The version policy is unit-testable pure logic, already implemented.

**Negative / costs**

* MyVpn inherits every Xray TUN limitation: ICMP echo only, locally-synthesised
  pongs, no PMTU discovery, a 1024-packet UDP egress queue that drops silently,
  and no per-app capture.
* `wintun.dll` must be shipped per-architecture beside `xray.exe` on Windows.
* `dns` is inert outside Windows, so MyVpn must implement DNS takeover
  separately on Linux and macOS (see ADR-0011).
* The recommended floor moves with upstream; the version policy must be
  revisited on each Xray release that touches `proxy/tun/`.

**Risks accepted with mitigations**

| Risk | Mitigation |
|---|---|
| Total routing loop on Linux/Windows | Require `autoOutboundsInterface`; host route first; treat the warning log as fatal. |
| Xray panics on a malformed prefix (Windows) | Mandatory client-side CIDR/IP validation. |
| Silent `sockopt` failure while the UI shows "connected" | Tail for `failed to set Interface`/`failed to set SO_MARK` and tear down. |
| DNS leak on Linux/macOS | OS-level DNS takeover (ADR-0011) plus kill-switch port-53 rules (ADR-0006). |
| A future Xray release renames or removes a field | Golden-JSON tests + `-test` pre-flight + the version gate; re-verify per release. |

## Alternatives considered

* **sing-box as the core.** Rejected by project requirement. It would also import
  a GPL-3.0 network stack into a client that must stay clean-room (ADR-0009).
* **tun2proxy / a third-party TUN front-end over a SOCKS inbound.** Rejected: an
  extra unmaintained native dependency in the privileged path, no better than
  the native inbound, and it does not remove the DNS/route/firewall work.
* **`XRAY_TUN_FD` handoff (MyVpn creates the interface).** Rejected for v1: it
  disables all of Xray's interface management (`ownsTun=false` means no MTU, no
  addresses, no routes, no link up/down), so MyVpn would own the full interface
  lifecycle including crash cleanup. Kept as a documented future option if
  deterministic route ownership is ever required.
* **Target `v26.1.13` (the absolute floor).** Rejected: it has only
  `name`/`mtu`/`userLevel`, so a single config shape could not work across
  platforms, and `autoOutboundsInterface` (loop prevention) does not exist.
* **Accept `v26.4.13` and special-case `mtu` as an array.** Rejected: an
  avoidable second code path for one release, and the release is known-broken;
  exact-version rejection is simpler and already implemented.
* **Rely on Go's case-insensitive JSON matching and emit `MTU`.** Rejected: the
  documented key is `mtu`; casings are treated as part of the schema contract.

## References

* `docs/research/03-xray-tun-inbound.md` — **primary grounding**: §1.1 version
  timeline (404/200 evidence, `v26.4.13` `repeated uint32`, `v26.4.15` scalar,
  `v26.9.9` recommendation), §1.2 the eight-field schema and the non-existent
  field list, §1.3 per-OS requirements, §1.4 what Xray does not do, §1.5
  IPv4/IPv6, §1.6 DNS interception, §1.7 the loop problem and the
  `autoSystemRoutingTable` asymmetry, §2.2 loop prevention, §2.4 C# model and
  validator rules, §3 risks R-1…R-13.
* `docs/research/02-issue-9765-geodata.md` §1.5 — root config `env` object
  requires Xray ≥ `v26.7.11` (commit `d5bc58d`).
* `docs/research/04-nat-udp-matrix.md` §1.5 — `autoOutboundsInterface` binds all
  outbounds and covers built-in DNS local modes.
* Upstream primary sources: `proxy/tun/config.proto`, `infra/conf/tun.go`,
  `infra/conf/xray.go`, `infra/conf/dns_proxy.go`, `proxy/tun/README.md`,
  `proxy/tun/tun_linux.go`, `proxy/tun/tun_windows.go`, `proxy/tun/tun_darwin.go`,
  `main/run.go` — all at `XTLS/Xray-core` commit
  `c412e77a9b712082ac9ebf27fa793951cb5a7d85` / release `v26.9.9`,
  <https://github.com/XTLS/Xray-core>.
* Upstream PRs: #5464 (initial TUN), #5559 (macOS), #5891 (FreeBSD), #6035
  (`autoOutboundsInterface: "auto"`), #6478 (Windows refinements), #6486
  (`desc`).
* Official docs: <https://xtls.github.io/en/config/inbounds/tun.html>,
  <https://xtls.github.io/en/config/env.html>,
  <https://xtls.github.io/en/config/outbounds/dns.html>.
* Implemented code this ADR constrains: `src/MyVpn.Core/Xray/XrayVersion.cs`,
  `src/MyVpn.Core/Domain/Enums.cs` (`TunnelMode`, `Ipv6Mode`),
  `src/MyVpn.Core/Settings/AppSettings.cs` (`TunSettings`, `MuxSettings`).
