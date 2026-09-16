# ADR-0007 — Per-process routing capability matrix

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —
- **Implementation status:** Planned. `MyVpn.Core/Domain/Enums.cs` implements
  `ProcessRoutingMode` and `ProcessSelectorKind`; `ErrorCodes.ProcessRoutingUnsupported`
  exists. No executor or capability probe exists.

## Context

"Per-app VPN" / "split tunnelling by application" is the single most-requested
feature in this product category and the single most-commonly-misrepresented
one. The research established what is actually achievable per platform, and the
answer differs sharply by OS. This ADR exists so that MyVpn publishes an honest
capability table instead of a marketing claim that fails at runtime.

Two framing rules come out of the research:

1. "Per-app" means **capture/redirect by process**. A destination-based
   split tunnel (route these CIDRs outside the tunnel) and a UID-based *block*
   list are different features and must be labelled as such.
2. Where a platform cannot do it reliably, MyVpn says so. A capability API that
   can only return "yes" is not a capability API.

## Decision

Publish, and implement against, the following per-platform capability matrix.
`IPlatformCapabilities` exposes it as data, the UI branches on it, and tests
assert the negative cases so a future contributor cannot "fix" an honest
limitation into an unreliable feature.

| Capability | Windows | Linux | macOS |
|---|---|---|---|
| Full tunnel (all traffic) | Yes | Yes | Yes |
| Destination-based split tunnel | Yes | Yes | Yes |
| Kill switch | Yes (WFP) | Yes (nftables) | Yes (PF, Apple-unsupported) |
| **Per-process include-routing** ("only app X uses the VPN") | **Partial, version-gated** | **Yes** | **No — not achievable** |
| **Per-process exclude/block** | **Yes** (permit/block only) | **Yes** | **Yes as a UID block list only** |
| Per-process child inheritance | **No** | **Yes** (cgroup subtree) | **No** |
| Reliable per-app traffic attribution | **No** | **Yes** (cgroup id) | **No** |
| Requires managed/MDM profile | No | No | **Yes** for true per-app VPN |

### Windows

* **`FWPM_CONDITION_ALE_APP_ID` can permit or block, not redirect.** A user-mode
  WFP filter's action set is `FWP_ACTION_PERMIT`/`FWP_ACTION_BLOCK`;
  `FWP_ACTION_CALLOUT_*` requires a kernel-mode callout driver. So "block all
  traffic from app X except through the tunnel" is expressible; "send app X's
  traffic into the tunnel" is not (from user mode).
* **`ALE_APP_ID` is path-based, not identity-based.** It is "the lower-case
  fully qualified device path of the application, as returned by
  `FwpmGetAppIdFromFileName0`". The same binary at a different path is a
  different app id; a different binary at the same path is the *same* app id.
  It also **does not inherit to children**: a child process has its own image
  path and therefore its own app id. Mitigations are `ALE_USER_ID` plus an
  install-directory ACL plus an Authenticode check at launch — but the
  limitation is real and is surfaced, not hidden.
* **`FwpmConnectionPolicyAdd0` is a version-gated spike, not a v1 dependency.**
  It is the one documented user-mode exception: it configures connection
  policies matching `ALE_APP_ID` with a route setting of `NEXT_HOP_INTERFACE`
  (the TUN LUID), which is genuine per-process routing without a driver. But its
  **minimum Windows build is undocumented** — the WDK page's "available starting
  with Windows Vista" is almost certainly boilerplate, and the API and its
  layers are absent from the WFP What's-New pages. The plan is: probe at
  startup on the oldest supported builds (Windows 10 22H2, Windows 11 21H2, x64
  and arm64); on `ERROR_INVALID_PARAMETER`/`ERROR_NOT_SUPPORTED` report
  "not available on this Windows build" and fall back. The feature ships behind
  a capability flag and is never assumed.
* **Xray's own `routing.rules[].process` matching is supported but
  unreliable.** On Windows it resolves the socket owner through the IP Helper
  tables (`GetExtendedTcpTable`/`GetExtendedUdpTable`) and
  `QueryFullProcessImageName`, and it **silently skips every TCP row that is not
  `MIB_TCP_STATE_ESTAB`**. Known real-world failures include protected/EDR
  processes (reported with Kaspersky; upstream issue #6535). It fails for UDP,
  for short-lived sockets such as DNS, for non-ESTABLISHED TCP and for protected
  processes. If exposed at all it is labelled best-effort, and a "not found"
  result is surfaced rather than silently misrouted.
* **Tracking children is only partially possible.** A job object covers only
  trees MyVpn launches (`JOB_OBJECT_LIMIT_BREAKAWAY_OK`/`_SILENT_BREAKAWAY_OK`
  let children escape); ETW `Process`/`Process_V2` reacts after the fact and can
  miss the first milliseconds; the reliable notification,
  `PsSetCreateProcessNotifyRoutine`, is kernel-mode only. There is **no**
  user-mode way to retroactively cover an arbitrary already-running process
  tree.

### Linux

Adopted: **cgroups v2 + nftables `socket cgroupv2` + fwmark + policy routing**,
with Xray's `autoOutboundsInterface` as loop prevention.

* Selection is by **cgroup membership**, which the kernel resolves per socket
  and which is inherited by the whole subtree across fork/exec — the best
  ergonomics available, and the reason Linux is the one platform where
  per-process include-routing is genuinely reliable.
* Routing is `ip rule fwmark` into a dedicated table so the **main** table is
  never touched:
  `ip route add default dev <tun> table 100`,
  `ip rule add fwmark 0xca6c/0xca6c lookup 100 priority 1000`,
  `ip rule add to <server-ip> lookup main priority 900` (the tunnel's own uplink
  must not re-enter the tunnel), and
  `ip rule add fwmark 0xca6c/0xca6c prohibit priority 1100` (fail closed when the
  tunnel is down).
* Because `socket cgroupv2` resolves a **numeric cgroup id**, not a path, rules
  stop matching when the cgroup is removed and re-created, and rules for a
  not-yet-existing cgroup fail to load ("cgroupv2 path fails: No such file or
  directory"). Mitigation is mandatory: the helper owns `myvpn.slice`, re-applies
  the ruleset on every connect and on app restart, prefers launching inside the
  slice (`systemd-run --slice=… --scope`) over moving existing PIDs (a moved
  process may already hold sockets created in the old cgroup), and runs an
  effectiveness probe (`VerifyEffectiveAsync`) rather than assuming success.
* `socket cgroupv2` requires **Linux ≥ 5.13 and nftables ≥ 0.99** (feature-detected
  at startup), and creating the slice requires root write access to a root-owned
  cgroup root, which is why ADR-0005's helper is required rather than optional.
  Where unavailable, the fallback is `meta skuid`/`meta skgid` marking, labelled
  as weaker; where cgroup v2 is absent entirely, the feature is disabled with a
  clear message rather than silently downgraded.
* **Do not** use `autoSystemRoutingTable` with `0.0.0.0/0` for this mode: on
  Linux that entry **replaces** the physical default route, which would destroy
  the "only marked traffic is tunnelled" property and create a loop.

### macOS

**True per-process tunnelling is not achievable for a self-distributed client.**
Stated plainly, and refused:

* `pf.conf(5)` `user`/`group` are **match criteria only** — TCP and UDP only,
  credentials frozen at socket-creation time (a root-then-drop-privileges
  process keeps root attribution), and unknown for forwarded connections. PF
  *can* rewrite a next hop (`route-to`/`reply-to`), so
  `pass out quick proto { tcp, udp } user 501 route-to (utun0 <peer>)` is
  syntactically expressible; it is **not** shipped, because reply asymmetry is
  documented behaviour, whether `route-to` yields a usable route for a synthetic
  peer on a userspace fd is **UNVERIFIED**, it silently excludes ICMP and
  mis-attributes setuid processes, and no mainstream macOS VPN ships this as a
  split-tunnel mechanism. `rtable` does not help — it is only effective before
  the route lookup, i.e. on inbound.
* `NEAppRule` is **read-only to the provider**:
  `NETunnelProvider.appRules` is documented as non-`nil` only for a Per-App VPN
  configuration, and the public API exposes no setter. Per-app VPN
  configurations are installed as VPN payloads with per-app rules in a
  configuration profile, which means MDM (or a user-installed profile at
  minimum). `[MANAGED]`.
* `NEFilterDataProvider` **cannot redirect**. Its verdicts pass or block
  ("The Filter Data Provider can choose to pass or block the data"), and the
  extension sandbox explicitly "prevents the extension from moving network
  content outside of its address space". It is a filter, not a router.
* `NETransparentProxyProvider` is destination-scoped (network rules), ignores
  `NEDNSSettings`/`NEProxySettings`, fails **open** for non-proxied flows, and is
  entitlement-gated.
* `ipfw` is gone (deprecated in 10.11; `bsd/netinet/ip_fw2.c` is absent from
  current XNU), and the utun proc-UUID hook (`UTUN_FLAGS_ENABLE_PROC_UUID`) is
  populated by the private NECP engine with no public API.
* `IP_BOUND_IF` is per-socket and chosen by the owning process; it is how MyVpn
  keeps its *own* transport out of the tunnel, not a way to reach another app.

So macOS ships **destination-based split tunnelling** and **proxy mode**, plus
an optional **UID block list** delivered by PF (`block drop quick out proto
{ tcp, udp } user <uid>`) — presented in the UI as *"Block these users from the
network"*, explicitly not as routing. True per-app tunnelling is documented as
requiring a managed profile and is out of scope.

## Consequences

**Positive**

* The UI can tell the truth per platform, and the capability object forces the
  question to be answered at the platform layer rather than in the view.
* On Linux, per-process routing is genuinely reliable (with the re-apply and
  probe discipline), which is a real differentiator.
* The negative tests encode the platform limits so a future contributor cannot
  implement an unreliable mechanism and call it fixed.

**Negative / costs**

* A capability matrix is more work than a boolean and must be maintained as
  platforms change (notably if `FwpmConnectionPolicyAdd0` becomes documented, or
  if the project ever obtains the NetworkExtension entitlement).
* macOS users will be told "no", which is a product cost accepted deliberately.
* Linux's cgroup-id staleness means the feature must be re-applied and verified,
  not set once.

**Still UNVERIFIED (must be retired by spikes/tests)**

* `FwpmConnectionPolicyAdd0` availability and behaviour on the oldest supported
  Windows builds, x64 and arm64.
* Which WFP conditions are classifiable pre-BFE, and whether a user-mode process
  may add `BOOTTIME` filters at ALE layers.
* The observable semantics of `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`.
* Whether `route-to`/`reply-to` on a userspace utun behaves as a per-process
  route in current macOS (spike; default outcome "rejected as unreliable").
* Coverage for WSL2/Hyper-V/Windows Sandbox/AppContainer traffic under ALE
  filters.
* Whether Android's `sockopt.interface` is sufficient (not a MyVpn target, but
  recorded for completeness).

## Alternatives considered

* **Promise per-process routing on all three platforms; implement what works and
  let it degrade.** Rejected: a security feature that silently does nothing is
  worse than an absent one, and this is precisely the failure mode the research
  documented in prior art.
* **A kernel-mode WFP callout driver on Windows** (the only way to redirect from
  WFP). Rejected for v1: an EV certificate is required to open a Hardware Dev
  Center account; since Windows 10 1607 new kernel drivers must be Dev-Portal
  signed and cross-signing is not accepted for 1809+; attestation signing plus a
  per-release certification loop is a very large recurring cost. Revisit only if
  `FwpmConnectionPolicyAdd0` proves unavailable.
* **A `NEPacketTunnelProvider` system extension on macOS** to obtain
  `NEAppRule`-based per-app routing. Rejected for v1: entitlement-gated,
  native-only, user-approval-gated, and it makes a from-source build unable to
  run the tunnel without the contributor's own entitled profile. Documented as
  the upgrade path.
* **PF `user`-scoped `route-to` on macOS.** Rejected as unreliable (see above);
  retained as a Phase-0 spike whose default outcome is rejection.
* **Xray `routing.rules[].process` as the Windows mechanism.** Rejected as the
  primary mechanism: silently skips non-ESTABLISHED TCP, fails for UDP and
  protected processes. Permitted only as an explicitly best-effort option.
* **Replacing the system default route on Linux to send everything through the
  tunnel, then excluding processes.** Rejected: it destroys the "unmarked
  traffic stays on the physical uplink" invariant, requires saving and restoring
  the original default route (the classic way VPN clients brick networking), and
  removes the fail-closed `prohibit` rule's meaning.
* **`meta skuid`/`meta skgid` marking as the primary Linux mechanism.** Rejected
  as primary: it does not inherit to children, and a process can change its own
  credentials. Kept as the documented weaker fallback below Linux 5.13.

## References

* `docs/research/06-windows-networking.md` — §1.4 (`ALE_APP_ID` semantics,
  no child inheritance, permit/block only, `FwpmConnectionPolicyAdd0` verbatim
  text and its undocumented version floor, `ALE_PACKAGE_ID`, child-tracking
  options), §2.6 (the consolidated "cannot be done reliably on Windows" list),
  §1.1.6 (user-mode filters cannot redirect), R7, R11, R18.
* `docs/research/07-linux-networking.md` — §1.2 (`socket cgroupv2` semantics and
  the cgroup-id staleness), §1.4 (cgroup v2 delegation), §2.3 (the comparison
  table, the recommended combination, the mark ruleset, loop prevention, the
  `skuid` fallback, `VerifyEffectiveAsync`), §2.6 (policy routing and the
  maintain/`main` decision), §3 R-1, R-5.
* `docs/research/08-macos-networking.md` — §1.4 (PF `user`/`group` and
  `route-to` verbatim, `IP_BOUND_IF`, the `ipfw` removal, `NEAppRule`
  read-only, `NEFilterDataProvider` cannot relay, the proc-UUID hook, the
  recommendation table), §1.9 (the honest verdict), §2.4
  (`IProcessRouter`/`IPlatformCapabilities` shapes), §3 R2, R12.
* `docs/research/04-nat-udp-matrix.md` §1.2/§1.5/§2.5 — `sockopt.interface` and
  `autoOutboundsInterface` reach UDP, which is what makes loop prevention work
  in this mode.
* Existing architecture: `src/MyVpn.Core/Domain/Enums.cs` (`ProcessRoutingMode`,
  `ProcessSelectorKind`), `src/MyVpn.Core/Settings/AppSettings.cs`
  (`ProcessRoutingSettings`, `ProcessRoutingProfile`, `ProcessSelector`),
  `src/MyVpn.Core/Results/ErrorCodes.cs` (`ErrorCodes.ProcessRoutingUnsupported`).
* Primary sources: WFP
  <https://learn.microsoft.com/windows/win32/fwp/> (`FwpmConnectionPolicyAdd0`,
  `FWPM_CONDITION_ALE_APP_ID`, `ALE_CONNECT_REDIRECT`); nftables `nft(8)` socket
  expressions and cgroup v2 support patch
  <https://patchwork.ozlabs.org/project/netfilter-devel/patch/20210426171056.345271-3-pablo@netfilter.org/>;
  `pf.conf(5)` <https://keith.github.io/xcode-man-pages/pf.conf.5.html>;
  Apple `NEAppRule`, `NETunnelProvider.appRules`, `NEFilterDataProvider`,
  `NETransparentProxyProvider`
  <https://developer.apple.com/documentation/networkextension>; XNU
  `bsd/net/if_utun.c`, `bsd/netinet/in_pcb.c`, `bsd/sys/un.h`.
* ADR-0004 (runtime capability probing), ADR-0005 (helper), ADR-0006
  (kill switch), ADR-0009 (licensing).
