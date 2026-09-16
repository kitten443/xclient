# ADR-0006 — Per-platform kill switch

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —
- **Implementation status:** Planned. `MyVpn.Core/Domain/Enums.cs` implements
  `KillSwitchMode`; the platform executors and the pure ruleset/filter renderers
  do not exist yet.

## Context

A VPN client that is not fail-closed is worse than no VPN client: the user
believes their traffic is protected while it egresses in the clear. MyVpn
therefore needs a kill switch on all three platforms, and the mechanism must
satisfy four properties:

1. **"Block all egress except the tunnel" is expressible atomically.** A
   half-applied policy is either a leak or a lockout.
2. It must be able to key on the tunnel **interface**, the VPN server's
   addresses, loopback, DHCP/NDP and the configured resolvers.
3. It must be reparable after a crash, including a `SIGKILL` of the privileged
   helper.
4. It must not silently disable itself across a reboot while the UI still claims
   protection.

The naive platform choices fail at least one of these, and the research
established why for each platform.

### Windows: WFP, not `INetFwPolicy2`/`netsh`

Windows Firewall's own rule engine cannot express this. Its documented
precedence is "explicit block rules take precedence over any conflicting allow
rules" and it "doesn't support weighted, administrator-assigned rule ordering",
so the only way to build fail-closed through `INetFwPolicy2` is to set
`DefaultOutboundAction = NET_FW_ACTION_BLOCK` — a **machine-wide**, user-visible
mutation of the host's firewall posture, subject to Group Policy override
(`LocalPolicyModifyState` exists precisely to tell you your local change will not
take effect). `INetFwRule.Interfaces` takes **friendly names**, not interface
LUIDs, so "the interface this connection will egress on is the TUN adapter" is
inexpressible. Rule edits are committed **rule-by-rule**, not transactionally.
And the whole API requires the Windows Firewall service to be running, so a
third-party kill switch would depend on a service the user, another VPN client,
or a domain GPO can disable underneath it.

WFP (`fwpuclnt.dll`) has the opposite properties: documented ACID transactions
(`FwpmTransactionBegin0`/`Commit0`/`Abort0`), weight-based arbitration inside a
sub-layer, `FWPM_CONDITION_IP_LOCAL_INTERFACE` matching by **LUID**, a
`FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` layer that sees the connecting process, and
boot-time filters (`FWPM_FILTER_FLAG_BOOTTIME`). It needs the Base Filtering
Engine, not the firewall service.

### The boot-time trap that must not be missed

BFE's documented rule for persistent objects is the trap:

> At start, the BFE only adds the following types of persistent objects to the
> system: the object is not associated with a provider; the object has an
> associated provider that does not specify a service name; the object has an
> associated provider and an associated service set to auto-start.

So a **persistent (always-on) kill switch is silently disabled at boot** unless
the provider sets `serviceName` **and** that service is installed with
auto-start. A client that ships always-on mode without this ships a false sense
of protection. `FWPM_PROVIDER_FLAG_DISABLED`/`FWPM_FILTER_FLAG_DISABLED` are
only ever returned by enumeration, so the helper must enumerate its own objects
at start and raise a visible alarm.

### macOS: PF, with Apple's own caveat

PF is the only mechanism that can provide a fail-closed kill switch for a
self-distributed (non-App-Store, non-MDM) macOS client, because
`NEPacketTunnelProvider`'s `includeAllNetworks`/`enforceRoutes` are gated behind
the `com.apple.developer.networking.networkextension` entitlement and a native
system extension (ADR-0007).

But Apple's **TN3165, "Packet Filter is not API"**, says plainly:

> It is not considered API. Do not use Packet Filter in a software product that
> you distribute to a wide audience. […] PF is not considered API because the PF
> rules you install might clash with those installed by the user, macOS system
> services, either now or in the future, or other third-party products.

MyVpn will ship it anyway, because there is no alternative at this distribution
model — but it is a **best-effort, Apple-unsupported** feature, isolated behind
`IKillSwitch`, documented as such, and tested against the exact services TN3165
names (Internet Sharing, AirDrop, Continuity, Xcode device debugging).

Two PF specifics are load-bearing:

* **Reference-counted enable.** `pfctl -d` (`DIOCSTOP`) unconditionally disables
  PF and destroys **every** other holder's token. `pfctl -e` holds no
  reference. MyVpn must use `pfctl -E` and capture the printed token, then
  release only its own with `pfctl -X <token>`. `pfctl -d` and `pfctl -e` are
  **forbidden**. (`pfctl -X 0` does not disable PF — token `0` is never in the
  list — but it is still a bug to ship.)
* **Apple's anchors must be preserved.** `pfctl -f` flushes the main ruleset
  that macOS loads at boot, and the startup file states "Care must be taken to
  ensure that the main ruleset does not get flushed, as the nested anchors rely
  on the anchor point defined here." MyVpn's ruleset therefore re-establishes
  Apple's evaluation point by including the `scrub-anchor`/`nat-anchor`/
  `rdr-anchor`/`dummynet-anchor`/`anchor "com.apple/*"` lines and
  `load anchor "com.apple" from "/etc/pf.anchors/com.apple"`. `/etc/pf.conf` and
  `/etc/pf.anchors/com.apple` are treated as **read-only inputs** and are never
  written.

### Linux: nftables, one transaction

`iptables` on every supported distribution is already the nf_tables shim, so
using it means giving up the nftables feature set (notably
`socket cgroupv2`) while gaining nothing. Two concrete nftables advantages
matter here: `nft -f` swaps the whole ruleset **atomically** — "there is no
moment when the firewall is partially configured" — and one `inet` table covers
IPv4 and IPv6 in a single transaction, avoiding the `iptables`/`ip6tables`
drift that produces IPv6 leaks.

## Decision

### Three modes, one meaning

* **`Disabled`** — no rules installed.
* **`OnDemand`** — rules exist only for the duration of a VPN session; a helper
  crash fails **open** but the tunnel is gone with it (the model WireGuard for
  Windows uses, and the correct default).
* **`AlwaysOn`** — rules persist across reboot. This is opt-in, loudly
  described, and requires the Windows `serviceName` + auto-start discipline or
  its platform equivalent.

`VpnConnectionStateExtensions.RequiresKillSwitch()` (already implemented) is the
single source of truth for when rules must be engaged: `Connected`, `Degraded`,
`Reconnecting`, **`Faulted` and `Disconnecting`**. In particular the kill switch
stays engaged in `Faulted` — the state whose doc comment says "the Kill Switch
may be the only thing keeping the user safe" — and during `Disconnecting` until
teardown completes. It is never disengaged merely because the core died.

### Windows: WFP via `fwpuclnt.dll`

One **dynamic** session for `OnDemand` (`FWPM_SESSION_FLAG_DYNAMIC`, so objects
self-delete and a crash fails open because the tunnel is gone too); a
non-dynamic session with all objects `*_FLAG_PERSISTENT` for `AlwaysOn`, with
`FWPM_PROVIDER0.serviceName` set and the service installed auto-start, plus an
equivalent `FWPM_FILTER_FLAG_BOOTTIME` set. The two flag sets cannot be combined
on one object, so equality is achieved with two equivalent filters per rule;
Apple's—rather, Microsoft's—documented guarantee that "the transition from
boot-time to persistent filters […] is atomic, so if a provider has both a
boot-time and a persistent filter, there will never be a window when neither is
in effect" is what makes that safe.

One dedicated sub-layer at the **maximum weight** (`weight = 0xFFFF`) holds the
policy, so MyVpn's arbitration is evaluated first. Inside it, still one
transaction:

| Weight | Filter | Purpose |
|---|---|---|
| 15 | `ALE_APP_ID` = `xray.exe` **and** `ALE_USER_ID` = the service's token security descriptor | The tunnel's own encrypted transport. The second condition stops another process living at the same image path from inheriting the exemption, because `ALE_APP_ID` is a path. |
| 14 | TCP/UDP to the configured resolvers, remote port 53 | Leaktight DNS: plaintext DNS anywhere else is blocked. |
| 13 | `FWP_CONDITION_FLAG_IS_LOOPBACK` | The local SOCKS/HTTP inbound and UI↔service IPC keep working. |
| 12 | `FWPM_CONDITION_IP_LOCAL_INTERFACE` = the TUN LUID | Anything the routing table sends into the tunnel. |
| 12 | DHCP v4/v6 and ICMPv6 NDP 133–137 | Otherwise the adapter cannot obtain or renew an address. |
| 0 | **No conditions → block** | The fail-closed catch-all, at `ALE_AUTH_CONNECT_V4/V6` and `ALE_AUTH_RECV_ACCEPT_V4/V6`. |

Within a layer, filters are evaluated highest-to-lowest and the first
terminating action wins, so every permit beats the weight-0 block and everything
else is denied. The application-identity blob comes from
`FwpmGetAppIdFromFileName0` on the exact, file-ACL-protected `xray.exe` path and
is freed with `FwpmFreeMemory0`. Every filter carries an explicit
`FWP_ACTION_TYPE`, and `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` is **not** relied
upon: its documented meaning is internally inconsistent (the structure page and
the arbitration page disagree on whether clearing it makes the action hard), and
the weight-0 catch-all already provides fail-closed semantics under either
reading.

Optional hardening for both modes: a second, lower-weight sub-layer with the
same shape at `FWPM_LAYER_OUTBOUND_IPPACKET_V4/V6`, which covers traffic the ALE
layers never classify and cuts an existing flow on its next packet rather than
at reauthorisation. It is optional because the condition set resolvable
pre-BFE is **UNVERIFIED**, and it must use IP-layer conditions only.

**Honest limitations, stated in the UI:** a user-mode WFP filter can only
permit or block, never redirect; WFP hard blocks cannot be overridden even by
MyVpn (by design, so corporate policy is not bypassed); protection is
unavailable while BFE is stopped; `FWPM_CONDITION_IP_LOCAL_INTERFACE` can be
`FWP_EMPTY` in some classifications, which fails closed but can interrupt
connectivity on reconnect; and coverage of AppContainer/WSL2/Hyper-V
compartments is **UNVERIFIED**.

### Linux: nftables `table inet myvpn_ks`, single transaction

One `inet` table, `delete table` + redefinition in a **single** `nft -f`
transaction, default-drop policies on `output`, `input` and `forward`, with:

* `oifname "lo"` and `oifname "<tun>"` accepted (by **name**, never by ifindex,
  because a TUN interface is created dynamically and ifindexes are recycled);
* server addresses accepted from `@vpn_endpoint4`/`@vpn_endpoint6` sets with
  `flags interval`, matched **independently of protocol/port** so an established
  session survives an endpoint-set refresh;
* DHCP (`udp sport 68 udp dport 67` and reverse) and ICMP/ICMPv6 accepted;
* `ct state established,related` accepted **after** the explicit rules;
* a final `counter drop comment "myvpn_ks: egress denied"`.

IPv6 leak prevention is structural: for an IPv4-only tunnel the
`vpn_endpoint6` set is empty, so all IPv6 egress falls through to the default
drop. There is deliberately **no** unconditional `udp dport 53 accept` in this
table — that would be a DNS leak by construction; DNS is handled by the DNS
guard (ADR-0011) and by the port-53 permit to configured resolvers being
absent here.

Two validated nftables traps the implementation must respect:

* `fwd`, `drop`, `accept` and `mark` are **reserved** and cannot be chain names;
  the forward chain is `forward_chain`.
* nftables **1.0.2** rejects `destroy table`/`destroy set` even though `nft(8)`
  documents them (the shipped man page is newer than the shipped binary).
  Cleanup is therefore an existence check followed by `delete`, and endpoint-set
  refresh uses `flush set` + `add element` in one transaction so the set is
  never observed empty.

`ExecStopPost=/usr/lib/myvpn/myvpn-helper --cleanup` runs the same idempotent
cleanup on every stop, including an unclean one; a companion oneshot unit with
`PartOf=` covers `SIGKILL`; the client detects a stale `inet myvpn_ks` table with
no live tunnel on next launch. The kill switch is **never** written to
`/etc/nftables.conf`: a boot without the VPN would then have no connectivity at
all.

### macOS: PF anchors, `pfctl -E` token, fail-closed ruleset

Bring-up order (interface existence matters because PF resolves names at parse
time): create the utun → set address/MTU → validate with `pfctl -n -f -` → `pfctl
-E` (capture token) → `pfctl -f -`. The ruleset includes Apple's anchor lines,
`set skip on lo0`, `set block-policy drop`, a `block drop quick inet6 all` for an
IPv4-only tunnel, passes for the server endpoints (held in a PF **table** so they
can be updated with `pfctl -t myvpn_server -T add/replace`, not a full reload),
DHCP on the physical interface, DNS only on the tunnel interface, the tunnel
interface itself, and a final `block drop all`. Teardown restores the captured
original ruleset and releases **only our** token with `pfctl -X`, verified with
`pfctl -s References`. `-o none` disables the ruleset optimiser while developing
so loaded rules match the source text one-to-one.

**Honest limitations, stated in the UI:** Apple declares PF "not API" and warns
of clashes with system services and other products; PF rules cannot fix a
resolver that chooses a physical-interface server (ADR-0011); PF is
`TCP`/`UDP`-attributable for `user`/`group` matches only; and a crashed helper
leaves the machine without connectivity until launchd restarts it and the
journal replay restores state — the intended failure direction.

### The mandatory Emergency Cleanup

All three platforms ship an explicitly labelled **Emergency Cleanup / restore
network** action that removes every MyVpn firewall object, route and DNS change
idempotently, plus a documented manual command line for the worst case:

* Windows: enumerate our own objects and delete by key; `netsh wfp dump` is the
  snapshot/escape hatch.
* Linux: `myvpn-helper --cleanup` (also the `prerm`/`postrm` action, so
  uninstalling never leaves the host offline).
* macOS: restore the saved original ruleset and `pfctl -X <token>`; snapshot
  `pfctl -s rules|nat|Anchors|References` **before** arming.

Recovery is attempted automatically from three places on every platform: the
graceful disconnect path, the process-crash path, and a start-up replay pass
that runs before any command is accepted.

## Consequences

**Positive**

* Fail-closed is a structural property on all three platforms, not a
  best-effort sequence of commands.
* `Faulted` keeps protection engaged, which is the only safe reading of that
  state.
* The endpoint sets/table can be refreshed atomically without dropping policy.
* The cleanup path is exercised on every stop, so it cannot rot.

**Negative / costs**

* Windows: two persistence modes, three flag sets, and a boot-time trap that is
  easy to regress; a startup self-check and a CI assertion on the service start
  type are mandatory.
* Linux: a fail-closed policy means a crashed helper takes the host offline
  until cleanup runs — an availability cost accepted deliberately.
* macOS: PF is explicitly unsupported by Apple and may break Internet Sharing,
  AirDrop, Continuity or Xcode device debugging; the kill switch must be
  isolated and testable, and the caveat is user-visible.

## Alternatives considered

* **`INetFwPolicy2` / `New-NetFirewallRule` / `netsh advfirewall` (Windows).**
  Rejected: no weight arbitration, no LUID-scoped interface match, no
  transactional install, no boot-time filter, machine-wide
  `DefaultOutboundAction` mutation, GPO-overridable, and dependent on the
  Windows Firewall service. Kept only for optional host-firewall interop and
  tests.
* **A kernel-mode WFP callout driver (Windows).** Rejected for v1: it is the
  only way to *redirect* (ADR-0007), but it drags in an EV certificate, a
  Microsoft Hardware Dev Center account, attestation signing and multi-week
  per-release certification — an enormous cost for permit/block behaviour that
  user-mode WFP already provides.
* **`iptables`/`ip6tables` (Linux).** Rejected: no atomic whole-ruleset
  replacement, no `socket cgroupv2`, and dual-stack drift is a known leak
  source. May be used only as a legacy fallback, documented as weaker.
* **Writing the kill switch into `/etc/nftables.conf` (Linux).** Rejected: a
  boot without the VPN would have no connectivity, and it violates the "never
  leave state behind" rule.
* **`nft destroy` / newer nftables syntax.** Rejected: not available on the
  validated baseline (nftables 1.0.2), which is the target floor.
* **A `NEPacketTunnelProvider` with `includeAllNetworks` + `enforceRoutes` for
  the macOS kill switch.** Rejected for v1: entitlement-gated, native-only,
  user-approval-gated, and it makes third-party builders unable to run the
  tunnel from source. It is the natural upgrade if the project ever obtains the
  entitlement, which is why `IKillSwitch` isolates the PF implementation.
* **`NETransparentProxyProvider` (macOS).** Rejected: it ignores `NEDNSSettings`
  and `NEProxySettings`, non-proxied flows fail **open** (returning `NO` lets the
  flow proceed directly), it is scoped by network rules rather than process, and
  it is equally entitlement-gated.
* **`pfctl -d`/`-e` (macOS).** Rejected: `-d` destroys every other enabler's
  token and stomps the Application Firewall, which enables PF via `-E` and owns
  the `com.apple/250.ApplicationFirewall` anchor. `-e` holds no reference.
* **A "self-disabling" kill switch that tears itself down if the helper dies.**
  Rejected: it converts a protection failure into a leak. The correct failure
  direction is "no network", with automatic repair.

## References

* `docs/research/06-windows-networking.md` — §1.1 (why WFP over
  `INetFwPolicy2`/`netsh`; the capability table; the WireGuard reference recipe;
  sub-layer weight `0xFFFF`; the persistent/boot-time `serviceName` trap;
  `CLEAR_ACTION_RIGHT` ambiguity; `FWP_EMPTY` on reauthorisation), §2.3 (two
  modes, one recipe), §2.4 (connect/disconnect ordering), §2.5 (C# interfaces),
  §2.6 (what cannot be done reliably), R1, R2, R4, R15.
* `docs/research/07-linux-networking.md` — §1.2 (`socket cgroupv2` caveat),
  §1.3 (atomicity, marks, chain types, `iifname`/`oifname`), §2.1 (TUN lifecycle
  and crash cleanup), §2.2 (the kill-switch ruleset, the `fwd` reserved name,
  the `destroy` rejection, atomic endpoint-set replacement), §2.5 (systemd
  hardening), §3 R-2, R-3, R-4, R-10.
* `docs/research/08-macos-networking.md` — §1.3 (TN3165 "Packet Filter is not
  API"; `pfctl -E`/`-X` token semantics and the `DIOCSTOP` hazard; preserving
  Apple's anchors; SIP facts; the validated ruleset), §2.3 (bring-up/tear-down
  ordering and invariants), §3 R5, R6.
* `docs/research/03-xray-tun-inbound.md` §1.3/§1.4 (elevation requirements),
  §1.7 (the loop problem the kill switch must not create).
* Existing architecture: `src/MyVpn.Core/Domain/VpnConnectionState.cs`
  (`RequiresKillSwitch`), `src/MyVpn.Core/Domain/Enums.cs` (`KillSwitchMode`),
  `src/MyVpn.Core/Results/ErrorCodes.cs` (`killswitch.*`),
  `src/MyVpn.Platform.Abstractions/MyVpn.Platform.Abstractions.csproj`
  (`IKillSwitch` + pure renderers).
* Primary sources: WFP reference (`FwpmEngineOpen0`, `FwpmProviderAdd0`,
  `FwpmSubLayerAdd0`, `FwpmFilterAdd0`, `FwpmTransaction*`,
  `FWPM_PROVIDER0`, `FWPM_CONDITION_*`, `FWPM_FILTER_FLAG_BOOTTIME`)
  <https://learn.microsoft.com/windows/win32/fwp/>; nftables
  <https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement>;
  `nft(8)`; `pfctl(8)` and `pf.conf(5)`
  <https://keith.github.io/xcode-man-pages/>; Apple TN3165
  <https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api>;
  XNU `bsd/net/pf_ioctl.c`.
* ADR-0005 (privileged helper), ADR-0007 (process routing), ADR-0011
  (transport/DNS and NAT strategy).
