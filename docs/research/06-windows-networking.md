# 06 — Windows Platform Networking (Windows 10 / Windows 11, x64 + arm64)

**Project:** MyVpn — cross-platform Xray VPN client (.NET 8)
**Scope of this document:** the authoritative Windows platform design for
(1) the WFP Kill Switch, (2) Wintun / the TUN data path, (3) the privileged service and local IPC,
(4) per-process routing, (5) routing-table manipulation, (6) DNS configuration, (7) the system proxy,
(8) code signing and packaging — plus concrete C# service interfaces, risks, an implementation plan,
affected modules and a test plan.

**Research method / confidence legend.** Every API claim below is backed by a primary source
(Microsoft Learn, or the official project repository for open-source components). Because the research
host is Linux, **no Windows code was executed and no API was empirically tested**; findings are
source-derived. Claims that could not be confirmed against a primary source are explicitly marked
`UNVERIFIED`. API names are copied from documentation — if a signature could not be confirmed, that is
stated rather than guessed. Known documentation ambiguities are called out (there is one important one
in §1.1.6).

---

## 1. Findings

### 1.1 Kill Switch via the Windows Filtering Platform (WFP)

#### 1.1.1 What is actually usable from .NET — and what is not

This was investigated explicitly, because the task brief contained two candidate hypotheses that turn
out to be wrong.

| Candidate | Verdict | Evidence |
|---|---|---|
| `Windows.Networking.Vpn` (WinRT) | **Not usable for MyVpn's kill switch.** It is the *Windows VPN platform plugin* API for building an OS-integrated VPN plugin. It requires the `networkingVpnProvider` **restricted capability**, i.e. a packaged (MSIX/Store-style) app with Microsoft-granted capability, and it manages the *OS VPN profile*, not a third-party TUN client's firewall. It provides no per-app WFP kill switch. | [Windows.Networking.Vpn Namespace](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn) — "To use the classes in this namespace, you must declare the **networkingVpnProvider** restricted capability." See also [`VpnChannel`](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnchannel). |
| `Microsoft.Windows.WFP` (a managed WFP namespace) | **Does not exist.** There is no Microsoft-supported managed wrapper for the WFP engine. Any .NET implementation must P/Invoke `fwpuclnt.dll`. | The WFP reference is explicitly C/C++: "The Windows Filtering Platform API is designed for use by programmers using C/C++ development software." — [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page). All functions are exported from `Fwpuclnt.dll` / link `Fwpuclnt.lib`. |

So there are exactly three realistic mechanisms, and only two of them are viable:

1. **P/Invoke to `fwpuclnt.dll`** — the full WFP management API (`FwpmEngineOpen0`, `FwpmProviderAdd0`,
   `FwpmSubLayerAdd0`, `FwpmFilterAdd0`, `FwpmTransactionBegin0`/`Commit0`/`Abort0`, `FwpmGetAppIdFromFileName0`,
   `FwpmEngineClose0`, plus the `Fwpm*DeleteByKey0` teardown calls).
2. **`INetFwPolicy2` / `INetFwRule` (the Windows Firewall COM API)** — can be consumed from .NET via COM
   interop (`[ComImport]` or the legacy `NetFwTypeLib` reference). Documented at
   [`INetFwPolicy2`](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2) and
   [`INetFwRule`](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule).
3. **`netsh advfirewall` / `New-NetFirewallRule`** — process-spawning wrappers over the same policy store as (2).

**Definitions confirmed as real WFP management functions** (headers `fwpmu.h`, library `Fwpuclnt.lib`,
DLL `Fwpuclnt.dll`), all found in the official
[Management Functions](https://learn.microsoft.com/en-us/windows/win32/fwp/fwp-mgmt-functions) index:

*Session/transaction:* `FwpmEngineOpen0`, `FwpmEngineClose0`, `FwpmTransactionBegin0`,
`FwpmTransactionCommit0`, `FwpmTransactionAbort0`.
*Objects:* `FwpmProviderAdd0`, `FwpmProviderDeleteByKey0`, `FwpmSubLayerAdd0`, `FwpmSubLayerDeleteByKey0`,
`FwpmFilterAdd0`, `FwpmFilterDeleteByKey0`, `FwpmFilterDeleteById0`, `FwpmFilterEnum0`,
`FwpmFilterCreateEnumHandle0`, `FwpmGetAppIdFromFileName0`, `FwpmFreeMemory0`.

`FwpmEngineOpen0` requires `FWPM_ACTRL_OPEN` on the filter engine and must be called before any other
object is added; a `NULL` session pointer uses defaults, and `FWPM_SESSION_FLAG_DYNAMIC` makes every object
added during the session self-delete when the session ends
([FwpmEngineOpen0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0),
[FWPM_SESSION0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0)).

#### 1.1.2 Why WFP beats `INetFwPolicy2` for a kill switch

The decisive facts:

* **Windows Firewall rule precedence makes "block all except X" impossible to express with a block rule.**
  Microsoft states plainly: "Explicit block rules take precedence over any conflicting allow rules" and
  "Windows Firewall doesn't support weighted, administrator-assigned rule ordering."
  ([Windows Firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)).
  Therefore the *only* way to build a fail-closed firewall through `INetFwPolicy2` is
  `INetFwPolicy2::put_DefaultOutboundAction(NET_FW_ACTION_BLOCK)` plus allow rules. That is a
  **machine-wide, user-visible mutation of the host firewall default posture**, it is subject to Group
  Policy override ("the effective result may differ due to group policy settings" —
  [`get_FirewallEnabled`](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_firewallenabled),
  and the `LocalPolicyModifyState` property exists specifically to tell you a local change will not take
  effect), and it cannot be made interface-LUID-aware.
* **`INetFwRule` has no interface-LUID and no local/next-hop interface condition.** Its full property set is
  `Action, ApplicationName, Description, Direction, EdgeTraversal, Enabled, Grouping, IcmpTypesAndCodes,
  Interfaces, InterfaceTypes, LocalAddresses, LocalPorts, Name, Profiles, Protocol, RemoteAddresses,
  RemotePorts, ServiceName` ([INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)).
  `Interfaces` is an array of *friendly names*, and `InterfaceTypes` only accepts `RemoteAccess | Wireless |
  Lan | All`. There is **no** way to say "the interface this connection will egress on is the TUN adapter",
  which is the exact predicate a split-tunnel-safe kill switch needs.
* **`INetFwRule` edits are non-atomic and committed rule-by-rule.** "Each time you change a property of a
  rule, Windows Firewall commits the rule and verifies it for correctness … when you edit a rule, you must
  perform the steps in a specific order" ([INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)).
  WFP, by contrast, is explicitly transactional and ACID: "Transactions are either read-only or read/write
  and enforce rigorous Atomic Consistent Isolated Durable (ACID) semantics", and a failed operation lets you
  abort the whole set ([Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)).
  For a kill switch, an install that half-applies is a leak or a lockout.
* **`INetFwPolicy2` cannot express weight-based arbitration or hard/soft actions**, cannot be scoped to a
  sub-layer, and cannot install a boot-time filter. WFP has all three
  ([Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration),
  [FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)).
* **`INetFwPolicy2` requires the Windows Firewall service** ("The Windows Firewall/Internet Connection
  Sharing service must be running to access this interface") and its rules live in the MpsSvc sub-layer,
  `FWPM_SUBLAYER_MPSSVC_WF`
  ([Filtering sublayer identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/management-filtering-sublayer-identifiers)).
  A third-party kill switch that depends on the user's host firewall being enabled is not fail-closed: the
  user (or a *different* VPN client, or a domain GPO) can disable it underneath you.
* **`netsh advfirewall` / `New-NetFirewallRule` inherit every `INetFwRule` limitation plus localization and
  parsing hazards.** They are the right tools for *optional* host-firewall interoperability (§2.6) and for
  tests, not for the kill switch.

WFP is also what Windows Firewall itself is built on, which means the same arbitration logic, the same
sub-layer weighting, and no "two firewalls fighting" behaviour: "the firewall application that is built
into Windows Vista … Windows Firewall with Advanced Security (WFAS) is implemented using WFP. Therefore,
applications developed with the WFP API or the WFAS API use the common filtering arbitration logic that is
built into WFP." ([Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)).

Capability comparison:

| Capability | WFP (`fwpuclnt.dll`) | `INetFwPolicy2` | `netsh advfirewall` |
|---|---|---|---|
| Per-application match | Yes — `FWPM_CONDITION_ALE_APP_ID` (path-derived blob) | Yes — `ApplicationName` (full path only, no wildcards) | Yes — `program=` (same limits) |
| Per-interface match by **LUID** | **Yes** — `FWPM_CONDITION_IP_LOCAL_INTERFACE` (LUID) at `ALE_AUTH_CONNECT` | **No** (friendly names / IANA type only) | **No** |
| Per-interface by friendly name | Possible | Yes — `Interfaces` | Yes — `interface=` |
| Protocol / port match | Yes (`FWPM_CONDITION_IP_PROTOCOL`, `..._PORT`) | Yes | Yes |
| "Block all except tunnel" atomically | **Yes** — one max-weight sub-layer, block at weight 0, permits above it | Only by mutating `DefaultOutboundAction`, and block rules then beat your allows | Same as COM |
| Transactional install | Yes (ACID) | No | No |
| Atomic boot-time enforcement (before BFE) | **Yes** — `FWPM_FILTER_FLAG_BOOTTIME` | No | No |
| Survives service crash | Yes (persistent objects) | Yes (rules are stored policy) | Yes |
| Fails closed if service dies | Configurable: dynamic session = **fails open**; persistent = fails closed | Yes | Yes |
| Direction | Full layers incl. IP packet, transport, ALE, stream | Inbound/Outbound only | Inbound/Outbound only |
| Needs Windows Firewall service | No (needs BFE) | **Yes** | **Yes** |
| Per-process *routing* (redirect into tunnel) | No (needs kernel callout); connection-policy API is the exception — see §1.4 | No | No |

#### 1.1.3 The reference implementation to imitate

The most useful primary source is WireGuard's own Windows client, which implements a production WFP kill
switch in user mode from a service. Its code is MIT-licensed and readable at
`wireguard-windows/tunnel/firewall/`:

* [`blocker.go`](https://raw.githubusercontent.com/WireGuard/wireguard-windows/master/tunnel/firewall/blocker.go)
* [`rules.go`](https://raw.githubusercontent.com/WireGuard/wireguard-windows/master/tunnel/firewall/rules.go)
* [`helpers.go`](https://raw.githubusercontent.com/WireGuard/wireguard-windows/master/tunnel/firewall/helpers.go)

What it concretely does (all facts read from the source above):

1. Opens a **dynamic** session: `wtFwpmSession0{ flags: cFWPM_SESSION_FLAG_DYNAMIC, txnWaitTimeoutInMSec: windows.INFINITE }`,
   then `fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, &handle)`.
2. Inside `fwpmTransactionBegin0` → `fwpmTransactionCommit0`, with `fwpmTransactionAbort0` on any error,
   it registers a provider (`fwpmProviderAdd0`) and a sub-layer (`fwpmSubLayerAdd0`) with
   **`weight: ^uint16(0)` (0xFFFF, maximum sub-layer weight)**.
3. It adds, at both `FWPM_LAYER_ALE_AUTH_CONNECT_V{4,6}` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V{4,6}`:

   | Filter | Weight | Conditions | Action |
   |---|---|---|---|
   | Permit the VPN service itself | 15 | `ALE_APP_ID` = own exe + `ALE_USER_ID` = own service SID security descriptor | `FWP_ACTION_PERMIT` (+ `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`) |
   | Permit DNS to configured servers | 15 (allow) / 14 (deny) | protocol UDP **or** TCP, remote port 53, `remote addr == allowed` | `PERMIT` above `BLOCK` |
   | Permit loopback | 13 | `FWPM_CONDITION_FLAGS` `FWP_MATCH_FLAGS_ALL_SET` `FWP_CONDITION_FLAG_IS_LOOPBACK` | `PERMIT` |
   | Permit the TUN interface | 12 | `FWPM_CONDITION_IP_LOCAL_INTERFACE == <TUN LUID>` | `PERMIT` |
   | Permit DHCP / NDP | 12 | protocol+ports+link-local multicast addresses | `PERMIT` |
   | **Block everything else** | **0** | *no conditions* | `FWP_ACTION_BLOCK` |

4. Because filter arbitration within a sub-layer evaluates matching filters from **highest weight to
   lowest** and stops at the first terminating action, every permit above "wins" and everything that
   matches nothing falls through to the weight-0 block. That is precisely fail-closed
   ([Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration),
   [Filter Weight Assignment](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment)).
5. `permitTunInterface` proves the key predicate is real: `FWPM_CONDITION_IP_LOCAL_INTERFACE` with
   `FWP_UINT64` value = the TUN adapter LUID **is available at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`**
   (confirmed independently in
   [Filtering conditions available at each filtering layer](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer),
   where `FWPM_CONDITION_IP_LOCAL_INTERFACE` is listed for `ALE_AUTH_CONNECT_V4` and `..._V6`).
6. `permitWireGuardService` adds **two** conditions — `ALE_APP_ID` *and* `ALE_USER_ID` — with the explicit
   comment that the second "prevents other processes hosted in the same exe from matching this filter".
   This is an important, easily-missed hardening point: `ALE_APP_ID` is a *path*, not a process identity, so
   any second process running the same image would otherwise inherit the tunnel exemption.

The sub-layer weight `0xFFFF` matters for a different reason than blocking: a **hard permit** at the highest
sub-layer cannot be overridden by a lower-priority sub-layer's block (see §1.1.6 for the ambiguity), and it
guarantees our arbitration runs first regardless of what else is installed on the machine.

#### 1.1.4 Concrete call sequence to install a fail-closed filter set

The following is the MyVpn sequence, adapted from the WireGuard pattern (which is the only
production-grade, primary-sourced user-mode example found). It runs **only in the SYSTEM service** (§1.3).
GUIDs marked `{FIXED}` are compile-time constants persisted in the app so that teardown and diagnostics do
not depend on runtime state; `{RUNTIME}` are generated per connect.

```
// 0. Preconditions
//    - BFE service (Base Filtering Engine) running; caller has FWPM_ACTRL_* rights (SYSTEM/Administrators).
//    - TUN adapter already created and its LUID known (WintunCreateAdapter + WintunGetAdapterLuid / GetAdaptersAddresses).
//    - The xray.exe path is final and file-ACL-protected; ALE_APP_ID is computed from that exact path.

// 1. Open engine session
FWPM_SESSION0 session = { .displayData = {"MyVpn", "kill switch"}, .flags = FWPM_SESSION_FLAG_DYNAMIC,
                          .txnWaitTimeoutInMSec = INFINITE };
FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
//    (strict/persistent mode instead uses flags = 0 — see 1.1.5.)

// 2. Begin one transaction: the whole policy is installed atomically or not at all
FwpmTransactionBegin0(engineHandle, 0);

// 3. Provider (must carry serviceName for persistent mode)
FWPM_PROVIDER0 provider = { .providerKey = {FIXED}, .displayData = {"MyVpn","MyVpn WFP provider"},
                            .flags = FWPM_PROVIDER_FLAG_PERSISTENT /* strict mode only */,
                            .serviceName = L"MyVpnSvc" /* strict mode only */ };
FwpmProviderAdd0(engineHandle, &provider, NULL);

// 4. Sub-layer — maximum weight so MyVpn arbitration is evaluated first
FWPM_SUBLAYER0 sub = { .subLayerKey = {FIXED}, .displayData = {"MyVpn","MyVpn kill switch"},
                       .providerKey = &provider.providerKey,
                       .flags = FWPM_SUBLAYER_FLAG_PERSISTENT /* strict mode only */,
                       .weight = 0xFFFF };
FwpmSubLayerAdd0(engineHandle, &sub, NULL);

// 5. Application identity blobs
FWP_BYTE_BLOB* xrayAppId;  FwpmGetAppIdFromFileName0(L"C:\\Program Files\\MyVpn\\xray.exe", &xrayAppId);
FWP_BYTE_BLOB* svcAppId;   FwpmGetAppIdFromFileName0(L"C:\\Program Files\\MyVpn\\MyVpnSvc.exe", &svcAppId);

// 6. Permits (each added at both ALE_AUTH_CONNECT_V4 and ALE_AUTH_CONNECT_V6;
//    inbound permits are added at ALE_AUTH_RECV_ACCEPT_V4/V6 as needed)
//    weight is FWP_UINT8 0..15 -> the 16 weight ranges, per Filter Weight Assignment.
PERMIT(weight 15, ALE_APP_ID == xrayAppId)                     // the tunnel client
PERMIT(weight 15, ALE_APP_ID == svcAppId)                      // the service's own control/telemetry
PERMIT(weight 14, IP_PROTOCOL == TCP|UDP, IP_REMOTE_PORT == 53,
                  IP_REMOTE_ADDRESS == <each configured resolver>)   // leaktight DNS
PERMIT(weight 13, FLAGS & FWP_CONDITION_FLAG_IS_LOOPBACK)      // 127.0.0.0/8 + ::1 for the local proxy
PERMIT(weight 12, IP_LOCAL_INTERFACE == <TUN LUID>)            // anything routed into the tunnel
PERMIT(weight 12, DHCP v4/v6 and ICMPv6 NDP 133/134/135/136/137 as in WireGuard rules.go)

// 7. The fail-closed catch-all, lowest weight inside our sub-layer
BLOCK (weight  0, no conditions)  at ALE_AUTH_CONNECT_V4, ALE_AUTH_CONNECT_V6,
                                        ALE_AUTH_RECV_ACCEPT_V4, ALE_AUTH_RECV_ACCEPT_V6

// 8. Commit or abort
FwpmTransactionCommit0(engineHandle);   // on any failure above: FwpmTransactionAbort0(engineHandle)

// 9. Public server IP protection (recommended, before step 7 in effect ordering terms):
//    permit the encrypted transport to the server regardless of interface, e.g.
PERMIT(weight 15, ALE_APP_ID == xrayAppId, IP_REMOTE_ADDRESS == <server IP set>)  // already covered by 15 above

// 10. Optional defence-in-depth for hard fail-closed (see 1.1.6 "packet-layer backstop"):
BLOCK (weight 0) at FWPM_LAYER_OUTBOUND_IPPACKET_V4 / _V6 with no conditions,
in a SECOND sub-layer of lower weight, plus
PERMIT(weight 15) same layer, IP_REMOTE_ADDRESS == <server IP set>,
PERMIT(weight 14) same layer, IP_LOCAL_INTERFACE == <TUN LUID>,
PERMIT(weight 13) same layer, link-local / DHCP / NDP addresses.

// 11. Teardown on explicit user disconnect (strict mode only)
FwpmFilterDeleteByKey0 / FwpmSubLayerDeleteByKey0 / FwpmProviderDeleteByKey0
FwpmEngineClose0(engineHandle)   // dynamic-session objects disappear automatically
```

Notes and constraints that must be honoured:

* `FWP_MATCH_EQUAL` on `FWP_BYTE_BLOB_TYPE` for `ALE_APP_ID` and `FWP_BYTE_BLOB_TYPE` for
  `ALE_USER_ID` (security descriptor) is shown in the official example
  ([FWPM_FILTER_CONDITION0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0)).
  `FwpmGetAppIdFromFileName0` documents that the returned blob must be freed with `FwpmFreeMemory0`, and the
  app-id is "the lower-case fully qualified device path" such as
  `\device\harddiskvolume1\program files\application.exe`
  ([FwpmGetAppIdFromFileName0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0),
  [Filtering condition identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)).
* Filters use `weight.type = FWP_UINT8` with values 0–15 to partition the weight space into 16 ranges and
  auto-weight within a range; this is exactly what WireGuard does and is documented
  ([Filter Weight Assignment](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment)).
* The `FWPM_ACTION0::filterType` GUID is required for non-callout actions (a zero GUID is used in practice;
  the documentation says it is "an arbitrary GUID chosen by the policy provider" —
  [FWPM_ACTION0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0)).
* A caller needs `FWPM_ACTRL_ADD` on the container plus `FWPM_ACTRL_ADD_LINK` on the layer, sub-layer,
  provider, callout and provider-context it references
  ([FwpmFilterAdd0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0),
  [Access control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)).
* `FwpmFilterAdd0` "cannot be called from within a read-only transaction. It will fail with
  `FWP_E_INCOMPATIBLE_TXN`" — hence `FwpmTransactionBegin0(handle, 0)` (read/write)
  ([FwpmFilterAdd0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0)).
* **Existing connections are re-evaluated, but only when they next carry a packet.** "A policy change is
  implemented as a filter addition or removal at an ALE layer. Once a policy change is detected, the first
  packet that traverses an ALE flow created at the affected layer will be specified for reauthorization to
  the layer" ([ALE Reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)).
  So installing the kill switch does effectively tear down pre-existing flows on their next packet — but a
  flow that is idle stays alive in the table and is only re-verified when it resumes. If an immediate,
  unconditional cut is required, the packet-layer backstop in step 10 evaluates *every* packet.
* ALE reauthorization can be identified and explicitly denied by matching
  `FWP_CONDITION_FLAG_IS_REAUTHORIZE` or `FWPM_CONDITION_ALE_REAUTH_REASON`; note the documented trick that
  "Fields of type `FWP_EMPTY` can be matched with `FWP_MATCH_EQUAL`, therefore a policy can be set to block
  reauthorizations and tear down an ALE flow"
  ([ALE Reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization),
  [Filtering condition flags](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-flags-)).
* **`0xFFFF` sub-layer weight does not let a permit override a block.** Arbitration is: within a layer,
  every sub-layer is evaluated from highest weight to lowest, then the actions are combined; a hard block
  cannot be overridden ([Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)).
  This is the safe direction — corporate/domain firewall blocks on the user's machine are *not* bypassed by
  MyVpn — but it also means MyVpn **cannot rescue a process the host firewall blocks**, and support should
  say so.

#### 1.1.5 Persistence across reboot — persistent filters vs re-installing at boot

The documentation distinguishes four object lifetimes
([Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)):

| Lifetime | Survives BFE stop/start | Survives reboot | Set by |
|---|---|---|---|
| Dynamic | No (dies with session) | No | `FWPM_SESSION_FLAG_DYNAMIC` |
| Static (default) | No | No | default |
| **Persistent** | **Yes** | **Yes** | `FWPM_*_FLAG_PERSISTENT` on provider/sublayer/filter |
| **Boot-time** | n/a — removed when BFE finishes init | Yes (re-added at each boot) | `FWPM_FILTER_FLAG_BOOTTIME` |

Two critical, directly quoted constraints:

1. **`PERSISTENT` and `BOOTTIME` are mutually exclusive *on the same filter*:** "`FWPM_FILTER_FLAG_PERSISTENT`
   … **Note** This flag cannot be set together with `FWPM_FILTER_FLAG_BOOTTIME`" and vice versa
   ([FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)).
   To get both, you add **two equivalent filters**, one with each flag.
2. **The boot-time → persistent transition is gapless:** "The transition from boot-time to persistent filters
   could be several seconds, or even longer on a slow machine. **It is atomic, so if a provider has both a
   boot-time and a persistent filter, there will never be a window when neither is in effect.**"
   ([WFP Operation](https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation)). A boot-time
   filter "is enforced at boot-time as soon as the TCP/IP stack driver (tcpip.sys) starts" and "is disabled
   when BFE starts" (same page).

**The trap that breaks naive persistence:** persistent filters are silently **disabled** at boot unless the
owning provider names an auto-start service. Both the provider and filter documentation say this:

> "At start, the BFE only adds the following types of persistent objects to the system: the object is not
> associated with a provider; the object has an associated provider that does not specify a service name;
> the object has an associated provider and an associated service set to auto-start."
> — [FwpmProviderAdd0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmprovideradd0);
> identical wording in [Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)
> and [FWPM_PROVIDER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0).

If that happens, BFE reports `FWPM_PROVIDER_FLAG_DISABLED` / `FWPM_FILTER_FLAG_DISABLED` on enumeration
(those flags "cannot be set when adding new providers/filters. It can only be returned by BFE when getting or
enumerating"). **MyVpn must therefore: (a) set `FWPM_PROVIDER0.serviceName = L"MyVpnSvc"`, (b) install the
service with `SERVICE_AUTO_START`, and (c) at startup enumerate its own filters and log/alert if any come
back disabled.**

Additional persistence constraints:

* **A persistent object cannot reference a dynamic or static object, or a persistent object owned by a
  different provider** ([Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)).
  Consequence: in strict mode the *provider*, the *sub-layer* and every *filter* must all be persistent and
  all owned by the same provider. You cannot mix a persistent block filter with a dynamic permit filter.
* **Boot-time filters are only classifiable at kernel-mode layers and with a boot-time-available condition
  set.** "Filters in kernel-mode layers can be marked as boot-time filters by passing the appropriate flag to
  `FwpmFilterAdd0`" ([Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management));
  the boot-time policy can be inspected with `netsh wfp show boottimepolicy`
  ([netsh wfp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wfp)).
  `UNVERIFIED:` which *conditions* are classifiable before BFE starts (in particular whether ALE conditions
  such as `FWPM_CONDITION_ALE_APP_ID` resolve at boot, and whether a pure user-mode process may successfully
  add a `BOOTTIME` filter at the ALE layers rather than only at the IP-packet layers). No primary source was
  found that states this either way, and the research process could not test it. **Design assumption to
  validate on hardware:** the boot-time companion filter should use only IP-layer conditions
  (`FWPM_LAYER_OUTBOUND_IPPACKET_V4/V6` with `IP_REMOTE_ADDRESS` = server IPs plus `IP_LOCAL_INTERFACE` =
  TUN LUID), which do not depend on ALE identity resolution.
* `netsh wfp dump` exists to snapshot the whole configuration and recreate it, which is the supported escape
  hatch if MyVpn ever leaves the machine in a bad state
  ([netsh wfp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wfp)).

**Recommended persistence model (two modes, explicit in the UI):**

| Mode | Session flags | Object flags | If `MyVpnSvc` crashes | Across reboot | Use |
|---|---|---|---|---|---|
| **Kill switch (default)** | `FWPM_SESSION_FLAG_DYNAMIC` | none | Filters vanish → **fails open**; tunnel is also gone | None | Ordinary "block non-tunnel traffic while connected" — WireGuard's model |
| **Lockdown (opt-in, "always-on")** | `0` (non-dynamic) | `PERSISTENT` on provider+sublayer+filters, `serviceName = MyVpnSvc`; plus an equivalent `BOOTTIME` filter set | Filters **remain** → fail-closed | Filters re-added by BFE at boot | Corporate/leak-paranoid users; must be explicitly disabled |

Lockdown mode must be paired with (i) an auto-start service, (ii) a "panic release" path that a local
administrator can invoke (`netsh wfp dump`/delete-by-key, or a documented CLI switch) so a broken policy can
never lock a machine out of the network permanently, and (iii) a startup self-check that enumerates and
reports any `*_FLAG_DISABLED` objects.

#### 1.1.6 What WFP cannot do, and known limitations / ambiguities

* **User-mode WFP filters cannot redirect traffic into a tunnel.** A `FWP_ACTION_*` filter can only permit or
  block (or call a callout). Packet/stream modification and reinjection — the mechanism a redirect needs —
  require a **kernel-mode callout driver** ("A *callout* is a set of functions exposed by a driver …
  Callouts can be registered at any of the kernel-mode WFP layers … can modify and secure inbound and
  outbound network traffic" — [WFP Operation](https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation),
  and [Introduction to WFP Callout Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-windows-filtering-platform-callout-drivers)).
  Real-world confirmation: Mullvad's split-tunnel product on Windows is a **driver**
  ([mullvad/win-split-tunnel](https://github.com/mullvad/win-split-tunnel), "Mullvad split tunnel driver for
  Windows"). MyVpn's routing must therefore be done by the **route table** plus the TUN adapter, not by WFP.
* **"Block all except the tunnel" is expressible, but "route app X through the tunnel" is not** — the latter
  is §1.4 and is done with the route table + `FwpmConnectionPolicyAdd0` (or not at all without a driver).
* **A hard block cannot be overridden, including by MyVpn.** Already covered above; it is a feature and a
  support-burden.
* **`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` semantics are documented inconsistently — treat as ambiguous.**
  The structure page lists it neutrally as "Clear filter action right"
  ([FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)),
  while the arbitration page says "Along with the action type, a filter also exposes the flag
  `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`. **If this flag is cleared, then the action type is hard** and cannot
  be overridden except when a hard permit is overridden by a Veto … else it is soft"
  ([Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)). The same
  page also states that setting `FWPS_RIGHT_ACTION_WRITE` *allows* override, which implies setting
  `CLEAR_ACTION_RIGHT` makes an action *hard*. The two readings contradict each other.
  `UNVERIFIED`. **Design decision:** do not depend on this flag. The MyVpn policy's fail-closed property
  comes from the weight-0 catch-all block inside our own maximum-weight sub-layer, which works under either
  reading. If the flag is used at all (WireGuard sets it on the service permit), it must be tested on
  hardware before shipping.
* **`FWPM_CONDITION_IP_LOCAL_INTERFACE` may be `FWP_EMPTY` in some classifications.** The ALE
  reauthorization page warns that "Some classifiable fields may be unknown during reauthorization … the
  values of the unknown fields are indicated as `FWP_EMPTY`" and that an outbound packet can be
  reauthorized at `ALE_AUTH_RECV_ACCEPT`, where arrival-interface fields are unknown
  ([ALE Reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)). A
  TUN-interface permit that does not match will fall through to the block — fail-closed, but it can break
  split tunnelling or cause a connectivity drop on reconnect. This is a **must-test** case.
* **`ALE_APP_ID` identifies a path, not a process.** Any process executing the same image at the same path
  matches. Mitigations: add the `ALE_USER_ID` security-descriptor condition (WireGuard's approach), protect
  the install directory with a restrictive ACL, and verify the image signature at launch.
* **Compartment / container traffic, IPsec, and kernel-mode network components** are not automatically
  covered by ALE filters. The `FWPM_CONDITION_COMPARTMENT_ID` condition exists for exactly this kind of
  scoping ([Filtering condition identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)).
  `UNVERIFIED:` a complete coverage matrix for WSL2/Hyper-V/Windows Sandbox/AppContainer traffic; the
  packet-layer backstop is the recommended mitigation and must be tested.
* **BFE outage = kill switch gone.** If the Base Filtering Engine service is stopped, dynamic *and*
  persistent WFP policy is inactive. MyVpn must monitor BFE state (there is a documented
  `FwpmBfeStateSubscribeChanges0` for kernel callers —
  [WFP Operation](https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation)) and surface a
  prominent "protection unavailable" state; a user-mode subscription equivalent was not confirmed.
  `UNVERIFIED`.
* **Nothing here is a substitute for a leak test.** The WFP policy must be validated by packet capture
  (`pktmon`, in-box: [pktmon](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon)),
  not by reading the firewall UI.

### 1.2 Wintun, and the Windows TUN data path

#### 1.2.1 Licensing — this constrains the product, read carefully

Wintun has **two distinct licences for two distinct artefacts**, and the common belief that it is
"GPL or MIT, pick one" is wrong.

| Artefact | Licence | Source |
|---|---|---|
| Wintun **source code** | **GPL-2.0** (`SPDX-License-Identifier: GPL-2.0`; README: "Source code is licensed under the GPLv2") | [COPYING](https://git.zx2c4.com/wintun/plain/COPYING), [README.md](https://git.zx2c4.com/wintun/plain/README.md) |
| Prebuilt, Microsoft-signed **`wintun.dll`** | **Proprietary "Prebuilt Binaries License"** — not GPL, not MIT | [prebuilt-binaries-license.txt](https://git.zx2c4.com/wintun/plain/prebuilt-binaries-license.txt), shipped in the zip as `LICENSE.txt` |

`UNVERIFIED:` whether the GPL-2.0 grant is "only" or "or later" — no "or later" wording was found, so treat
it as GPL-2.0-only.

**What this means for a closed-source MyVpn.** The prebuilt-binaries licence is the sanctioned distribution
path for commercial software, and it is permissive *for the intended use*: §3(d) forbids redistribution
"except insofar as the Software is distributed alongside other software that uses the Software **only via
the Permitted API**", where the Permitted API is the `wintun.h` interface set. MyVpn may therefore:

* bundle the **unmodified, arch-matched `wintun.dll`** taken from [wintun.net](https://www.wintun.net/)
  (0.14.1; zip SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`), **and**
* ship the accompanying `LICENSE.txt` next to it (inside the zip; Xray ships it as `LICENSE-wintun.txt`);

and must **not**: reverse-engineer / decompile / disassemble / **extract from** / modify it (§3(a)), create
derivative works other than through the API (§3(b)), strip notices (§3(c)), or imply WireGuard/Wintun
endorsement (§3(e)). The grant is non-exclusive and non-transferable (§2).

Three consequences that are easy to get wrong:

1. **Do not ship the `.sys`/`.cat` separately.** Official builds contain no loose driver files at all —
   `wintun.dll` embeds `wintun.sys`, `wintun.cat` and `wintun.inf` as resources and extracts them to a temp
   directory at install time ([api/driver.c](https://git.zx2c4.com/wintun/plain/api/driver.c),
   [api/resource.c](https://git.zx2c4.com/wintun/plain/api/resource.c)). Extracting and redistributing the
   driver is exactly the "extract from" that §3(a) prohibits, and the README adds: "Do not distribute
   drivers or files named 'Wintun', as they will most certainly clash with official deployments. Instead
   distribute `wintun.dll` as downloaded from wintun.net."
2. **Do not rename or patch it.** GPL-2.0 gives you the right to modify *source* and build your own driver,
   but that build is no longer the Microsoft-signed binary and will not load on modern Windows without your
   own Hardware Dev Center attestation-signed catalogue (§1.8), and it must not be named "Wintun".
3. **The driver is already signed by Microsoft**, which is the entire point: wintun.net states that "Due to
   Microsoft's driver signing requirements, we provide precompiled and signed versions that may be
   distributed with your software." The embedded catalogue chains to
   `Microsoft Windows Third Party Component CA 2012` → `Microsoft Windows Hardware Compatibility Publisher`,
   consistent with [attestation signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation).
   `UNVERIFIED:` certificate thumbprints/validity (no SignTool on the research host).

#### 1.2.2 Xray-core already uses Wintun and already bundles it

This removes most of the work, and it should drive the architecture.

* Xray-core pins `golang.zx2c4.com/wintun` and `golang.zx2c4.com/wireguard/windows` (for `winipcfg`) in
  [`go.mod`](https://github.com/XTLS/Xray-core/blob/main/go.mod). There is **no** TAP-Windows/OpenVPN
  dependency. The Windows TUN implementation is
  [`proxy/tun/tun_windows.go`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_windows.go):
  `wintun.CreateAdapter(name, desc, guid)` → `adapter.StartSession(0x800000)` (8 MiB ring) → a packet loop
  over `AllocateSendPacket`/`SendPacket` / `ReceivePacket`/`ReleaseReceivePacket` into a gVisor netstack,
  with IP/route/DNS/MTU configured through `winipcfg` (`SetIPAddressesForFamily`, `SetRoutesForFamily`,
  `SetDNS`, `ipif.NLMTU = options.MTU`, metric 0, router discovery/DAD disabled).
* Official Xray release archives **bundle the pristine Wintun DLL**: `Xray-windows-64.zip` contains a
  `wintun.dll` that is byte-identical to `wintun-0.14.1/bin/amd64/wintun.dll`, the arm64 archive contains the
  arm64 DLL, the 32-bit archive the x86 DLL, and each ships `LICENSE-wintun.txt`.
* Xray does **not** install a driver itself; it relies on `wintun.dll`'s `WintunCreateAdapter` auto-installing
  the embedded signed driver (which requires elevation). Its TUN README states the requirement: "`wintun.dll`
  specific for your Windows/arch must be present next to `Xray.exe` binary."
  ([proxy/tun/README.md](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/README.md)).
* Config surface: [`proxy/tun` docs](https://xtls.github.io/en/config/inbounds/tun.html) — `name`, `desc`
  (default `Wintun`), `mtu` (default 1500), `gateway`, `dns`, `autoSystemRoutingTable`,
  `autoOutboundsInterface`.

#### 1.2.3 What MyVpn must actually do

There are two viable architectures, and MyVpn should pick one deliberately:

**(A) MyVpn owns Wintun (P/Invoke `wintun.h`).** Maximum control; more code. Required steps:

1. Ship the pristine per-arch `wintun.dll` + `LICENSE.txt` in the installer next to `MyVpnSvc.exe`.
   x64 and arm64 are both fully supported — `bin/arm64/wintun.dll` exists and embeds an arm64
   `wintun.sys`/`.cat`. `desc` must be `"Wintun"` (Wintun's own documentation and Windows' driver
   name-matching expect it).
2. Run the owner **elevated / as SYSTEM**: `WintunCreateAdapter` eventually calls `SetupCopyOEMInfW`, and
   "A caller of this function is required have administrative privileges, otherwise the function fails"
   ([SetupCopyOEMInfW](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupcopyoeminfw)).
   Additionally the Wintun device object's DACL is reported to grant `FILE_ALL_ACCESS` only to
   `S-1-5-18` (SYSTEM) and `S-1-5-32-544` (Administrators), and `TUN_IOCTL_REGISTER_RINGS` performs a
   `SeAccessCheck(..., FILE_WRITE_DATA, ...)` before registering rings
   ([driver/wintun.c](https://git.zx2c4.com/wintun/plain/driver/wintun.c)). **`UNVERIFIED:`** — this was
   derived by decoding the security descriptor in the shipped binary, not from documentation. It has a
   design-critical consequence: see §1.3.6.
3. `WintunOpenAdapter`/`WintunCreateAdapter` → `WintunStartSession(adapter, capacity)`, capacity a power of
   two in `[0x20000, 0x4000000]`; **one session per adapter at a time**.
4. Drive the rings: block on `WintunGetReadWaitEvent` when `WintunReceivePacket` returns
   `ERROR_NO_MORE_ITEMS`; treat `ERROR_BUFFER_OVERFLOW` on send as a drop; always
   `WintunReleaseReceivePacket`.
5. Configure the interface **yourself** — Wintun does none of it: DHCP is disabled in the INF
   (`EnableDhcp = 0`), the driver advertises `MtuSize = 0xFFFF`, so MyVpn must set the IP address/prefix,
   the MTU (`NlMtu`, typically 1500 or 1420), disable router discovery/DAD, and add routes (§1.5) and DNS
   (§1.6).

**(B) MyVpn delegates the TUN to Xray's `tun` inbound** (ship `xray.exe` + `wintun.dll` +
`LICENSE-wintun.txt`, run it from the service, configure `protocol: "tun"`). Much less code and it tracks
Xray upstream; the cost is that MyVpn's route/DNS/MTU control becomes indirect (Xray's
`autoSystemRoutingTable`/`dns` settings) and Xray's TUN limitations become MyVpn's (the Xray TUN README
documents that its ICMP support is echo-only and that it answers local SYN-ACK by spoofing).

**Recommendation: (B) for v1, (A) only if a requirement genuinely cannot be met through Xray's inbound**
e.g. a custom split-tunnel routing model or precise MTU/route ownership. Note that (A) and (B) are not
mutually exclusive in the long run, but the Kill Switch (§1.1) must know the TUN adapter's **LUID** either
way, so the adapter-identification code is shared.

Key Wintun limitations to carry into the design:

* **Layer 3 only.** "A layer 3 TUN driver"; `NdisMediumIP`, no Ethernet/ARP/MAC/broadcast. Anything needing
  L2 (e.g. some multicast discovery, Wake-on-LAN tools) will not work through the tunnel.
* **Ring-buffer semantics** as above; a full send ring silently drops.
* **Single session per adapter.**
* **Install and session start require elevation** (SYSTEM/Administrators).
* **OS support:** the Wintun README lists Windows 7, 8, 8.1, 10 and 11; the arm64 driver targets Windows 10.
  (Note: the brief's hypothesis of a "Windows 10 1809+" requirement is not supported by Wintun's own docs.)
  `UNVERIFIED:` whether Xray's `winipcfg` code path imposes a higher minimum build than Wintun itself.
* **No NAT, no routing, no DNS, no MTU logic in the driver** — an adapter alone carries no traffic.

### 1.3 Privileged service and local IPC

#### 1.3.1 Service hosting on .NET 8

* Use the Generic Host with Windows Service lifetime:
  `Host.CreateApplicationBuilder().Services.AddWindowsService(...)` →
  `WindowsServiceLifetime`; the extension is context-aware and only activates when running as a service
  ([UseWindowsService](https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.hosting.windowsservicelifetimehostbuilderextensions.usewindowsservice)).
  `AddWindowsService` also sets the content root to `AppContext.BaseDirectory`
  ([Host an ASP.NET Core app in a Windows Service](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/windows-service)) —
  important because a service's working directory is `C:\WINDOWS\system32`, so **never** resolve assets via
  `GetCurrentDirectory()`.
* Classic `ServiceBase` remains available in .NET 8
  ([ServiceBase](https://learn.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicebase)) and is the
  base class of `WindowsServiceLifetime`; its only real advantage is SCM command handling
  (`OnCustomCommand`, pause/continue). `System.ServiceProcess.ServiceController` targets net8.0+ but is
  Windows-only. `UNVERIFIED:` whether `ServiceInstaller`/`ServiceProcessInstaller` are supported on modern
  .NET — install the service from the MSI/WiX instead.
* **Account choice.** Options and their documented trade-offs:

  | Account | Token contents | Notes |
  |---|---|---|
  | `LocalSystem` (S-1-5-18) | `NT AUTHORITY\SYSTEM` + `BUILTIN\Administrators`, extensive privileges | SCM-predefined, not resolvable via `LookupAccountName`. Microsoft: "Most services do not need such a high privilege level." ([LocalSystem Account](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)) |
  | `NT SERVICE\MyVpnSvc` (virtual service account) | Auto-managed, passwordless, per-service SID `S-1-5-80-<SHA1(upper name)>` present in the token and usable in ACLs | ([Service accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts)) |
  | `LocalService` / `NetworkService` | Reduced, network as the machine | Usually too weak for driver/adapter work |

  Service SID type is set with `ChangeServiceConfig2(SERVICE_CONFIG_SERVICE_SID_INFO)` / `sc sidtype`:
  `SERVICE_SID_TYPE_UNRESTRICTED` (0x1) or `SERVICE_SID_TYPE_RESTRICTED` (0x3). The restricted form also adds
  World (`S-1-1-0`), the service logon SID and the **write-restricted SID `S-1-5-33`**, and takes effect from
  the next boot
  ([SERVICE_SID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info),
  [ChangeServiceConfig2](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)).
  A write-restricted token is checked twice — "access check runs twice (enabled + restricting) and grants
  only if both allow"
  ([Restricted tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens),
  [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)).
* Harden the SCM descriptor: `sc sdset <name> <SDDL>` / `sc sdshow`
  ([sc sdset](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc742037(v=ws.11))).
  Grant non-admins only `SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_INTERROGATE`.
  Granting `SERVICE_CHANGE_CONFIG` or `SERVICE_STOP` to an untrusted principal is a documented
  privilege-escalation path
  ([Service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights),
  [ACE strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings)).
* **WFP needs the right ACE, not a specific account.** The WFP engine's default security descriptor grants
  `GENERIC_ALL` to Administrators, `GR/GW/GX` to the service SIDs `MpsSvc`, `NapAgent`, `PolicyAgent`,
  `RpcSs`, `WdiServiceHost`, and only `FWPM_ACTRL_OPEN` + `FWPM_ACTRL_CLASSIFY` to everyone; `FwpmEngineOpen0`
  requires `FWPM_ACTRL_OPEN`
  ([Access control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control),
  [Access right identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/access-right-identifiers)).
  So a dedicated `NT SERVICE\MyVpnSvc` must be granted ACEs on the WFP engine/filter containers
  (`Fwpm*SetSecurityInfo0`) before it can add filters, whereas `LocalSystem` inherits Administrators'
  `GENERIC_ALL`. **No Microsoft source states that WFP requires LocalSystem** — `UNVERIFIED`.
* **Driver access follows the device object's DACL, not the account name.** The I/O manager performs a full
  access check against the device's own security descriptor (`IoCreateDeviceSecure`, INF `Security` AddReg,
  `FILE_DEVICE_SECURE_OPEN`)
  ([Applying security descriptors on the device object](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/applying-security-descriptors-on-the-device-object),
  [Controlling device namespace access](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/controlling-device-namespace-access)).

#### 1.3.2 Named-pipe security

* `CreateNamedPipe` takes a `SECURITY_ATTRIBUTES`; if it is `NULL` the pipe receives the **default** SD,
  which grants full control to LocalSystem, Administrators and Creator Owner **and read access to Everyone
  and ANONYMOUS**; the same SD covers both ends
  ([CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea),
  [Named pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)).
  **Never accept the default.**
* Pipes live in `\\.\pipe\<name>`; if the Server service is running, **every named pipe is remotely
  reachable** unless you deny `NT AUTHORITY\NETWORK` or pass `PIPE_REJECT_REMOTE_CLIENTS` (0x00000008)
  ([Named pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes),
  [Pipe names](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names)).
* Client access is checked at `CreateFile`; creating an *instance* additionally needs
  `FILE_CREATE_PIPE_INSTANCE`. Read the SD with `GetSecurityInfo`, change it with `SetSecurityInfo`
  ([GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)).
* .NET specifics that will bite an implementer:
  * `PipeSecurity` (in `System.IO.Pipes.AccessControl`) is a `NativeObjectSecurity` holding DACL+SACL;
    `PipeAccessRule` is its ACE type
    ([PipeSecurity](https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.pipesecurity),
    [PipeAccessRule](https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.pipeaccessrule)).
  * On .NET Core/5+ the accessors are **extension methods**
    (`PipesAclExtensions.GetAccessControl/SetAccessControl(this PipeStream, …)`), not instance methods
    ([PipeStream.SetAccessControl](https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.pipestream.setaccesscontrol)).
  * **There is no `PipeSecurity` overload of the `NamedPipeServerStream` constructor on .NET Core** (that is
    .NET Framework-only). Use
    `NamedPipeServerStreamAcl.Create(name, direction, maxInstances, transmissionMode, options, inBuf, outBuf, pipeSecurity, inheritability, accessRights)`
    ([NamedPipeServerStreamAcl.Create](https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstreamacl.create)).
  * **`PipeOptions.CurrentUserOnly` silently ignores a supplied `PipeSecurity`** (same page).
    `PipeOptions.FirstPipeInstance` = 524288 and `CurrentUserOnly` = 536870912; on Windows `CurrentUserOnly`
    verifies **both account and elevation level** of the other end
    ([PipeOptions](https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.pipeoptions)).
  * To bind the pipe to the caller's *interactive logon session* rather than merely the user account, put
    the **logon SID** in the DACL — Microsoft's own guidance for excluding remote / other-session users
    ([Named pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)).
  * `PipeTransmissionMode.Message` exists but is Windows-only and is lost once a stream protocol (HTTP/2,
    gRPC) rides on top — **do not rely on it for framing**
    ([Named pipe type, read and wait modes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes)).

#### 1.3.3 Client-identity verification — the concrete anti-escalation gate

The server must identify the client process **before dispatching any command**. The complete documented
sequence:

| Step | API | Why |
|---|---|---|
| 1 | `GetNamedPipeClientProcessId(pipe, &pid)` | Returns a PID, **not** a handle; the `Pipe` must come from `CreateNamedPipe` ([doc](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)) |
| 2 | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` — **immediately**, and keep the handle | `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000) is "required to retrieve certain information about a process (… QueryFullProcessImageName)" and is allowed even against protected processes ([doc](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess), [process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)) |
| 3 | `QueryFullProcessImageNameW(handle, 0, …)` | Win32 image path (needs the same right) ([doc](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew)) |
| 4 | Path allow-list against the signed install directory (resolve to a canonical NT/device path, reject symlinks/junctions, compare case-insensitively) | The only check that stops a same-named binary in a writable directory |
| 5 | `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`, `WTD_UI_NONE`, `WTD_REVOKE_WHOLECHAIN`, `WTD_STATEACTION_VERIFY` then `_CLOSE`, `WTD_CHOICE_FILE` | Authenticode check of the image ([WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust), [WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data)). Returns a `LONG`; success is `== 0` **only**. Caveat: the PE signature does not cover every byte (checksum and certificate table are excluded), so `WinVerifyTrust` alone does not prove the on-disk image is byte-identical in those regions; `EnableCertPaddingCheck=1` tightens this ([Understanding PE signatures](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures)) |
| 6 | `OpenProcessToken(PROCESS_QUERY_LIMITED_INFORMATION, TOKEN_QUERY)` + `GetTokenInformation` for `TokenUser`, `TokenSessionId`, `TokenIntegrityLevel`, `TokenElevationType`, `TokenElevation` | Identity, session and elevation ([OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken), [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation), [TOKEN_INFORMATION_CLASS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)) |
| 7 | Compare `TokenSessionId` against an active session from `WTSEnumerateSessionsW` / `WTSGetActiveConsoleSessionId` | Prevents a fast-user-switch or RDP session from driving another user's tunnel ([WTSGetActiveConsoleSessionId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wtsgetactiveconsolesessionid), [WTSEnumerateSessionsW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsw)) |
| 8 | Integrity level: accept `Medium`/`High` per policy; an unlabelled object is treated as medium ([Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control), [TOKEN_MANDATORY_LABEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label)) | Detects unexpected contexts; **not** a tamper detector |
| 9 | Optionally `ImpersonateNamedPipeClient` and **abort the request if it fails** | Adopt the client token for the operation; end with `RevertToSelf`. It succeeds only when the token level is below `SecurityImpersonation`, or the caller holds `SeImpersonatePrivilege`, or the client used explicit credentials, or is the same identity ([doc](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient), [Impersonating a named pipe client](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client)) |

Threat-model notes that must be written into the code comments, because they are the difference between a
toy and a real gate:

* **PID reuse is real and documented.** "Process identifiers can be reused by the system … unique only while
  the associated process is running"
  ([Process.Id](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.id),
  [Process handles and identifiers](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers)).
  Therefore: resolve the PID **once**, immediately open the handle, and do every subsequent check against
  that **handle**, not against the PID. Never cache a PID-based authorisation for the lifetime of a
  long-lived connection; re-run the gate on every new connection. `UNVERIFIED:` there is no documented API
  that returns the client's process *handle* from the pipe, so a handle-identity comparison against the pipe
  client is not available.
* **"Not injected" cannot be proven with documented APIs.** Token integrity/elevation, owning user, session
  id, image path + Authenticode and per-connection revalidation are the available signals; in-memory
  tampering or reflection cannot be ruled out. Treat this as a documented limitation, not a solved problem.
* **.NET helpers are insufficient on their own.** `NamedPipeServerStream.GetImpersonationUserName()` returns
  the client's user *name*, returns **null** if the client has not yet written or did not connect with
  `TokenImpersonationLevel.Impersonation`, and can throw. `PipeStream` exposes no client-identity API and
  `NamedPipeServerStream` has **no** `ClientProcessId`/`ClientSessionId` member — P/Invoke is mandatory
  ([GetImpersonationUserName](https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream.getimpersonationusername),
  [PipeStream](https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.pipestream)).
  `NamedPipeServerStream.RunAsClient` and `WindowsIdentity.RunImpersonated` are the impersonation helpers
  ([RunAsClient](https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream.runasclient),
  [RunImpersonated](https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsidentity.runimpersonated)).
* **Anti-squatting.** The `\\.\pipe\` namespace is first-come: a malicious process can create
  `\\.\pipe\MyVpnSvc` before the service starts, after which the real service fails with
  `ERROR_ACCESS_DENIED`/`ERROR_PIPE_BUSY` ([Pipe names](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names)).
  Defences: create the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE` (0x00080000) /
  `PipeOptions.FirstPipeInstance` **during service start**, fail closed if the name is taken, and grant
  `FILE_CREATE_PIPE_INSTANCE` only to SYSTEM/Administrators (note `FILE_GENERIC_WRITE` implies
  `FILE_CREATE_PIPE_INSTANCE` — the same bit — so grant individual rights rather than generic write)
  ([Named pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)).
  On the client side, verify the server you reached: `GetNamedPipeServerProcessId` + validate, and/or
  `PipeOptions.CurrentUserOnly`, and ideally a server challenge/response
  ([GetNamedPipeServerProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid)).
  `UNVERIFIED:` no Microsoft "how to verify a pipe server" recipe exists; the challenge/response part is
  design, not documentation.

#### 1.3.4 ALPC vs named pipes vs gRPC-over-named-pipes

* **ALPC — do not use.** The Win32
  [Interprocess communications](https://learn.microsoft.com/en-us/windows/win32/ipc/interprocess-communications)
  overview does not list ALPC among supported mechanisms (it lists Clipboard, COM, Data Copy, DDE, File
  Mapping, Mailslots, Pipes, RPC, Windows Sockets). `NtCreatePort`, `NtConnectPort`, `NtRequestPort`,
  `NtReplyPort`, `NtAcceptConnectPort`, `NtCompleteConnectPort` have **no Learn API pages and are absent
  from the `winternl.h` header page**; the only Learn page touching ALPC is the ETW trace class
  ([ALPC (ETW)](https://learn.microsoft.com/en-us/windows/win32/etw/alpc)). Direct ALPC is undocumented for
  user mode; the `NtQueryInformationProcess` page is the canonical warning that `winternl.h` surfaces "may be
  altered or unavailable in future versions" and their structures are "internal to the operating system and
  subject to change" ([NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)).
* **gRPC over named pipes *is* officially supported** — this is the key finding, because the brief expected
  it might require a custom transport. A first-party article (".NET 8 + Windows") shows the server as
  Kestrel `ListenNamedPipe("MyPipeName", o => o.Protocols = HttpProtocols.Http2)` and the client as
  `GrpcChannel` over a `SocketsHttpHandler.ConnectCallback` returning a `NamedPipeClientStream`
  ([Inter-process communication with gRPC and named pipes](https://learn.microsoft.com/en-us/aspnet/core/grpc/interprocess-namedpipes)).
  `ListenNamedPipe` is
  [`KestrelServerOptions.ListenNamedPipe`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.core.kestrelserveroptions.listennamedpipe);
  `ConnectCallback` is a public generic byte-stream hook
  `Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>>`
  ([SocketsHttpHandler.ConnectCallback](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttphandler.connectcallback)) —
  the API page itself never mentions named pipes, so the *named-pipe* use is documented only in the ASP.NET
  Core article. **No custom subchannel/transport is required for the Microsoft-supported path.**
* The pipe ACL for that path is first-class: `UseNamedPipes(options => options.PipeSecurity = …)` with
  `NamedPipeTransportOptions`, and `CurrentUserOnly=false` is **required** when you set `PipeSecurity` (else
  `ArgumentException`); per-endpoint customisation via `CreateNamedPipeServerStream` is .NET 9+
  ([NamedPipeTransportOptions](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.transport.namedpipes.namedpipetransportoptions)).
* **Documented gRPC-over-pipe limitation:** "Some connectivity features of `GrpcChannel`, such as client side
  load balancing and channel status, can't be used together with named pipes." Plan the client around a
  single channel and application-level readiness, not `GrpcChannel.State`.
* gRPC message limits are configurable: `MaxReceiveMessageSize` defaults to **4 MB**,
  `MaxSendMessageSize` to null/unlimited ([gRPC configuration](https://learn.microsoft.com/en-us/aspnet/core/grpc/configuration)).
* `NamedPipeClientStream.Connect()` **blocks forever**; `Connect(int)` takes milliseconds and throws
  `TimeoutException` on expiry (`Timeout.Infinite = -1` is allowed). **Always pass a finite timeout**
  ([NamedPipeClientStream.Connect](https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeclientstream.connect)).

#### 1.3.5 Recommended IPC design

**Choose gRPC over a named pipe.** Rationale: it is first-party-supported, gives schema, streaming and
cancellation for free, needs no custom transport, and its pipe ACL is configurable through
`NamedPipeTransportOptions.PipeSecurity`; raw `System.IO.Pipes` is only preferable if MyVpn wants zero
ASP.NET Core dependency, in which case it owns framing, versioning and timeouts.

Concretely:

1. **Service**: dedicated Windows service, `AddWindowsService()`, `BackgroundService`.
2. **Pipe**: one duplex pipe `\\.\pipe\MyVpnSvc.<product-guid>`; create the first instance at service start
   with `FILE_FLAG_FIRST_PIPE_INSTANCE` + `PIPE_REJECT_REMOTE_CLIENTS` and an explicit DACL via
   `NamedPipeServerStreamAcl.Create` / `NamedPipeTransportOptions.PipeSecurity`:
   * `SYSTEM` (S-1-5-18): `FullControl`
   * `BUILTIN\Administrators` (S-1-5-32-544): `FullControl`
   * the interactive user SID (or better, the **interactive logon SID**): `ReadWrite` — and **not**
     `CreateNewInstance`
   * **no** `Everyone`/`ANONYMOUS` ACE (the default DACL's Everyone *read* is the thing to remove)
3. **Client**: `PipeOptions.CurrentUserOnly` and `TokenImpersonationLevel.Impersonation`, finite
   `Connect()` timeout, and — because `CurrentUserOnly` cannot be combined with a custom server
   `PipeSecurity` on the same side — pick one strategy per side and document it.
4. **Gate**: run the §1.3.3 sequence on **every** connection before reading a single command; fail closed
   and log.
5. **Wire protocol**: 4-byte little-endian length prefix + 1-byte protocol version + 1-byte message type +
   payload; hard cap each frame (~1 MiB for control messages, with gRPC's 4 MB `MaxReceiveMessageSize` as the
   outer ceiling); reject and close on oversize; per-request `CancellationToken` timeouts (5–10 s control
   ops, 30 s long ops); `PipeOptions.Asynchronous`.
6. **Never expose privileged primitives over the pipe.** The RPC surface is a *closed command set*
   ("connect profile X", "get stats", "set kill-switch", "set split-tunnel app list"), never "run this
   command", "open this path", or "install this route with these raw parameters".

#### 1.3.6 Design-critical conflict: service-account hardening vs Wintun

If MyVpn owns Wintun itself (§1.2.3 option A), then two pieces of otherwise-correct hardening advice
collide, and the resolution must be explicit:

* The Wintun device DACL is reported to admit only `S-1-5-18` and `S-1-5-32-544`
  (`UNVERIFIED:` binary decode, see §1.2.3), so the process that registers the rings must be **LocalSystem**
  (or at least running with an Administrators-enabled token).
* `SERVICE_SID_TYPE_RESTRICTED` adds the **write-restricted SID `S-1-5-33`**, and a write-restricted token
  grants access "only if both [the enabled and the restricting] checks allow"
  ([Restricted tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)). Because
  Wintun's device DACL does not contain `S-1-5-33`, `TUN_IOCTL_REGISTER_RINGS`'s `FILE_WRITE_DATA` check
  would fail. **`SERVICE_SID_TYPE_RESTRICTED` and owning a Wintun session are therefore very likely
  incompatible.**

Resolution: **run a single `LocalSystem` service with `SERVICE_SID_TYPE_UNRESTRICTED`** (which still adds the
per-service SID for ACL use) and compensate by (a) minimising the RPC surface, (b) the §1.3.3 identity gate,
(c) a locked-down SCM descriptor, (d) no user-writable directories on the DLL search path, and (e) the
installer ACL'ing `C:\Program Files\MyVpn\` to Administrators/SYSTEM. If option B is chosen (Xray owns
Wintun), the Wintun device is opened by `xray.exe`, so the same conclusion applies to whatever service
launches Xray. **Both premises here are `UNVERIFIED` and cheap to test on hardware** — do it in the first
spike, because the answer changes the service-account design.

### 1.4 Per-process routing on Windows — what is actually achievable

This is where marketing claims and reality diverge most. Four mechanisms exist; only some do what users
mean by "per-app VPN".

#### 1.4.1 Xray's own `process` routing rule — supported but unreliable on Windows

* The routing-rule field is **`process`** (an array); it replaced the older `processName`
  ([PR #5496](https://github.com/XTLS/Xray-core/pull/5496)). A value matches a **process name** (no `/`), an
  **absolute path** (contains `/`, no trailing slash) or a **folder** (trailing `/`). Matching is
  case-sensitive on Windows and `.exe` is stripped only for name matching; `self/` and `xray/` are sugars.
  ([XTLS routing docs](https://xtls.github.io/en/config/routing.html))
* The Windows implementation,
  [`common/net/find_process_windows.go`](https://raw.githubusercontent.com/XTLS/Xray-core/main/common/net/find_process_windows.go),
  resolves the local socket owner through the IP Helper tables `GetExtendedTcpTable`/`GetExtendedUdpTable`
  by source IP + port, then `OpenProcess` + `QueryFullProcessImageName`. For **TCP it silently skips every
  row whose state is not `MIB_TCP_STATE_ESTAB` (5)**; when nothing matches it returns "not found".
* Documented real-world failures are in the project's own tracker: on a TUN, the lookup fails for
  high-privilege/protected processes (reportedly Kaspersky) with
  `app/router: Unables to find local process name: common/net: not found`
  ([XTLS/Xray-core issue #6535](https://github.com/XTLS/Xray-core/issues/6535)). Maintainer analysis in that
  thread: the table lookup succeeds but no owner row/PID is found; "only accepting ESTABLISHED is too little";
  a proper UDP solution needs a heavier packet driver (WinDivert judged too heavy).
* `UNVERIFIED:` no primary source claims Windows `process` matching requires the target to start *after*
  Xray, nor that it is unsupported. The accurate statement is **supported but unreliable** — it fails for
  UDP, short-lived sockets (DNS), non-ESTABLISHED TCP, and protected processes.
* sing-box is in the same position and is a useful cross-check: `process_name` / `process_path` /
  `process_path_regex` are documented "Only supported on Linux, Windows, and macOS"
  ([sing-box route rules](https://sing-box.sagernet.org/configuration/route/rule/#process_name)) and its
  Windows implementation is the **same user-mode IP Helper approach**
  ([`searcher_windows.go`](https://raw.githubusercontent.com/SagerNet/sing-box/testing/common/process/searcher_windows.go),
  [`winiphlpapi/iphlpapi.go`](https://raw.githubusercontent.com/SagerNet/sing/main/common/winiphlpapi/iphlpapi.go));
  an open PR shows Windows matching is currently case-sensitive and needs lowercasing
  ([PR #4346](https://github.com/SagerNet/sing-box/pull/4346)). **The brief's hypothesis that sing-box
  requires a WFP callout driver for Windows process matching is not supported** — matching is user-mode;
  any driver in that product is for the TUN itself.

**Product consequence:** MyVpn may expose `process`-based routing (which outbound an app uses) but must label
it best-effort, must surface "not found" rather than silently misrouting, and must not promise it for
UDP-heavy or protected processes.

#### 1.4.2 WFP per-app filters — `FWPM_CONDITION_ALE_APP_ID`

* Definition: "The **lower-case fully qualified device path** of the application, as returned by
  `FwpmGetAppIdFromFileName0`" (e.g. `\device\harddiskvolume1\program files\application.exe`), type
  `FWP_BYTE_BLOB`
  ([Filtering condition identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)).
* **Path-based, not hash-based.** The same binary at a different path has a different app id; a different
  binary at the same path has the same id; replacing a file in place changes nothing. "App X" therefore means
  "an executable at path P" — a feature (survives in-place upgrades) and a risk (a dropped binary at a
  trusted path inherits the exemption). `UNVERIFIED:` whether any hash-based condition exists.
* **Both directions are possible**, but only at ALE layers: `ALE_APP_ID` appears at outbound
  `ALE_AUTH_CONNECT`, inbound `ALE_AUTH_RECV_ACCEPT`, `ALE_FLOW_ESTABLISHED`, `ALE_RESOURCE_ASSIGNMENT` and
  `ALE_AUTH_LISTEN`
  ([conditions per layer](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer),
  [ALE Layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)).
* **Scope = the socket-owning process, per connection.** Outbound that is the connecting process; inbound the
  owner of the listening/accepted socket.
* **No app-id inheritance.** A child process has its own image path and therefore its own app id, so a filter
  for a parent executable does **not** cover a differently-named child. `UNVERIFIED:` as an explicit
  Microsoft statement (it follows from the path definition). `ALE_ORIGINAL_APP_ID` exists to recover the
  originating app across a proxy/redirect, not for child inheritance
  ([Proxied connections tracking](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking)).
* **Semantics are permit/block only, not route.** A user-mode filter can use only `FWP_ACTION_PERMIT` or
  `FWP_ACTION_BLOCK`; `FWP_ACTION_CALLOUT_*` requires a `calloutKey` registered by a **kernel-mode** callout
  driver ([FWPM_ACTION0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0),
  [FwpmCalloutAdd0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpmk/nf-fwpmk-fwpmcalloutadd0),
  [Types of callouts](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/types-of-callouts)).
  Redirect *does* exist (`FWPM_LAYER_ALE_CONNECT_REDIRECT_V{4,6}` "allows for modification of remote
  addresses and ports"; `..._BIND_REDIRECT_...` for local address/port — [ALE Layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers))
  but reaching it requires a driver that creates a redirect handle and drives `FWPS_CONNECT_REQUEST0`.
  **Therefore a user-mode WFP filter cannot send a chosen app's traffic into the userspace TUN** — only
  permit/block, or (from a driver) rewrite the destination to a local proxy port.

#### 1.4.3 `FwpmConnectionPolicyAdd0` — the one documented exception (and the newest finding)

There **is** a documented Microsoft API for process-based routing that does not need a callout driver:
[`FwpmConnectionPolicyAdd0`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmconnectionpolicyadd0).

> "The TCP/IP stack supports destination address-based routing for outbound connections.
> `FwpmConnectionPolicyAdd0` API allows you to configure more expressive routing policies for outbound
> connections, and thereby to enable more complex scenarios such as source address-based routing,
> **process-based routing**, port-based routing, and others. … The route setting of the first policy whose
> conditions (ANDed) matches the outbound connection is applied."

* **Match conditions** (same page): `FWPM_CONDITION_ALE_APP_ID`, `ALE_USER_ID`, `IP_LOCAL_ADDRESS`,
  `IP_LOCAL_ADDRESS_TYPE`, `IP_LOCAL_PORT`, `IP_PROTOCOL`, `IP_REMOTE_ADDRESS`,
  `IP_DESTINATION_ADDRESS_TYPE`, `IP_REMOTE_PORT`, `FLAGS`, `ALE_ORIGINAL_APP_ID`, `ALE_PACKAGE_ID`,
  `COMPARTMENT_ID`.
* **Route settings** (`FWP_NETWORK_CONNECTION_POLICY_SETTING_TYPE`): `..._SOURCE_ADDRESS`,
  `..._NEXT_HOP_INTERFACE` (the LUID of the outgoing interface — i.e. **send this app's traffic to the TUN**),
  `..._NEXT_HOP` (gateway)
  ([enum page](https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_network_connection_policy_setting_type)).
* Exposed in **both** user mode (`fwpmu.h`, `Fwpuclnt.dll`) and kernel mode (`fwpmk.h`, `fwpkclnt.lib`), on
  the layers `FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V4/_V6`, whose condition set matches the list
  above ([Filtering layer identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-)).
* This is the **only documented way to do true per-process routing into a TUN without shipping a kernel
  driver**: add a policy matching `ALE_APP_ID == slack.exe` with route setting
  `NEXT_HOP_INTERFACE = <TUN LUID>`, and Slack's connections egress the tunnel while everything else follows
  the route table.
* **`UNVERIFIED`, and it matters: the minimum Windows build is not documented.** The user-mode page has no
  Requirements table at all, and the WDK page's "Minimum supported client: Available starting with Windows
  Vista" is almost certainly copy-paste boilerplate (the API and layer are absent from the
  [What's New in WFP](https://learn.microsoft.com/en-us/windows/win32/fwp/what-s-new-in-windows-filtering-platform)
  pages and the docs were first written in 2024 —
  [WDK page](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpmk/nf-fwpmk-fwpmconnectionpolicyadd0)).
  **Treat as a version-gated enhancement:** spike it on the oldest supported build (Windows 10 22H2, Windows
  11 21H2), detect `ERROR_INVALID_PARAMETER`/`ERROR_NOT_SUPPORTED`, and fall back to route-table-only
  behaviour. Do **not** architect v1 around it.

#### 1.4.4 `FWPM_CONDITION_ALE_PACKAGE_ID` — a red herring for Win32 apps

Defined as "the **security identifier (SID) of an app container**" (`FWP_SID`, Windows 8+), it identifies an
AppContainer / packaged (MSIX) identity, not a Win32 process
([Filtering condition identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)).
It is the right tool for the subset of Store/MSIX apps that run in an AppContainer; it is **not** a way to
identify ordinary Win32 processes (use `ALE_APP_ID`). `UNVERIFIED:` whether it is empty or omitted for
non-packaged processes — the docs define it but do not describe the Win32 case.

#### 1.4.5 Child-process tracking — what is realistic

| Option | What it gives | Fatal limitation |
|---|---|---|
| **Job objects** — `CreateJobObject` / `AssignProcessToJobObject`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | `CreateProcess` children join by default; the whole tree dies with the last job handle | Only for trees **MyVpn launches**; `Win32_Process.Create` children are not associated; `JOB_OBJECT_LIMIT_BREAKAWAY_OK` / `..._SILENT_BREAKAWAY_OK` let children escape ([Job objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), [Nested jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs)) |
| **ETW** — NT Kernel Logger `Process`/`Process_V2`, `EVENT_TRACE_FLAG_PROCESS` in `EVENT_TRACE_PROPERTIES.EnableFlags`, event types START(1)/END(2)/rundown(3,4), consumed with `SetTraceCallback` | A user-mode process start/stop stream including parent PID | Reacts *after* the fact; a connection made in the first milliseconds can be missed; rundown must be handled for pre-existing processes ([Process_V2](https://learn.microsoft.com/en-us/windows/win32/etw/process-v2), [NT Kernel Logger constants](https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants)) |
| **`PsSetCreateProcessNotifyRoutine`** | The real, reliable notification | **Kernel-mode only** — `ntddk.h`, `NtosKrnl.lib`, registered by a driver, max 64 callbacks system-wide; no user-mode equivalent ([doc](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine)) |
| **WMI `Win32_ProcessStartTrace`** + `ManagementEventWatcher` | Works from .NET user mode; gives `ProcessID`, `ParentProcessID`, `ProcessName` | Older WMI eventing stack; deprecation status `UNVERIFIED` (page is under previous-versions but carries no deprecation notice) ([doc](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/krnlprov/win32-processstarttrace)) |
| **`Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-Audit-API-Calls`** | Commonly cited for this purpose | `UNVERIFIED:` no canonical Microsoft Learn reference pages found (only Q&A/forum mentions). Do not design against them |

`.NET`'s `System.Diagnostics.Process` exposes **no** process-creation event (`UNVERIFIED:` absence claim); the
workaround is WMI event watching. **Realistic conclusion:** MyVpn can install WFP filters per process *as
processes appear*, but it **cannot retroactively cover arbitrary children** of an already-running application
unless it launched that tree under a job object or maintains an ETW-tracked tree — and breakaway plus
protected processes defeat both.

#### 1.4.6 The realistic options (no kernel driver)

| Goal | Mechanism | Driver? | Key limitation |
|---|---|---|---|
| Full tunnel + destination-IP split routing | Route table (§1.5) | No | Per-destination, never per-process |
| Per-app **block** / "kill non-tunnel traffic" | User-mode WFP filter, `ALE_APP_ID` + BLOCK/PERMIT | No (admin + BFE) | Path-based; no child inheritance; permit/block only |
| Per-app **routing into the TUN** | `FwpmConnectionPolicyAdd0`, `ALE_APP_ID` → `NEXT_HOP_INTERFACE = TUN LUID` | No | **Availability unverified on Win10/Win11 GA**; spike + gate it |
| Per-app **proxying** (no TUN) | SOCKS/HTTP inbound + Xray `process` rule | No | Unreliable: UDP, non-ESTABLISHED TCP, protected processes |
| Per-app routing via WFP connect-redirect callout | Kernel-mode callout driver | **Yes** | EV cert + Microsoft attestation signing (§1.8); not worth it for v1 |
| Track children of a proxied app | Job object and/or ETW | No | Only trees you launch; breakaway/protected processes defeat it |
| Retroactive coverage of an arbitrary running tree | — | — | Not achievable |

### 1.5 Routing-table manipulation

#### 1.5.1 The right APIs

All are Windows Vista+ NetIO functions in `netioapi.h` / `iphlpapi.dll`:

| Function | Purpose | Admin? |
|---|---|---|
| `CreateIpForwardEntry2(const MIB_IPFORWARD_ROW2*)` | Add a route (IPv4 **and** IPv6) | **Yes** — documented as Administrators only, otherwise `ERROR_ACCESS_DENIED` ([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2)) |
| `SetIpForwardEntry2` | Modify an existing matching route | **Yes** ([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipforwardentry2)) |
| `DeleteIpForwardEntry2` | Delete a matching route | **Yes** ([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipforwardentry2)) |
| `GetIpForwardTable2` | Enumerate (`AF_INET`/`AF_INET6`/`AF_UNSPEC`); free with `FreeMibTable`; rows may contain alignment padding | Not documented; `UNVERIFIED` whether it works unelevated in all cases ([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2)) |
| `InitializeIpForwardEntry` | `VOID` local struct init; sets infinite lifetimes and `Loopback/AutoconfigureAddress/Publish/Immortal = TRUE`; leaves `SitePrefixLength`, `Metric`, `Protocol` illegal for the caller to set | No ([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-initializeipforwardentry)) |
| `GetBestRoute2(InterfaceLuid, InterfaceIndex, SourceAddress, DestinationAddress, AddressSortOptions, BestRoute, BestSourceAddress)` | Ask the stack which route it would choose; `AddressSortOptions` is currently unused | No ([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2)) |

`MIB_IPFORWARD_ROW2` carries `DestinationPrefix` (`IP_ADDRESS_PREFIX`), `NextHop` (`SOCKADDR_INET`),
`InterfaceLuid`/`InterfaceIndex`, `Metric`, `Protocol`, `Origin`, `ValidLifetime`, `PreferredLifetime`
([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2)). Two
rules that matter: **an on-link route requires `NextHop` to be all zeros** (`0.0.0.0` / `::`), and a default
route is simply prefix length 0.

`CreateIpForwardEntry` (the older `iphlpapi.h` IPv4-only form) still exists but has real drawbacks: IPv4-only,
requires `dwForwardProto = MIB_IPPROTO_NETMGMT`, and only works on interfaces with a single sub-interface
([doc](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-createipforwardentry)).
**Use the `...2` family only.**

**Two names from the brief do not exist and must not appear in code:** there is **no `BestRouteLookup`** (the
documented names are `GetBestRoute2` and the legacy `GetBestRoute`), and the correct DNS API is
`SetInterfaceDnsSettings`, not `DNS_SetInterfaceDnsSettings` (§1.6).

#### 1.5.2 `route.exe` / `netsh` / PowerShell vs the API

* **`route.exe` is IPv4-only.** Syntax `mask <netmask>` with a dotted-decimal gateway, metric 1–9999,
  `if <index>`; `/p` writes to
  `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes`. **No IPv6 form is documented**
  ([route](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/route_ws2008)).
* **IPv6 goes through netsh**: `netsh interface ipv6 add route [prefix=]<v6>/<len> [interface=] [nexthop=]
  [metric=] [store=]active|persistent`
  ([netsh interface](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)).
* **`New-NetRoute` is a CIM/WMI wrapper** over `MSFT_NetRoute`: `-AddressFamily IPv4|IPv6`, `-RouteMetric`
  (default 256), `-PolicyStore ActiveStore|PersistentStore` (default both; `PersistentStore` alone "cannot be
  used") ([New-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netroute)).
* **Engineering rule: use the NetIO API in-process.** It is the only way to construct the exact
  `MIB_IPFORWARD_ROW2` (including `InterfaceLuid`) that teardown must match; it covers IPv4 and IPv6 in one
  code path; it returns real error codes instead of localized text; and it can be rolled back
  deterministically. `netsh`/`New-NetRoute` remain useful for persistent configuration and tests. **Never
  parse `route print` or `netsh` output** — it is localized. (`UNVERIFIED:` the localization hazard is
  engineering guidance, not a documented warning on the `route` page.)

#### 1.5.3 Metric handling, route selection and loop avoidance

* Documented selection: **longest-prefix match wins**; among equal longest matches, **lowest total metric**;
  ties go to the first interface in binding order. IPv6 uses largest prefix length then lowest metric. Total
  metric = route `Metric` + `MIB_IPINTERFACE_ROW.Metric`
  ([TCP/IP Fundamentals — route determination](https://learn.microsoft.com/en-us/previous-versions/tn-archive/bb962066(v=technet.10)),
  [MIB_IPFORWARD_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2)).
* A full-tunnel `0.0.0.0/0` / `::/0` on the TUN therefore only wins if its total metric is lower than the
  physical interface's. Set the TUN interface metric low (and/or raise the physical metric) via
  `GetIpInterfaceEntry` → `SetIpInterfaceEntry` (**admin**)
  ([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry),
  [MIB_IPINTERFACE_ROW](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row)).
  The documented split-tunnel alternative is `DisableDefaultRoutes = TRUE` ("the stack ignores that
  interface's default route") / `-IgnoreDefaultRoutes`.
* **MTU is `MIB_IPINTERFACE_ROW.NlMtu`**, set through the same Get/Set pair (`Set-NetIPInterface -NlMtuBytes`;
  IPv4 minimum 576, IPv6 minimum 1280)
  ([Set-NetIPInterface](https://learn.microsoft.com/en-us/powershell/module/nettcpip/set-netipinterface)).
  For IPv4 you must leave `SitePrefixLength = 0`.
* **Loop avoidance is mandatory and is an ordering-sensitive two-step operation.** The VPN server's own IP
  must keep egressing the *physical* NIC, or the encrypted outer packets re-enter the TUN default route and
  the tunnel deadlocks:

  1. **Before** installing `0.0.0.0/0` and `::/0`, call `GetBestRoute2` for the server IP to learn its current
     next-hop and interface (or read the same data from `GetIpForwardTable2`).
  2. Add **host routes** `/32` (IPv4) and `/128` (IPv6) to the server via that same next-hop/interface with a
     low route metric, so they are more specific than the default route and always win.

  `UNVERIFIED:` this "compute-then-pin" procedure is standard industry practice but is not spelled out as a
  documented Microsoft procedure; the primitives and selection rules above are documented. The legacy
  guidance instead recommends a default gateway on one interface plus explicit static routes for disjoint
  networks. **The pinned host routes must be recomputed whenever the adapter changes** — otherwise roaming
  (Wi-Fi → Ethernet, or a new DHCP lease) leaves the server route pointing at a dead next-hop.
* **Strong-host caveat:** on Vista+ a route lookup specifying an explicit source address is restricted to that
  source interface, so the old RAS metric-bumping trick no longer forces all traffic through the VPN; use
  `DisableDefaultRoutes` for split-tunnel restriction
  ([SetIpInterfaceEntry](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry)).
* **Change notifications:** `NotifyRouteChange2(Family, Callback, Context, InitialNotification, &Handle)` with
  `CancelMibChangeNotify2` to stop — **never cancel from inside the callback** (documented deadlock). The
  callback's `Row` is partial; re-query with `GetIpForwardEntry2`
  ([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2)). The
  legacy `NotifyAddrChange` is IPv4-only, `OVERLAPPED`-based, cancelled with `CancelIPChangeNotify`
  ([doc](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-notifyaddrchange)).
* **Do not call `SetCurrentThreadCompartmentId`** — the documentation says "Reserved for future use. Do not
  use this function." ([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setcurrentthreadcompartmentid)).
* **Finding the TUN adapter:** `GetAdaptersAddresses(AF_UNSPEC, …)` returns `IP_ADAPTER_ADDRESSES` with
  `IfIndex`, `Ipv6IfIndex`, `AdapterName` (GUID string), `FriendlyName`, `IfType`, `OperStatus`, `Mtu`,
  `FirstUnicastAddress`, `FirstDnsServerAddress`. Preallocate ~15 KB and retry on `ERROR_BUFFER_OVERFLOW`;
  since Windows 10 the list order follows route metric
  ([doc](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)).
* **Adding the tunnel address:** `CreateUnicastIpAddressEntry(MIB_UNICASTIPADDRESS_ROW*)` (**admin**); the
  address is **not persistent** — it dies with the adapter/reset/PnP and is destroyed by reboot.
  `OnLinkPrefixLength = 255` means "full host length"; `DadState = IpDadStatePreferred` requests optimistic
  DAD on Windows 10+. Wait for DAD to settle (~1 s IPv6, ~3 s IPv4) via `NotifyUnicastIpAddressChange` or
  polling before declaring the tunnel up
  ([doc](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry)).

### 1.6 DNS configuration

#### 1.6.1 The correct API — `SetInterfaceDnsSettings`

`SetInterfaceDnsSettings(GUID Interface, const DNS_INTERFACE_SETTINGS*)` and `GetInterfaceDnsSettings` are
**real, documented** `netioapi.h` / `iphlpapi.dll` APIs. The name is **not** `DNS_SetInterfaceDnsSettings`.
Client floors: **Windows 10 build 19041** for VERSION1, **build 19645** for VERSION3
([SetInterfaceDnsSettings](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings),
[GetInterfaceDnsSettings](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getinterfacednssettings)).

Semantics that are easy to get wrong: **only fields whose bit is set in `Flags` are written, and everything
else must be zeroed**; `DNS_SETTING_IPV6` (0x1) retargets the *entire structure* at the IPv6 stack, so
configuring both families takes two calls.

| Structure | Flag bits |
|---|---|
| `DNS_INTERFACE_SETTINGS` (V1) | `DNS_SETTING_IPV6 0x1`, `NAMESERVER 0x2`, `SEARCHLIST 0x4`, `REGISTRATION_ENABLED 0x8`, `DOMAIN 0x20`, `ENABLE_LLMNR 0x80`, `QUERY_ADAPTER_NAME 0x100`, `PROFILE_NAMESERVER 0x200` |
| `DNS_INTERFACE_SETTINGS_EX` (V2) | adds `SUPPLEMENTAL_SEARCH_LIST 0x800` |
| `DNS_INTERFACE_SETTINGS3` (V3) | adds `DNS_SETTING_DOH 0x1000`, `DNS_SETTING_DOH_PROFILE 0x2000`, plus `DNS_SERVER_PROPERTY ServerProperties[]` |

([DNS_INTERFACE_SETTINGS](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-dns_interface_settings),
[DNS_INTERFACE_SETTINGS_EX](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-dns_interface_settings_ex),
[DNS_INTERFACE_SETTINGS3](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-dns_interface_settings3))

#### 1.6.2 DNS over HTTPS

DoH goes through the *same* API: `DNS_INTERFACE_SETTINGS3` with `DNS_SETTING_DOH`/`DNS_SETTING_DOH_PROFILE`
and a `DNS_SERVER_PROPERTY[]` where `Type = DnsServerDohProperty` and `Property.DohSettings` points at a
`DNS_DOH_SERVER_SETTINGS`. `Template` is the DoH URI (hostname must match the server IP); flags are
`ENABLE_AUTO 0x1`, `ENABLE 0x2`, `FALLBACK_TO_UDP 0x4`, `AUTO_UPGRADE_SERVER 0x8`. Only **one** property per
server is allowed and `ServerIndex` must match the index in `NameServer`
([DNS_DOH_SERVER_SETTINGS](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-dns_doh_server_settings),
[DNS_SERVER_PROPERTY](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-dns_server_property)).

The supported alternative surface is the Settings UI, the Group Policy "Configure DNS over HTTPS (DoH) name
resolution" (Allow/Prohibit/Require DoH), and the
`Add-DnsClientDohServerAddress -ServerAddress -DohTemplate -AllowFallbackToUdp -AutoUpgrade` /
`Get-DnsClientDohServerAddress` cmdlets. **Caveat: "Require DoH" fails when the resolver is not on the
known-DoH list** ([Secure DNS Client over HTTPS](https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support)).
`UNVERIFIED:` whether DoH settings survive reboot without re-application — treat DoH as per-session state
MyVpn owns and restores.

#### 1.6.3 NRPT — the right tool for split DNS, and a naming correction

For split DNS (corp.example.com via the VPN resolver, everything else via the local one) the documented
mechanism is the **Name Resolution Policy Table**, which is checked *before* a query is sent, so a matching
rule can force a namespace to VPN DNS, and an "Any"/default rule can implement a full-tunnel resolver policy.

* **Documented management:** Group Policy `Computer Configuration > Policies > Windows Settings > Name
  Resolution Policy`, or `Add-DnsClientNrptRule -Namespace <ns> -NameServers <ip>`, `Remove-DnsClientNrptRule`,
  `Get-DnsClientNrptRule`, `Get-DnsClientNrptPolicy`
  ([Add-DnsClientNrptRule](https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule),
  [Configure DNSSEC rules using the NRPT](https://learn.microsoft.com/en-us/windows-server/networking/dns/name-resolution-policy-table)).
* **Registry form** (documented in the MS-GPNRPT open specification):
  `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\{Rule-GUID}` **or**
  `HKLM\SYSTEM\CurrentControlSet\services\Dnscache\Parameters\DnsPolicyConfig\{Rule-GUID}`
  ([MS-GPNRPT §2.2.2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnrpt/2d34f260-1e9e-4a52-ac91-2056dfd29702)).
* **Naming correction required by the brief:** `DnsSetNrptTable`, `DnsAddPolicyTableRule` and
  `DnsRemovePolicyTableRule` are **not documented public APIs** — they are absent from the official `windns.h`
  function list and their documentation URLs do not resolve. The documented C-level DNS interfaces are
  `DnsQueryConfig` and `DnsGetProxyInformation` / `DNS_PROXY_INFORMATION`
  ([windns.h function list](https://learn.microsoft.com/en-us/windows/win32/api/windns/)). **Do not use the
  `Dns*PolicyTable*` names.** Use the cmdlets at runtime; treat the registry form as the fallback and note the
  `Policies` hive is the GPO/MDM-managed location that policy can lock or revert.
* Per-interface DNS still lives in
  `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<interface>\NameServer` (`REG_SZ`,
  space-separated; a user value overrides DHCP), with global `Tcpip\Parameters\NameServer` /
  `DhcpNameServer` ([NameServer](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978468(v=technet.10)),
  [TCP/IP and NBT parameters](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/tcpip-and-nbt-configuration-parameters)).
  `SetInterfaceDnsSettings` is the supported API fronting this store — prefer it.

#### 1.6.4 Bring-up and teardown

**Bring-up** (all in the privileged service):

1. **Adapter** — create/open Wintun; enumerate with `GetAdaptersAddresses` for `Luid`, `IfIndex`, adapter GUID
   (the adapter must exist before it can be addressed).
2. **Address** — `CreateUnicastIpAddressEntry` with the tunnel IP, `OnLinkPrefixLength`, optimistic DAD; wait
   for `DadState = IpPreferred`.
3. **MTU + metric** — `SetIpInterfaceEntry` (`NlMtu` e.g. 1420; interface `Metric` low; `DisableDefaultRoutes`
   for strict full tunnel; IPv4 `SitePrefixLength = 0`).
4. **Routes** — `GetBestRoute2` the VPN server IP, pin `/32` + `/128` host routes to the physical
   next-hop/interface, **then** add `0.0.0.0/0` and `::/0` on the TUN with a low metric.
5. **DNS** — snapshot `GetInterfaceDnsSettings`; apply nameservers (two calls if IPv6 is needed) and/or
   `Add-DnsClientNrptRule` for split DNS; optionally DoH via VERSION3.
6. **Verify** — `GetBestRoute2` for the server IP must still resolve to the physical interface;
   `GetIpForwardTable2` for the default routes; `GetInterfaceDnsSettings` / `Resolve-DnsName`;
   `Get-DnsClientNrptPolicy -Effective`.

**Teardown** (reverse order, idempotent, and **re-run on every service start**):

1. `DeleteIpForwardEntry2` every row MyVpn added, matching exactly on
   `DestinationPrefix` + `NextHop` + `InterfaceLuid`; delete the pinned host routes **last**.
2. Restore DNS from the snapshot, remove the NRPT rules MyVpn added, or delete the interface `NameServer`
   value to fall back to DHCP.
3. Restore interface metric / `DisableDefaultRoutes`, then `DeleteUnicastIpAddressEntry`, then close and
   delete the adapter.
4. Persisted routes/DNS must be removed explicitly.

**Crash-safety warning.** NetIO-created routes and interface addresses live in the in-memory IP stack; only
`/p`, `store=persistent` or `New-NetRoute`'s default write a persistent copy (IPv4 registry
`...\Tcpip\Parameters\PersistentRoutes`). There is **no documented transactional or rollback API** for routes
or interface DNS settings, and **no Microsoft promise that Windows cleans up a third-party VPN's routes/DNS
after abnormal termination**. (`UNVERIFIED:` the "routes survive a service crash" consequence is inferred from
the documented lifetime/persistence model.) MyVpn must therefore: snapshot before mutation into its **own**
service-owned storage (not the OS stores); re-run teardown on start; keep a "clean state" marker so an unclean
shutdown is detectable; prefer `ActiveStore` (runtime-only) state so reboot is a clean reset; and know that
`netsh interface ipv4 reset` / `ipv6 reset` is the documented blunt rollback
([netsh interface](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)).

**IPv6.** Prefer route/interface controls over disabling IPv6: `DisableDefaultRoutes` / `-IgnoreDefaultRoutes`
or `Set-NetIPInterface -RouterDiscovery Disabled` stops RA-installed defaults
([MIB_IPINTERFACE_ROW](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row)).
If IPv6 must be suppressed, the documented registry is
`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents` (`0x20` prefer IPv4 is
Microsoft's recommendation; `0xFF` disables; `0xffffffff` causes a 5-second startup delay, so use `0xff`); it
requires a restart
([Guidance for configuring IPv6](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows)).
Add `::/0` and on-link IPv6 routes exactly as IPv4 via `MIB_IPFORWARD_ROW2` with `AF_INET6` and an all-zero
`NextHop`.

### 1.7 System proxy (WinINET, WinHTTP, PAC)

#### 1.7.1 Two independent stores — you must write both

* **WinINET is per-user.** "WinINET proxy settings are typically per-user rather than per-machine", so a
  SYSTEM service **cannot** correctly set another logged-on user's proxy. The only machine-wide forcing
  mechanism is `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ProxySettingsPerUser = 0`,
  after which only elevated apps can change the proxy
  ([IEInternals — Understanding Web Proxy Configuration](https://learn.microsoft.com/en-us/archive/blogs/ieinternals/understanding-web-proxy-configuration)).
* **Never write the WinINET registry keys directly.** Microsoft states: "Client applications should not use
  registry functions to change the default values of the Internet options, because the implementation of how
  the options are stored can be altered in the future." Use `InternetSetOption`/`InternetQueryOption`
  ([Setting and Retrieving Internet Options](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)).
* **WinINET must not be used from a service at all**: "WinInet does not support server implementations. In
  addition, it should not be used from a service."
  ([INTERNET_PER_CONN_OPTION_LISTA](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_option_lista)).
  This single sentence dictates the architecture of this feature: **the per-user WinINET write must be
  performed by a user-session helper/UI process, not by the service.**
* **WinHTTP is the machine-wide store used by services**, including BITS and Windows Update. A WinINET-only
  proxy therefore **misses Windows Update/BITS** — a real, user-visible consequence
  ([IEInternals](https://learn.microsoft.com/en-us/archive/blogs/ieinternals/understanding-web-proxy-configuration)).
* Docs pages that the brief asked about and that **do not exist** (do not use these names in code):
  `InternetSetPerSiteProxySettings` — not a documented WinINET API, and `WinHttpSetProxySettings` — not in
  the documented WinHTTP function list ([WinHTTP Functions](https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttp-functions)).

#### 1.7.2 The calls

**Per-connection WinINET (per user, from the UI/helper process):**

* `InternetSetOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, size)` /
  `InternetQueryOption(...)` with an `INTERNET_PER_CONN_OPTION_LIST` (and `INTERNET_PER_CONN_OPTION`);
  `pszConnection = NULL` means the LAN/default connection. A worked sample is in
  [Setting and Retrieving Internet Options](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)
  ([INTERNET_PER_CONN_OPTION_LISTA](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_option_lista)).
* Passing `NULL` as the handle changes settings **system-wide**; using an `InternetOpen` handle changes them
  process-wide only. `INTERNET_OPTION_PROXY` is deprecated in favour of `PER_CONNECTION`
  ([Option Flags](https://learn.microsoft.com/en-us/windows/win32/wininet/option-flags)).
* **Notify the stack, or nothing takes effect.** After writing:
  * `INTERNET_OPTION_SETTINGS_CHANGED` (39) — "Notifies the system that the registry settings have been
    changed so that it verifies the settings on the next call to InternetConnect";
  * `INTERNET_OPTION_REFRESH` (37) — "Causes the proxy data to be reread from the registry for a handle";
    the per-connection documentation is explicit: "To refresh the global proxy settings, you must call
    `InternetSetOption` with the `INTERNET_OPTION_REFRESH` option flag";
  * `INTERNET_OPTION_PROXY_SETTINGS_CHANGED` (95) — "Alerts the current WinInet instance that proxy settings
    have changed" ([Option Flags](https://learn.microsoft.com/en-us/windows/win32/wininet/option-flags)).

**Machine-wide WinHTTP (from the service):**

* `netsh winhttp` is **current, not deprecated** (applies to Windows 11 / Server 2025, last updated
  2025-08-20): `netsh winhttp import proxy source=ie`, `netsh winhttp set proxy proxy-server=...
  bypass-list=...`, `netsh winhttp reset proxy`, `netsh winhttp show proxy`. Current builds add
  `netsh winhttp set advproxy setting-scope=user|machine
  settings="{...Proxy,ProxyBypass,AutoconfigUrl,AutoDetect...}"`
  ([netsh winhttp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-winhttp)).
* The registry value behind it is `WinHttpSettings` (`REG_BINARY`) under
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`
  ([Getting Web Proxy Settings](https://learn.microsoft.com/en-us/archive/blogs/timid/getting-web-proxy-settings)) —
  `UNVERIFIED:` confirmed only via an archived MSDN blog, not a current API reference. **Prefer the `netsh
  winhttp` command over writing this binary blob.**
* `WinHttpSetDefaultProxyConfiguration` exists but is **deprecated on Windows 8.1+**: "Most proxy
  configurations are not supported … nor does it support proxy authentication. Instead, use
  `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY` with `WinHttpOpen`"
  ([doc](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsetdefaultproxyconfiguration)).
  So for MyVpn *itself* (and any .NET `HttpClient` it configures), use `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`.
* Reading the *user's* current WinINET configuration from a service requires impersonation:
  `WinHttpGetIEProxyConfigForCurrentUser` "should not be used in a service process that does not impersonate a
  logged-on user", otherwise it queries LocalService/NetworkService settings and usually fails
  ([doc](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpgetieproxyconfigforcurrentuser)).
  `WinHttpGetProxyForUrl` evaluates WPAD + PAC per URL (ECMAScript PAC only, caches the PAC)
  ([doc](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpgetproxyforurl)).

#### 1.7.3 PAC and browser behaviour

* WinINET precedence is **Auto-detect (WPAD) → `AutoConfigURL` (PAC) → fixed proxy**. WPAD is DHCP INFORM
  option 252 plus DNS `wpad.<domain>`
  ([IEInternals](https://learn.microsoft.com/en-us/archive/blogs/ieinternals/understanding-web-proxy-configuration)).
* A local PAC is served over HTTP from `http://127.0.0.1:<port>/proxy.pac` (HTTP/HTTPS only). **`file://`
  PAC is deprecated/blocked** (IE11+, and .NET moved to WinHTTP which never supported `file://` PAC).
  WinHTTP also refuses a PAC whose `Content-Type` is not `application/x-ns-proxy-autoconfig` and whose
  extension is not `.js`/`.pac`/`.dat`. Authenticated PAC download is blocked (IE11+). If MyVpn hosts a PAC,
  it must serve the correct content type
  ([WinHttpGetProxyForUrl](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpgetproxyforurl),
  [Chromium proxy docs](https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md)).
* **Chrome and Edge use the platform proxy by default** on Windows; Edge additionally publishes a
  `ProxySettings` policy that scopes proxy config to the browser only
  ([Chromium proxy support](https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md),
  [Edge ProxySettings policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/proxysettings)).
* **Firefox does not use WinINET unless its own Mode is `system`** — it has an independent proxy stack with
  `Mode ∈ {none, system, manual, autoDetect, autoConfig}`
  ([Firefox admin reference — Proxy](https://firefox-admin-docs.mozilla.org/reference/policies/proxy/);
  IEInternals adds "Firefox respects the WinINET setting only when configured to 'Use System Proxy
  Settings'"). `UNVERIFIED:` Firefox's shipped default — the Mozilla SUMO page was unreachable. Treat as
  user/policy-dependent and **document that "system proxy" does not cover Firefox out of the box.**
* Security caveats worth surfacing in the UI: WPAD is spoofable via DNS search-suffix/TLD collision
  (US-CERT TA16-144A); PAC-driven `DIRECT` maps sites into the Local Intranet zone by default; there is an
  implicit localhost proxy bypass, and `<-loopback>` subtracts it
  ([Chromium proxy docs](https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md)).

#### 1.7.4 Detecting and restoring the previous state

* **Read before you write.** `InternetQueryOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, list, &size)`
  returns the current `INTERNET_PER_CONN_*` values; the documented pattern is to call it **twice** — once to
  size the buffer, once to fill it. Persist the snapshot to disk and restore on disconnect, uninstall and
  crash recovery ([Setting and Retrieving Internet Options](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)).
  Do the same for WinHTTP (capture `netsh winhttp show proxy` output or the `WinHttpSettings` blob *before*
  changing it).
* **Detect third-party changes rather than overwriting them.** Store a hash of the values MyVpn set; if the
  current values differ on disconnect, the user (or another VPN) changed them — back off and log rather than
  blindly restoring. (Engineering practice; no single Microsoft source.)
* Primary-sourced pitfalls to design around:
  * **GPO-locked proxy** — `ProxySettingsPerUser = 0` makes the setting machine-wide and only changeable by
    elevated apps, so non-admin writes silently fail.
  * **Shared store, last-writer-wins** — other VPN/proxy tools write the same `HKCU` keys.
  * **Windows Update/BITS are WinHTTP**, so a WinINET-only proxy misses them.
  * **Shutdown regression** — since IE10, proxy changes made during system shutdown through the WinINET API
    "return success, but upon restart … [are] discarded".
  * Because of the above, many real clients make system proxy an **optional, user-visible feature**.
  All from [IEInternals](https://learn.microsoft.com/en-us/archive/blogs/ieinternals/understanding-web-proxy-configuration).
* **No OS-level per-app proxy setting named `ProxySettings` exists in Windows 11** as far as could be
  determined (`UNVERIFIED`; the closest things are Edge's browser-scoped policy and WinHTTP's user/machine
  scope).

**Recommended design for this feature:** expose it as an opt-in toggle. The **user-session helper** writes
WinINET through `InternetSetOption` + `INTERNET_OPTION_SETTINGS_CHANGED` + `INTERNET_OPTION_REFRESH`; the
**service** writes WinHTTP via `netsh winhttp set proxy` / `set advproxy setting-scope=machine`; both snapshot
before mutating and restore on disconnect; and MyVpn offers a local PAC at
`http://127.0.0.1:<port>/proxy.pac` with `Content-Type: application/x-ns-proxy-autoconfig` for clients that
ignore a fixed proxy.

### 1.8 Code signing and packaging

#### 1.8.1 The 2024–2026 signing landscape (two things changed recently)

* **Keys must be in hardware.** The CA/Browser Forum Code Signing Baseline Requirements require subscriber
  private keys for code-signing certificates to be generated, stored and used in a suitable Hardware Crypto
  Module (FIPS 140-2 level 2 or equivalent for signing services) since **2023-06-01**, and the "any other
  method" escape hatch closed at that date; CS certificate validity is capped at 460 days for certificates
  issued on or after 2026-03-01
  ([CA/B Forum CSBR](https://cabforum.org/working-groups/code-signing/requirements/)). Microsoft's guidance
  agrees: "As of June 2023, the CA/Browser Forum requires private keys for OV certificates to be stored on a
  hardware security module (HSM) or hardware token"
  ([Code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)).
* **Azure Trusted Signing has been renamed Azure Artifact Signing**, and the old `/azure/trusted-signing/`
  URLs now resolve to Artifact Signing. It is managed end-to-end signing with keys in **FIPS 140-3 level 3**
  HSMs, no hardware token, CI/CD integration, with Public Trust, Private Trust, VBS enclave, CI policy and
  test-signing modes ([What is Artifact Signing?](https://learn.microsoft.com/en-us/azure/artifact-signing/overview)).
  * Eligibility: Public Trust is available to organizations in the US, Canada, EU, UK, Australia, NZ, Japan,
    South Korea, Singapore, Switzerland, Norway and Israel; **individual** developers only in the US or
    Canada, requiring an Azure billing account of type Individual whose legal name/address matches government
    ID. Identity validation is portal-only and takes 1–20 business days
    ([quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart),
    [resources and roles](https://learn.microsoft.com/en-us/azure/artifact-signing/concept-resources-roles)).
    Note that Microsoft's older app-dev summary still lists a narrower region set — prefer the quickstart.
  * Pricing: Basic **$9.99/account/month** (5,000 signatures/month, one profile of each type); Premium
    **$99.99/account/month** (100,000 signatures, ten profiles); **$0.005 per signature** beyond quota
    ([Change the account SKU](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-change-sku)).
* **EV no longer bypasses SmartScreen — that behaviour was removed in 2024**, so EV now behaves like OV for
  reputation purposes and paying the EV premium solely to avoid SmartScreen warnings is no longer justified
  ([SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)).
  EV is still required to open a Hardware Dev Center account (§1.8.3), so buy EV only for driver work.

#### 1.8.2 SmartScreen reality

* Two signals: **publisher/certificate reputation** and **file-hash reputation**. A signed application still
  warns until reputation accumulates — "can take several weeks and hundreds of clean installs from a wide
  audience". Unsigned/self-signed binaries are strongly blocked, and each new version restarts hash
  reputation **unless** it is signed by the same publisher identity
  ([SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)).
* Artifact Signing "does not provide instant SmartScreen trust" — reputation still builds over time with a
  consistent publisher identity
  ([Code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)).
* There is **no consumer mechanism** to submit a file for reputation review; reputation builds organically.
  Enterprise administrators may submit via the Microsoft Security Intelligence portal to accelerate internal
  deployment ([SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation),
  [file submission](https://www.microsoft.com/en-us/wdsi/filesubmission)).
* **Windows 11 Smart App Control** can supersede SmartScreen and blocks unsigned files unless positively
  reputed, applying to all executables rather than only downloaded ones (same page). This is a product risk
  for a VPN client that users install from a website: **plan for the first weeks of releases to warn**, and
  keep the signing identity constant forever.

#### 1.8.3 Driver signing — the reason not to write a driver

* Since **Windows 10 1607** "Windows will not load any new kernel-mode drivers which are not signed by the
  Dev Portal"; cross-signing stopped being accepted for Windows 10 as of **1809**, with only narrow
  grandfathering ([Driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-),
  [driver signing options](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings)).
* A Hardware Dev Center account requires an **EV code-signing certificate** — "an EV code signing certificate
  is required to establish a dashboard account"
  ([Driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)).
* **Attestation signing** needs no HLK test logs and covers kernel + user mode on Windows 10 Desktop+, but
  **requires an EV certificate**, cannot publish to Windows Update for retail (testing only), and Microsoft
  re-signs with its own SHA-2 certificate and regenerates the catalogue. **WHCP/HLK** (a full test pass) is the
  path for retail/Windows Update and all Windows versions
  ([Attestation sign Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation),
  [WHCP specifications and policies](https://learn.microsoft.com/en-us/windows-hardware/design/compatibility/whcp-specifications-policies)).
* **Conclusion, and it is a load-bearing one for this document: shipping any custom kernel driver (WFP
  callout, TUN, split-tunnel) means an EV certificate plus Microsoft attestation/HLK signing, a Partner Center
  account, and a multi-week certification loop per release.** Bundling the already-signed `wintun.dll` avoids
  all of it ([wintun.net](https://www.wintun.net/)). This is the dominant argument against the
  kernel-driver-based per-process routing option in §1.4.6.

#### 1.8.4 Packaging

| Technology | Services | Machine-wide | Upgrades | Verdict for MyVpn |
|---|---|---|---|---|
| **MSI (WiX v4/v5)** | Yes (`ServiceInstall`/`ServiceControl`) | Yes (`ALLUSERS=1`) | `MajorUpgrade` | **Recommended.** Needs admin; can also install a driver package later if ever needed ([WiX](https://docs.firegiant.com/wix/)) |
| **MSIX** | Yes since **Windows 10 2004** (min 10.0.19025.0) **but requires admin + a restricted capability**, and services with dependencies outside the package are unsupported | Provisioning possible | Automatic/framework updates | **Rejected: "MSIX currently does not support driver installation."** Also per-user primary scope ([MSIX with services](https://learn.microsoft.com/en-us/windows/msix/packaging-tool/convert-an-installer-with-services), [MSIX known issues](https://learn.microsoft.com/en-us/windows/msix/packaging-tool/tool-known-issues)) |
| **ClickOnce** | No | No — per-user, per-application cache, no registry/Program Files | Self-updating, rollback | Rejected: cannot install a service ([ClickOnce](https://learn.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment)) |
| **Squirrel.Windows** | No | No — "no UAC dialogs", per-user | Delta updates | Rejected: desktop app updater only ([Squirrel.Windows](https://github.com/Squirrel/Squirrel.Windows)) |
| **WiX Burn bundle** | Yes (drives MSI/EXE packages) | Yes | Bundle chain | **Recommended as the outer shell**, so MyVpn can conditionally install the TUN component and the service ([WiX Burn](https://docs.firegiant.com/wix/tools/burn/)) |

MSIX packages must be Authenticode-signed (`signtool sign /fd SHA256 /tr … /td SHA256`); Store-distributed
MSIX is re-signed by Microsoft and therefore never triggers SmartScreen, but non-Store MSIX is signed by the
vendor and still builds reputation
([Sign an MSIX package using SignTool](https://learn.microsoft.com/en-us/windows/msix/package/sign-app-package-using-signtool)).

**`signtool` usage.** Canonical form: `signtool sign /fd SHA256 /tr <RFC3161-URL> /td SHA256 <file>`;
`/fd` and `/td` are **mandatory** in SDK/HLK/WDK/ADK builds 20236+, and SHA-256 is recommended. Also
`signtool timestamp /tr <url> /td SHA256 <file>` and `signtool verify /pa /all <file>`. `/as` appends a
signature (dual/secondary signing), `/a` auto-selects a certificate, `/sm` selects the machine store, and
`/ac` adds a cross-certificate ([SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)).
**Sign every PE and package**: `MyVpn.exe` (UI), `MyVpnSvc.exe`, every shipped DLL, helper/bootstrapper
executables, MSI custom-action DLLs, **and the MSI itself** — and timestamp each. Order matters: modifying a
file after signing breaks its signature.

**WiX licensing — flag this.** WiX is **MS-RL, not MIT**: the repository `LICENSE.TXT` (main branch and the
`v5.0.0` tag) states "This software is released under the Microsoft Reciprocal License (MS-RL)"
([LICENSE.TXT](https://github.com/wixtoolset/wix/blob/main/LICENSE.TXT)). MS-RL is a weak copyleft that is
fine for *using* WiX as a build tool, but any modifications to WiX source must be shared back. Separately,
WiX v6/v7 participate in the **Open Source Maintenance Fee**: source stays MS-RL, but **organizations with
more than $10,000 annual revenue must sponsor the wixtoolset GitHub organisation**, and EULA-acceptance
enforcement was added in WiX v7 ([WiX Open Source Maintenance Fee](https://docs.firegiant.com/wix/osmf/)).
That is a **compliance obligation with a cost**, and it needs a decision before the packaging choice is
frozen. Alternatives to evaluate if the fee is unacceptable: WiX v4 (pre-OSMF), or a different MSI authoring
toolchain.

**Signing recommendation.** Use Azure **Artifact Signing** (Public Trust) if the legal entity qualifies
in-region — ~$9.99/month, FIPS 140-3 L3 keys, CI-friendly, and it satisfies the CA/B hardware-key rule.
Otherwise buy an **OV certificate on a USB HSM or cloud HSM**; buy EV only if a Hardware Dev Center account is
actually needed. Expect SmartScreen warnings for the first weeks regardless, keep one signing identity
forever, and submit builds to the Security Intelligence portal for enterprise pilots.

---

## 2. Architecture proposal

### 2.1 Process model

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ User session (interactive, unelevated)                                       │
│                                                                              │
│  MyVpn.exe  (WPF/WinUI UI, user session)                                     │
│   • owns the tray icon, profile editor, connect/disconnect commands          │
│   • gRPC CLIENT over the named pipe  (ConnectCallback → NamedPipeClientStream)│
│   • owns the SYSTEM PROXY write (uses a user token; §1.7)                    │
│   • never touches WFP, routes, DNS, or Wintun                                │
│                                                                              │
│  • user-session helper (optional, same process): writes WinINET via           │
│    InternetSetOption + INTERNET_OPTION_SETTINGS_CHANGED/REFRESH, because      │
│    "WinINet ... should not be used from a service"                            │
└───────────────────────────────▲──────────────────────────────────────────────┘
                                │  \\.\pipe\MyVpnSvc.<product-guid>
                                │  ACL: SYSTEM+Administrators FullControl;
                                │       interactive user ReadWrite (no CreateNewInstance)
                                │  gRPC over HTTP/2-on-named-pipe, frame cap ~1 MiB
                                │  gate: client PID→handle→path+Authenticode→SID/session/integrity
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ Windows service  MyVpnSvc  (LocalSystem, SERVICE_SID_TYPE_UNRESTRICTED,       │
│                              auto-start, SERVICE_SID added to WFP ACLs)       │
│                                                                              │
│  IKillSwitch      → WFP via P/Invoke fwpuclnt.dll        (kill switch)        │
│  IRouteManager    → NetIO CreateIpForwardEntry2 / GetBestRoute2 (routes)      │
│  IDnsConfigurator → SetInterfaceDnsSettings / NRPT        (DNS)               │
│  ITunnelDevice    → wintun.dll P/Invoke  OR  supervise xray.exe (tun inbound)  │
│  IProcessRouter   → xray process rules + optional FwpmConnectionPolicyAdd0    │
│                                                                              │
│  owns: the Wintun session (single session per adapter), all routes, WFP       │
│  filters, interface DNS, and the crash-recovery/teardown journal              │
└──────────────────────────────────────────────────────────────────────────────┘
                                │ spawns / supervises
                                ▼
                    xray.exe  (child of the service, fixed path,
                               file-ACL'd to Administrators/SYSTEM)
```

Why this shape is forced, rather than chosen:

1. **Wintun requires elevation/SYSTEM** to install the driver and to register rings (§1.2.3), and the ring
   registration is a `FILE_WRITE_DATA` check against a device DACL that admits only SYSTEM and Administrators
   (`UNVERIFIED:` binary decode). So a privileged owner of the TUN is unavoidable.
2. **WFP `FwpmFilterAdd0` requires `FWPM_ACTRL_*` rights** (§1.1.4), and `CreateIpForwardEntry2` /
   `SetIpInterfaceEntry` / `CreateUnicastIpAddressEntry` are documented as **Administrators-only** (§1.5). All
   of that must live in the service.
3. **WinINET must not be used from a service** (§1.7.1), so the system-proxy feature is split by necessity:
   WinINET in the user session, WinHTTP in the service.
4. **One Wintun session per adapter** (§1.2.3) means the TUN owner must be a single process; a UI process
   cannot share it.

### 2.2 Service account decision (and its conflict)

Run a single **`LocalSystem`** service today, because:
* owning Wintun very likely requires SYSTEM/Administrators (device DACL), and
* `SERVICE_SID_TYPE_RESTRICTED` adds the write-restricted SID `S-1-5-33`, which is absent from that DACL and
  would therefore break `TUN_IOCTL_REGISTER_RINGS` (§1.3.6).

Use `SERVICE_SID_TYPE_UNRESTRICTED` so a per-service SID still exists for ACLs, add that SID (or rely on
Administrators) to the WFP engine/filter containers
([Access control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)), lock the SCM
descriptor with `sc sdset`, and compensate for the broad token with a minimal RPC surface and the §1.3.3
identity gate. **Spike the Wintun DACL question first** — if a restricted/less-privileged account turns out to
be able to register rings, the account can be narrowed substantially.

### 2.3 Kill switch: two modes, one filter recipe

Reuse the exact WireGuard pattern (§1.1.3–1.1.4): one maximum-weight sub-layer, all permits above a
weight-0 unconditional block at `ALE_AUTH_CONNECT_V{4,6}` (and `ALE_AUTH_RECV_ACCEPT_V{4,6}` for inbound
control). Permits:

| Weight | Permit | Rationale |
|---|---|---|
| 15 | `ALE_APP_ID` = `xray.exe` **and** `ALE_USER_ID` = the service's token security descriptor | The tunnel's own encrypted transport. The second condition is what stops another process at the same image path from inheriting the exemption |
| 14 | DNS to the configured resolvers only (UDP+TCP, remote port 53) | "Leaktight DNS": while the kill switch is on, plaintext DNS to anything else is blocked |
| 13 | `FWP_CONDITION_FLAG_IS_LOOPBACK` | The local SOCKS/HTTP inbound and the UI↔service IPC must keep working |
| 12 | `FWPM_CONDITION_IP_LOCAL_INTERFACE` = TUN LUID | Anything the route table sends into the tunnel |
| 12 | DHCP v4/v6 and ICMPv6 NDP 133–137 | Otherwise the adapter cannot get/keep an address |

**Mode A — Kill switch (default).** `FWPM_SESSION_FLAG_DYNAMIC`. Filters vanish if the service dies, which is
acceptable because the tunnel dies too. This is WireGuard's model and the right default.

**Mode B — Lockdown / always-on (opt-in).** Non-dynamic session; provider + sub-layer + filters all carry
`*_FLAG_PERSISTENT` and the provider carries `serviceName = L"MyVpnSvc"` with the service set to
auto-start (without which BFE disables the whole thing at boot — §1.1.5); plus a set of **equivalent
`BOOTTIME` filters** at the IP-packet layers, relying on the documented gapless boot-time → persistent
transition. Add a startup self-check that enumerates MyVpn's own objects and raises a visible alarm if any
come back `*_FLAG_DISABLED`. Add a documented "panic release" (`netsh wfp dump` + delete-by-key, or a CLI
switch) so a broken policy can never permanently lock a machine out of the network.

Optional hardening in both modes: an IP-packet-layer backstop at
`FWPM_LAYER_OUTBOUND_IPPACKET_V4/_V6` (block at weight 0; permit the server IP set and the TUN LUID) to cover
traffic that ALE layers never see and to cut flows unconditionally on the next packet rather than at
reauthorization.

### 2.4 Connect / disconnect data flow

**Connect (service, in order — the ordering is the correctness):**

1. Validate the requested profile; resolve the server hostname and capture the resolved IP set.
2. Bring up the TUN device (Wintun session, or start `xray.exe` with the `tun` inbound).
3. Enumerate the adapter (`GetAdaptersAddresses`) to get `Luid`/`IfIndex`; assign the tunnel address
   (`CreateUnicastIpAddressEntry`) and wait for DAD.
4. `SetIpInterfaceEntry`: MTU, low interface metric, `DisableDefaultRoutes` per split-tunnel policy.
5. `GetBestRoute2` for each server IP → pin `/32` + `/128` host routes to the **physical** next-hop.
6. Add the full-tunnel routes (`0.0.0.0/0`, `::/0`) on the TUN with a low metric — or the split-tunnel prefix
   list.
7. Snapshot and apply DNS (`SetInterfaceDnsSettings`, then NRPT rules for split DNS). Store the snapshot.
8. **Install the WFP kill switch last**, once the tunnel is actually usable — so a failure here leaves a
   working (if unprotected) tunnel rather than a dead machine. If the tunnel is not yet up, install the
   fail-closed policy first and then permit the tunnel; pick one ordering and encode it explicitly.
9. Mark state clean in the journal; report connected over IPC; hand the SOCKS/HTTP endpoint to the UI.

**Disconnect (reverse, idempotent):**

1. Remove the WFP policy (close the session in Mode A; delete-by-key in Mode B).
2. Restore DNS from the snapshot; remove MyVpn's NRPT rules.
3. Delete every route MyVpn added (exact `DestinationPrefix`+`NextHop`+`InterfaceLuid`), pinned host routes
   last.
4. Restore the interface metric/`DisableDefaultRoutes`; `DeleteUnicastIpAddressEntry`.
5. Stop `xray.exe` / end the Wintun session; delete the adapter.
6. Restore the system proxy (WinINET by the UI, WinHTTP by the service).
7. Clear the journal.

**Crash recovery:** on every service start, read the journal and re-run teardown before doing anything else,
because routes/DNS/routes survive abnormal termination and there is no OS rollback (§1.5.3, §1.6.4).

### 2.5 C# interface proposals

The interfaces below are the contract the Windows implementation satisfies. They should be shared with the
other platform research documents so the core can be platform-agnostic; every `*Platform*` type is
`partial`/`[SupportedOSPlatform("windows")]` and registered only on Windows.

```csharp
// ── Platform-agnostic contracts (MyVpn.Core.Abstractions) ─────────────────────────

public interface IKillSwitch
{
    KillSwitchMode Mode { get; }                 // Off, Standard (dynamic), Lockdown (persistent)
    bool IsArmed { get; }
    Task ArmAsync(KillSwitchPlan plan, CancellationToken ct);
    Task DisarmAsync(CancellationToken ct);      // explicit user action only
    Task<KillSwitchStatus> GetStatusAsync(CancellationToken ct);
}

/// <summary>Everything the filter set needs to be built. Note TUN LUID and the
/// allowed process identity are required: the fail-closed recipe is
/// "block all, permit these".</summary>
public sealed record KillSwitchPlan(
    KillSwitchMode        Mode,
    ulong                 TunnelInterfaceLuid,
    IReadOnlyList<IPAddress> VpnServerAddresses,
    string                TunnelClientExecutablePath,   // xray.exe — becomes ALE_APP_ID
    string?               TunnelClientServiceName,      // -> ALE_USER_ID (service SID)
    IReadOnlyList<IPAddress> AllowedDnsResolvers,
    bool                  AllowLoopback,
    bool                  PermitDhcpAndNdp);

/// <summary>CANNOT be done reliably on Windows (see §1.1.6, §1.4):
///  - redirect a specific process's traffic into the TUN from user mode (needs a
///    kernel callout driver), so this interface cannot offer "route app X" — only
///    permit/block. Per-process routing lives on IProcessRouter.
///  - guarantee protection while BFE is stopped.
///  - guarantee coverage of AppContainer/WSL2/Hyper-V compartments.
/// </summary>
public sealed record KillSwitchStatus(
    bool   EngineAvailable,     // BFE reachable
    bool   FiltersInstalled,
    int    InstalledFilterCount,
    bool   AnyObjectsDisabledAtBoot,   // FWPM_*_FLAG_DISABLED observed -> alarm
    string? Detail);
```

```csharp
public interface IRouteManager
{
    Task<RouteSnapshot> CaptureAsync(CancellationToken ct);   // before any mutation
    Task              ApplyAsync(TunnelRoutes routes, CancellationToken ct);
    Task              RestoreAsync(RouteSnapshot snapshot, CancellationToken ct);
    Task<IPAddress?>  GetNextHopForAsync(IPAddress destination, CancellationToken ct); // GetBestRoute2
    IAsyncEnumerable<RouteChange> WatchAsync(CancellationToken ct);                    // NotifyRouteChange2
}

/// <summary>Windows notes:
///  • CreateIpForwardEntry2 / SetIpForwardEntry2 / DeleteIpForwardEntry2 are admin-only.
///  • Use MIB_IPFORWARD_ROW2 (unified v4/v6); on-link => NextHop = 0.0.0.0 / ::.
///  • GetNextHopForAsync MUST be called for the server IP *before* adding 0.0.0.0/0 so
///    the pinned /32 + /128 can be computed — otherwise the tunnel loops.
///  • Caller must record the exact row (DestinationPrefix, NextHop, InterfaceLuid) so
///    teardown can match it.
///  • No transactional rollback exists; the snapshot is MyVpn's own responsibility.</summary>
public sealed record TunnelRoutes(
    ulong                InterfaceLuid,
    int                  InterfaceMetric,
    uint                 Mtu,
    bool                 DisableDefaultRoutes,
    IReadOnlyList<IPAddress> VpnServerAddresses,   // get pinned host routes
    IReadOnlyList<IPrefix>   IncludedPrefixes,     // split tunnel; empty = full tunnel
    IReadOnlyList<IPrefix>   ExcludedPrefixes);
```

```csharp
public interface IDnsConfigurator
{
    Task<DnsSnapshot> CaptureAsync(Guid adapterId, CancellationToken ct);
    Task              ApplyAsync(Guid adapterId, DnsPlan plan, CancellationToken ct);
    Task              RestoreAsync(Guid adapterId, DnsSnapshot snapshot, CancellationToken ct);
}

/// <summary>Windows notes:
///  • SetInterfaceDnsSettings / GetInterfaceDnsSettings (netioapi.h). The name in the
///    brief, DNS_SetInterfaceDnsSettings, does not exist.
///  • Only fields whose bit is set in DNS_INTERFACE_SETTINGS.Flags are written; zero the
///    rest. DNS_SETTING_IPV6 retargets the whole struct => two calls for dual stack.
///  • Split DNS uses the NRPT (Add-DnsClientNrptRule / MS-GPNRPT registry), NOT the
///    non-existent DnsSetNrptTable / DnsAddPolicyTableRule.
///  • DoH (Windows 11) = DNS_INTERFACE_SETTINGS3 + DNS_SETTING_DOH + DNS_SERVER_PROPERTY.
///  • Snapshot is mandatory: there is no OS rollback and no crash cleanup.</summary>
public sealed record DnsPlan(
    IReadOnlyList<IPAddress> NameServersV4,
    IReadOnlyList<IPAddress> NameServersV6,
    IReadOnlyList<string>    SearchSuffixes,
    IReadOnlyList<NrptRule>  SplitDnsRules,        // namespace -> resolvers
    DohSettings?             Doh);
```

```csharp
public interface ISystemProxy
{
    ProxySnapshot Capture();                       // both stores
    Task          ApplyAsync(ProxyPlan plan, CancellationToken ct);
    Task          RestoreAsync(ProxySnapshot snapshot, CancellationToken ct);
}

/// <summary>Windows notes — this interface is split across two processes by necessity:
///  • WinINET (HKCU, per-user) must be written by the USER-SESSION process via
///    InternetSetOption(INTERNET_OPTION_PER_CONNECTION_OPTION) followed by
///    INTERNET_OPTION_SETTINGS_CHANGED and INTERNET_OPTION_REFRESH. A service must not
///    use WinINET at all.
///  • WinHTTP (machine) must be written by the SERVICE (netsh winhttp set proxy /
///    set advproxy setting-scope=machine). WinHttpSetDefaultProxyConfiguration is
///    deprecated on 8.1+.
///  • Capture must read both stores; InternetQueryOption is called twice
///    (size probe, then buffer).
///  • Never write the WinINET registry keys directly.
///  • "System proxy" does NOT cover Firefox unless it is set to use system settings.</summary>
public sealed record ProxyPlan(
    string?               PacUrl,            // http://127.0.0.1:<port>/proxy.pac, never file://
    IReadOnlyList<string> BypassList,
    string?               FixedProxy);       // e.g. socks=127.0.0.1:10808
```

```csharp
public interface IProcessRouter
{
    ProcessRoutingCapabilities Capabilities { get; }   // probed once at startup
    Task ApplyAsync(ProcessRoutingPlan plan, CancellationToken ct);
    Task ClearAsync(CancellationToken ct);
}

[Flags]
public enum ProcessRoutingCapabilities
{
    None                    = 0,
    XrayProcessRules        = 1,   // SOCKS/HTTP inbound + Xray `process` rule (best effort)
    WfpConnectionPolicy     = 2,   // FwpmConnectionPolicyAdd0 (availability UNVERIFIED)
    RouteTablePerDestination= 4,   // reliable, but not per-process
}

/// <summary>Honest statement of what this cannot do on Windows (§1.4):
///  • selective capture/redirect of an arbitrary app's packets into the TUN — needs a
///    kernel callout driver;
///  • reliable per-app attribution for UDP, non-ESTABLISHED TCP, short-lived sockets
///    and protected/high-privilege processes (Xray returns "not found");
///  • child-process inheritance: ALE_APP_ID is path-based and does not inherit, so a
///    differently-named child is not covered;
///  • retroactive coverage of an arbitrary already-running process tree.
/// The UI must state these limits rather than implying a reliable "per-app VPN".</summary>
```

```csharp
public interface ITunnelDevice : IAsyncDisposable
{
    ulong InterfaceLuid { get; }
    Guid  InterfaceGuid { get; }
    Task  StartAsync(TunnelOptions options, CancellationToken ct);
    Task  StopAsync(CancellationToken ct);
}
// Windows: either a Wintun P/Invoke owner, or a supervisor for xray.exe's `tun` inbound.
// Either way the service owns it; the LUID feeds IKillSwitch and IRouteManager.
```

### 2.6 What CANNOT be done reliably on Windows (consolidated)

State these in the product documentation, not just in code comments:

1. **Per-process routing into the TUN without a kernel driver** is only possible via the undocumented-version
   `FwpmConnectionPolicyAdd0`. Everything else is per-destination routing. `UNVERIFIED` availability means the
   feature must ship gated and be presented as "not available on this Windows build" when the probe fails.
2. **Reliable per-app traffic attribution** (Xray/sing-box `process` rules) — fails for UDP, short-lived
   sockets, non-`ESTABLISHED` TCP and protected processes. No user-mode fix exists.
3. **Redirecting an already-running arbitrary process tree** — impossible; you can only act on processes as
   they appear (ETW) or on trees you launched (job objects).
4. **Child-process inheritance in WFP `ALE_APP_ID`** — does not exist by design; each image path is its own
   app id.
5. **Overriding a host/domain firewall block** — WFP hard blocks win; MyVpn cannot "punch through" corporate
   policy, by design.
6. **Protection while the Base Filtering Engine is stopped** — no user-mode WFP policy is enforced.
7. **A guaranteed-clean network state after a crash** — no OS rollback for routes/interface DNS; MyVpn must
   self-heal from its own journal.
8. **Firefox coverage by "system proxy"** — Firefox has an independent proxy stack.
9. **A service setting the interactive user's WinINET proxy** — architecturally excluded by Microsoft.
10. **Instant SmartScreen trust** — removed for EV in 2024; reputation is earned over weeks.
11. **A graceful per-app story for AppContainer/MSIX apps** — `ALE_PACKAGE_ID` addresses the packaged subset
    only.

---

## 3. Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Lockdown (persistent) filters are silently **disabled at boot** because the provider's `serviceName` is missing or the service is not auto-start | Medium | **Leak** (fail-open) while the user believes they are protected | Always set `serviceName` + auto-start; enumerate own objects at startup and alarm on `*_FLAG_DISABLED`; CI test asserts the service start type |
| R2 | A WFP policy mistake bricks networking (no DNS, no DHCP, no tunnel) | Medium | **High** — user cannot work or reach support | Install inside one transaction with abort-on-error; permit DHCP/NDP and loopback by default; documented panic release; `netsh wfp dump` snapshot stored before first install |
| R3 | `FWPM_CONDITION_IP_LOCAL_INTERFACE` is `FWP_EMPTY` in some classifications (§1.1.6), so the TUN permit misses | Medium | Connection drop / broken split tunnel — but fail-closed, not a leak | Test at both `ALE_AUTH_CONNECT` and reauthorization; keep the packet-layer backstop; log the classification when a permit misses |
| R4 | `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` semantics are **documented inconsistently** (§1.1.6) | Certain (ambiguity) | Wrong hardening assumption | Do not depend on it for correctness; the weight-0 block provides fail-closed under either reading; test on hardware before using the flag |
| R5 | `ALE_APP_ID` is path-based; a second process at `xray.exe`'s path inherits the tunnel exemption | Medium | Privilege/exemption leak | Add `ALE_USER_ID` security-descriptor condition; ACL the install dir to Administrators/SYSTEM; verify image signature at launch; never install into a user-writable path |
| R6 | Service crash leaves stale routes/DNS and no WFP policy | High (over time) | Broken networking; or a leak if Mode B filters remain without the tunnel | Journal + re-run teardown on start; define and document Mode B's intentional fail-closed-after-crash behaviour |
| R7 | `FwpmConnectionPolicyAdd0` unavailable on the user's build | Medium | Feature gap vs competitor claims | Startup probe + capability flag; UI degrades honestly; do not architect v1 on it |
| R8 | Wintun EULA breach (e.g. shipping the extracted `.sys`, renaming, patching) | Low | Legal exposure; loss of the commercial distribution path | Bundle the pristine DLL + `LICENSE.txt` exactly as Xray does; a build-time hash check against the published 0.14.1 SHA-256; automated "no `.sys`/`.cat` in the payload" test |
| R9 | Wintun/`xray.exe` upgrade drift (Xray bundles a different Wintun version) | Medium | Version skew, two `wintun.dll` copies | One owner of the TUN; if option B, ship Xray's DLL and do not ship a second copy; pin and verify hashes in CI |
| R10 | `SERVICE_SID_TYPE_RESTRICTED` + Wintun device DACL incompatibility (§1.3.6) | Medium | TUN fails to start on some configurations | Decide the account after a hardware spike; if LocalSystem is required, document why and harden elsewhere |
| R11 | Per-user WinINET proxy write from a service silently does nothing | High if attempted | Feature appears broken; user's browser still leaks | Put the WinINET write in the UI process; make the feature opt-in; verify after write by reading back |
| R12 | GPO/managed-machine conflicts (firewall locked, proxy locked) | Medium | Silent non-enforcement | Detect and surface; `LocalPolicyModifyState` for the firewall; never claim protected if verification fails |
| R13 | SmartScreen warnings on early releases reduce install conversion | High | Business | Azure Artifact Signing or OV+HSM, one constant identity, sign every build, submit for enterprise pilots, document the browser "More info → Run anyway" path |
| R14 | WiX OSMF sponsorship obligation (>$10k revenue) discovered late | Medium | Cost/compliance surprise | Decide the packaging toolchain before v1 freeze; evaluate WiX v4 vs alternatives |
| R15 | IPv6 leak while the user assumes IPv4-only tunnelling | Medium | **Leak** (traffic bypasses the tunnel) | Always install v6 filters and `::/0` (or explicitly `DisableDefaultRoutes` and disable v6 per policy); test with an IPv6-capable captive network |
| R16 | Server IP changes (CDN/round-robin) after the pinned host route is set | Medium | Tunnel loop or connection loss | Re-resolve and re-pin on reconnect and on route-change notifications; watch `NotifyRouteChange2` |
| R17 | DNS leak via a resolver not in the permit list | Medium | Privacy leak | Permit DNS only to the configured resolvers and block port 53 elsewhere; verify with a capture test |
| R18 | Protected/EDR processes (e.g. Kaspersky) defeat per-app attribution | Medium | Feature unreliable for a subset of users | Detect and report; do not crash or misroute |

---

## 4. Implementation plan

Ordered so that the riskiest, most design-changing unknowns are resolved first. Each phase ends with a
go/no-go.

**Phase 0 — Hardware spike (1–2 weeks, Windows VM + real x64 and arm64 hardware).**
Answers the four `UNVERIFIED` items that can change the architecture:
1. Does a dedicated/restricted service account (or `SERVICE_SID_TYPE_RESTRICTED` LocalSystem) survive Wintun
   ring registration? → final service-account decision (§1.3.6).
2. `FwpmConnectionPolicyAdd0` availability and behaviour on Windows 10 22H2 and Windows 11 21H2/H2x64+arm64
   (§1.4.3).
3. Do `BOOTTIME` filters added from user mode at the IP-packet layers actually enforce before BFE starts, and
   which conditions classify? (§1.1.5).
4. `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` observable semantics (§1.1.6).
Deliverable: a short spike report that either confirms or amends §2–§3.

**Phase 1 — Service skeleton + IPC (1–2 weeks).**
`MyVpnSvc` host, `AddWindowsService()`, LocalSystem + unrestricted service SID, auto-start, SCM descriptor
lockdown, MSI/WiX service install. One first-instance named pipe with the explicit DACL and
`PIPE_REJECT_REMOTE_CLIENTS`; gRPC over named pipes (Kestrel `ListenNamedPipe` + `GrpcChannel`
`ConnectCallback`); the full §1.3.3 identity gate with an allow-list of exactly `MyVpn.exe`. Health/status
RPC. **Exit criterion:** an unauthorised client (a copy of the UI at another path, a different user, a
different session) is rejected and the rejection is logged.

**Phase 2 — TUN + routes + DNS bring-up (2–3 weeks).**
Pick option B (supervise `xray.exe`'s `tun` inbound) unless Phase 0 mandates option A. `IRouteManager` with
snapshot/apply/restore, the server-IP pinning, journal-based crash recovery, `IDnsConfigurator` with
snapshot/apply/restore and NRPT split DNS. **Exit criterion:** connect/disconnect/kill-the-service/reconnect
leaves the route table, interface DNS and adapter state identical to the pre-connect snapshot (byte-compared
via `GetIpForwardTable2` + `GetInterfaceDnsSettings`).

**Phase 3 — Kill switch (2–3 weeks).**
The full P/Invoke layer (`FwpmEngineOpen0`, provider/sublayer/filter add, transaction begin/commit/abort,
`FwpmGetAppIdFromFileName0`, delete-by-key), Mode A dynamic filters, the weight table from §2.3, the startup
disabled-object self-check, and the panic release. **Exit criterion:** a scripted leak test (below) passes on
x64 and arm64; Mode A leaves no objects behind after `FwpmEngineClose0`.

**Phase 4 — Lockdown mode (1–2 weeks).**
Persistent provider/sublayer/filters with `serviceName`, the equivalent `BOOTTIME` set, the boot-transition
test, and the explicit disable path.

**Phase 5 — System proxy (1 week).**
User-session WinINET writer with snapshot/restore and read-back verification; service-side WinHTTP via
`netsh winhttp`; optional local PAC server with the correct content type; the "Firefox not covered" warning.

**Phase 6 — Per-process routing (2–3 weeks, feature-flagged).**
Xray `process` rules as the baseline, with honest capability reporting; `FwpmConnectionPolicyAdd0` when the
Phase 0 probe says it exists. UI copy must state UDP/protected-process/long-lived-tree limitations.

**Phase 7 — Packaging, signing, hardening (2 weeks + lead time).**
WiX MSI + Burn bundle, Artifact Signing onboarding (1–20 business days for identity validation — start this
in Phase 2 at the latest), sign every PE/MSI/bundle, hash-verify the bundled `wintun.dll`, add the
"no `.sys`/`.cat` in the payload" and "no `wintun.dll` outside the sanctioned copy" build checks.

**Phase 8 — arm64 + Windows 10 validation (1–2 weeks).**
Run the whole matrix on arm64 and on Windows 10 22H2 (the oldest supported build), because the Wintun arm64
driver and the `SetInterfaceDnsSettings` build floor (19041) are hard boundaries.

---

## 5. Files / modules affected (`src/MyVpn.*`)

The repository currently contains **no `src/` tree** (only `docs/research/`), so this is the **proposed**
module map, not a description of existing files. It is written so the same shape can be mirrored by the other
platform documents.

```
src/
  MyVpn.Core.Abstractions/
    IKillSwitch.cs                      # §2.5 contract + KillSwitchPlan/Status
    IRouteManager.cs                    # §2.5 + RouteSnapshot/RouteChange
    IDnsConfigurator.cs                 # §2.5 + DnsSnapshot/DnsPlan/NrptRule
    ISystemProxy.cs                     # §2.5 + ProxySnapshot/ProxyPlan
    IProcessRouter.cs                   # §2.5 + ProcessRoutingCapabilities
    ITunnelDevice.cs                    # §2.5 + TunnelOptions
    IPrefix.cs, IpcContracts/*.proto    # shared types + gRPC service definitions

  MyVpn.Platform.Windows/               # Windows-only implementation (net8.0-windows)
    Interop/
      Fwpuclnt.cs                       # P/Invoke: FwpmEngineOpen0/Close0, Provider/SubLayer/Filter Add0,
                                        #   TransactionBegin/Commit/Abort0, GetAppIdFromFileName0,
                                        #   FreeMemory0, *DeleteByKey0, FwpmConnectionPolicyAdd0
      FwpmTypes.cs                      # FWPM_SESSION0, FWPM_PROVIDER0, FWPM_SUBLAYER0, FWPM_FILTER0,
                                        #   FWPM_FILTER_CONDITION0, FWPM_ACTION0, FWP_VALUE0, FWP_BYTE_BLOB,
                                        #   FWPM_PROVIDER_CONTEXT3, FWPM_DISPLAY_DATA0
      WfpGuids.cs                       # layer/condition/sublayer/flag constants incl.
                                        #   ALE_AUTH_CONNECT_V4/V6, ALE_AUTH_RECV_ACCEPT_V4/V6,
                                        #   OUTBOUND_IPPACKET_V4/V6, ALE_APP_ID, ALE_USER_ID,
                                        #   IP_LOCAL_INTERFACE, IP_PROTOCOL, *_PORT, FLAGS, IS_LOOPBACK
      NetIoApi.cs                       # CreateIpForwardEntry2/Set/Delete, GetIpForwardTable2,
                                        #   InitializeIpForwardEntry, GetBestRoute2, GetAdaptersAddresses,
                                        #   CreateUnicastIpAddressEntry, Get/SetIpInterfaceEntry,
                                        #   Get/SetInterfaceDnsSettings, NotifyRouteChange2
      WinInet.cs                        # InternetSetOption/InternetQueryOption,
                                        #   INTERNET_PER_CONN_OPTION_LIST
      NamedPipeIdentity.cs              # GetNamedPipeClientProcessId/SessionId,
                                        #   OpenProcess/QueryFullProcessImageName, WinVerifyTrust,
                                        #   OpenProcessToken/GetTokenInformation, WTSEnumerateSessions
      Wintun.cs                         # wintun.h exports (only if Phase 2 chooses option A)
    KillSwitch/
      WfpKillSwitch.cs                  # IKillSwitch (Mode A + Mode B + boot-time companion)
      WfpFilterPlan.cs                  # the weight table from §2.3 as data
      WfpSelfCheck.cs                   # enumerates own objects, detects *_FLAG_DISABLED
      WfpPanicRelease.cs                # documented emergency teardown
    Routing/
      WindowsRouteManager.cs            # IRouteManager
      RouteSnapshotStore.cs             # journal, clean-shutdown marker
      NetworkChangeWatcher.cs           # NotifyRouteChange2 / adapter-change handling
    Dns/
      WindowsDnsConfigurator.cs         # IDnsConfigurator (SetInterfaceDnsSettings + NRPT + DoH)
    Proxy/
      WindowsSystemProxyService.cs      # WinHTTP side (service)
      WindowsWinInetProxyClient.cs      # WinINET side (invoked by the UI)
      LocalPacServer.cs                 # http://127.0.0.1:<port>/proxy.pac
    ProcessRouting/
      ProcessRoutingProbe.cs            # capability detection (Xray rules, FwpmConnectionPolicyAdd0)
      XrayProcessRouting.cs, WfpConnectionPolicyRouting.cs

  MyVpn.Service/                        # MyVpnSvc.exe
    Program.cs                          # AddWindowsService(), LocalSystem, auto-start
    Ipc/
      PipeServer.cs                     # NamedPipeServerStreamAcl.Create, FIRST_PIPE_INSTANCE, ACL
      ClientIdentityGate.cs             # the §1.3.3 sequence, fail-closed
      ControlService.cs                 # gRPC service; closed command set only
    Orchestration/
      TunnelOrchestrator.cs             # the connect/disconnect sequences from §2.4
      StartupRecovery.cs                # re-run teardown on start

  MyVpn.App/                            # MyVpn.exe (WPF/WinUI, user session)
    Ipc/PipeClient.cs                   # GrpcChannel + ConnectCallback(NamedPipeClientStream)
    Proxy/WinInetProxyWriter.cs         # the per-user WinINET write
    ViewModels/LeakProtectionViewModel.cs  # honest capability/limitation display

installer/
  MyVpn.wxs                             # MSI: files, service, ACLs, WFP/Wintun prerequisites
  MyVpn.Bundle.wxs                      # WiX Burn bootstrapper
  signing/sign-all.ps1                  # signtool for every PE + MSI + bundle, RFC3161 timestamp
  payload/wintun.dll + wintun-LICENSE.txt   # pristine 0.14.1, per-arch, hash-verified in CI
```

---

## 6. Tests

Windows-only tests are marked **W-MANUAL** (require an interactive Windows machine and/or elevation) or
**W-AUTO** (automatable on a Windows CI runner with an admin agent). Nothing here is runnable on the Linux
research host.

### 6.1 Kill switch

| Test | Type | Method / acceptance |
|---|---|---|
| Filter set installs transactionally | W-AUTO | Arm the kill switch; `netsh wfp show filters file=-` (or `FwpmFilterEnum0`) must list exactly the expected filters in MyVpn's sub-layer at weight 0xFFFF |
| Fail-closed: all non-tunnel egress blocked | **W-MANUAL** | `pktmon start --etw -c` (or Wireshark) on the physical NIC; with the tunnel down and the kill switch armed, run `curl`/`ping`/a browser: **zero** packets may leave the physical adapter to non-permitted destinations |
| Tunnel traffic still works | W-AUTO | With the kill switch armed and the tunnel up, `curl https://ifconfig.me` returns the VPN egress IP |
| DNS cannot leak | **W-MANUAL** | Configure a resolver *outside* the permit list; `Resolve-DnsName` must fail/time out; capture must show no port-53 egress to it |
| Loopback unaffected | W-AUTO | The local SOCKS/HTTP inbound and IPC still work with the kill switch armed |
| Lease renewal survives | W-AUTO | With the kill switch armed, `ipconfig /renew` on the TUN must succeed (DHCP permits in place) |
| IPv6 is not a leak path | **W-MANUAL** | On an IPv6-capable network, capture both families; no v6 egress outside the tunnel |
| Pre-existing flows are cut | W-AUTO | Open a long-lived download, arm the kill switch, confirm the transfer stalls within one packet (ALE reauthorization) and that nothing egresses the physical NIC |
| No orphans after disarm | W-AUTO | Disarm; enumerate filters/sublayer/provider — MyVpn objects must be gone (Mode A: `FwpmEngineClose0` removes them) |
| **Lockdown survives reboot** | **W-MANUAL** | Arm lockdown, reboot, and before the service starts confirm egress is still blocked (`netsh wfp show boottimepolicy`, then post-BFE `netsh wfp show filters`); then confirm the service starts and the tunnel comes up |
| Disabled-object alarm | W-AUTO | Set the service to Manual/Disabled, reboot, start the service manually: the self-check must report `*_FLAG_DISABLED` and the UI must show "protection unavailable" |
| Panic release works | W-AUTO | With lockdown armed and the tunnel broken, the documented release command must restore connectivity |
| Cannot bypass a host firewall block | W-MANUAL | Add a Windows Firewall block rule for a test app; MyVpn must not be able to permit it |
| BFE stopped → protection reported unavailable | W-MANUAL | Stop the Base Filtering Engine; the UI must not claim protection |

### 6.2 Service and IPC security

| Test | Type | Method / acceptance |
|---|---|---|
| Unauthorised path rejected | W-AUTO | Run the UI binary from a copied path (`%TEMP%`) and connect: rejected, logged, no command dispatched |
| Unauthorised user rejected | W-AUTO\* | Connect from a second local account (or a different session): rejected |
| Different session rejected | W-MANUAL | Fast-user-switch / RDP in from another session and attempt to connect: rejected |
| Squatting detected | W-AUTO | Pre-create `\\.\pipe\MyVpnSvc.<guid>`; the service must fail closed and log, not silently serve |
| ACL is minimal | W-AUTO | `Get-Acl`/`GetSecurityInfo` on the pipe: only SYSTEM, Administrators and the interactive user SID appear; **no** `Everyone`/`ANONYMOUS` ACE; the user lacks `CreateNewInstance` |
| Remote clients rejected | W-AUTO | From another machine, attempt to open the pipe: fails (`PIPE_REJECT_REMOTE_CLIENTS`) |
| Oversize frame rejected | W-AUTO | Send a frame above the cap: connection closed, no allocation blow-up, event logged |
| Connect/read timeouts hold | W-AUTO | Never-connected and hung clients must not stall the service (`Connect(ms)` timeout, per-request `CancellationToken`) |
| Service cannot be reconfigured by non-admins | W-AUTO | `sc sdshow MyVpnSvc` reviewed; a non-admin `sc config`/`sc stop` attempt fails |
| PID-reuse race not exploitable | W-AUTO | Kill and rapidly recreate a client; the gate must re-run per connection and never authorise from a cached PID |

\* automatable if the CI agent can create a second local account.

### 6.3 Routing, DNS, proxy state integrity

| Test | Type | Method / acceptance |
|---|---|---|
| Snapshot/restore fidelity | W-AUTO | Record `GetIpForwardTable2` + `GetIpInterfaceEntry` + `GetInterfaceDnsSettings` before connect; after disconnect they must be value-identical |
| Service-kill recovery | W-AUTO | Kill `MyVpnSvc` mid-session with `taskkill /f`; on next start the journal must drive teardown and the table must return to baseline |
| Server route never enters the tunnel | W-AUTO | `GetBestRoute2` for each server IP must report the **physical** interface after full-tunnel routes are installed (loop prevention) |
| Roaming re-pins the host route | W-MANUAL | Disable Wi-Fi / move to Ethernet; the tunnel must recover and the pinned `/32` must be updated |
| Default route wins | W-AUTO | `Get-NetRoute 0.0.0.0/0` shows the TUN with a lower total metric than the physical NIC (or the physical NIC has `IgnoreDefaultRoutes`) |
| MTU applied | W-AUTO | `Get-NetIPInterface -InterfaceAlias <tun>` reports the configured `NlMtu` |
| Split DNS works | W-AUTO | With an NRPT rule for a test namespace, `Resolve-DnsName` for that namespace hits the VPN resolver and others do not (`Get-DnsClientNrptPolicy -Effective`) |
| DoH configured (Windows 11 only) | W-AUTO | `Get-DnsClientDohServerAddress`/interface settings reflect the request; "Require DoH" behaviour tested against a non-listed resolver to confirm the documented failure mode |
| WinINET proxy set and read back | W-AUTO | After apply, `InternetQueryOption(...PER_CONNECTION_OPTION)` returns the values; the setting is visible in Settings → Network → Proxy |
| WinHTTP proxy set | W-AUTO | `netsh winhttp show proxy` reflects the change; a BITS/WinHTTP request honours it |
| Proxy restore on crash | W-AUTO | Kill the UI mid-session; next launch must detect the journal and restore WinINET |

### 6.4 TUN and packaging

| Test | Type | Method / acceptance |
|---|---|---|
| Wintun driver installs on a clean machine | **W-MANUAL** | Fresh Windows 10 22H2 and Windows 11, x64 and arm64: install from the MSI; the adapter appears and `TUN_IOCTL_REGISTER_RINGS` succeeds |
| arm64 end-to-end | **W-MANUAL** | Windows 11 on ARM: adapter, routes, DNS, kill switch all work with `bin/arm64/wintun.dll` |
| Payload hygiene | W-AUTO | Build-output test: exactly one `wintun.dll` per architecture, byte-hash equals the published 0.14.1 hash, `wintun-LICENSE.txt` present, and **no** `*.sys`/`*.cat` in the payload |
| Signature coverage | W-AUTO | `signtool verify /pa /all` succeeds on every shipped PE, the MSI and the bundle; all have RFC3161 timestamps |
| Uninstall restores state | W-AUTO | Uninstall from a connected state: adapter gone, routes/DNS/proxy baseline, service removed, WFP objects gone |
| Upgrade in place | W-AUTO | Install v(N), connect, upgrade to v(N+1): no duplicate adapters, no orphaned WFP objects, state restored |
| Smart App Control / SmartScreen behaviour | **W-MANUAL** | On a Windows 11 machine with Smart App Control on, document the actual install experience per release for the support knowledge base |
