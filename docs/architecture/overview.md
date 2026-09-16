# MyVpn architecture overview

Status: **foundation**. This document describes the intended architecture and
states plainly which parts exist in `src/` today and which do not. Read the
["Implemented vs planned"](#implemented-vs-planned) table before treating
anything here as available.

MyVpn is a cross-platform (Windows 10/11, Linux, macOS Intel + Apple Silicon)
desktop VPN client built on **Xray-core only** — the native Xray TUN inbound is
the sole network core, and sing-box is excluded (ADR-0002). It is C# / .NET 8
with Avalonia UI, organised as Clean Architecture + MVVM + DI over a Platform
Abstraction Layer, with a separate privileged helper service.

## Layer diagram

```
                       ┌──────────────────────────────────────────────┐
   no dependencies     │  MyVpn.Core                                  │
   (domain only)       │  domain model · value objects · state        │
                       │  machine · settings record · pure validators │
                       └───────────────────────┬──────────────────────┘
                                               │
                       ┌───────────────────────▼──────────────────────┐
   ports + use cases   │  MyVpn.Application                           │
                       │  capability interfaces · use cases           │
                       └───────────────────────┬──────────────────────┘
                                               │
                       ┌───────────────────────▼──────────────────────┐
   adapters            │  MyVpn.Infrastructure                        │
                       │  Xray engine · geo data · subscriptions ·    │
                       │  settings · diagnostics                      │
                       └───────────────────────┬──────────────────────┘
                                               │
                       ┌───────────────────────▼──────────────────────┐
   OS seam             │  MyVpn.Platform.Abstractions                 │
                       │  capability interfaces + PURE plan renderers  │
                       └───────────────────────┬──────────────────────┘
                                               │
                       ┌───────────────────────▼──────────────────────┐
   executors           │  MyVpn.Platform.{Linux,Windows,MacOS}        │
                       │  thin executors that need privilege          │
                       └───────────────────────┬──────────────────────┘
                                               │
        ┌──────────────────────┬───────────────┴───────────────┬──────────────────┐
        │                      │                               │                  │
┌───────▼───────┐   ┌──────────▼─────────┐         ┌───────────▼──────┐  ┌────────▼────────┐
│ MyVpn.UI      │   │ MyVpn.Ipc          │         │ MyVpn.Cli        │  │ MyVpn.Service   │
│ Avalonia      │──▶│ typed contract +   │◀────────│ headless driver  │  │ privileged host │
│ (never root)  │   │ authenticated      │         │ (diagnose etc.)  │  │ (system service)│
└───────────────┘   │ transport          │         └──────────────────┘  └─────────────────┘
                    └────────────────────┘
```

## The dependency rule

The single rule that must not bend: **dependencies point inward, and the UI
never performs privileged or network-mutating work.**

* `MyVpn.Core` depends on nothing. No NuGet packages, no I/O, no OS API.
  Everything in it is a pure function or an immutable value and must be
  unit-testable without a filesystem, a network or a process.
* `MyVpn.Application` depends only on Core (plus logging abstractions). It
  declares the ports and orchestrates use cases; concrete implementations are
  injected, which is what makes the use cases testable with fakes.
* `MyVpn.Infrastructure` depends on Core + Application + Platform.Abstractions.
  It is the only place that touches the filesystem, HTTP and the Xray process.
* `MyVpn.Platform.Abstractions` depends only on Core. It holds *capability
  interfaces* (`IKillSwitch`, `IRouteManager`, `IDnsConfigurator`,
  `IProcessRouter`, `ISystemProxy`, `IPrivilegedHost`, `ITunDeviceManager`) plus
  **plan** value objects and **pure renderers** that turn a platform-neutral
  plan into nftables text / WFP filter descriptors / PF anchor text.
* `MyVpn.Platform.{Linux,Windows,MacOS}` depend on Core +
  Platform.Abstractions and contain only the thin executors that need privilege.
* `MyVpn.Ipc` depends only on Core so the wire contract is auditable in
  isolation.
* `MyVpn.UI`, `MyVpn.Cli` and `MyVpn.Service` are the hosts. The UI talks only
  to a service facade — in-process for proxy-only mode, IPC-backed for TUN /
  kill-switch mode — and never to a platform assembly directly.

Splitting *plan* (pure) from *execution* (privileged) is what makes the OS
integration testable on an unprivileged CI runner: renderers are covered by unit
tests on every platform, and only the executors need root.

All projects target plain `net8.0`, including the platform layers, so the whole
solution restores, builds and unit-tests on any runner; OS behaviour is selected
at runtime by capability probing, and unsafe OS calls are
`RuntimeInformation`-guarded (ADR-0004).

## Module inventory

Responsibility and dependencies as declared in each `.csproj`; **source
presence** is stated per project because it varies.

| Project | Responsibility | Depends on | Source today |
|---|---|---|---|
| `MyVpn.Core` | Domain model, value objects, the VPN state machine, the settings/configuration model, pure validators and parsers. Zero package references. | — | **Present** (`Core/`) — see the file inventory below |
| `MyVpn.Application` | Ports (capability interfaces) and use cases: connect, disconnect, switch profile, update subscriptions, update geo data, run diagnostics. | Core, logging abstractions | **None** — `.csproj` only |
| `MyVpn.Infrastructure` | Xray process engine, config generation, geo-data management, subscription download/parsing, settings persistence, logging, updates, diagnostics. | Core, Application, Platform.Abstractions | **None** — `.csproj` only |
| `MyVpn.Platform.Abstractions` | Capability interfaces plus pure plan renderers (nftables / WFP / PF). | Core | **None** — `.csproj` only |
| `MyVpn.Platform.Linux` | Linux executors: nftables, netlink/`ip` routing, `systemd-resolved`/`resolvconf` DNS, cgroup v2, system proxy, D-Bus helper client. | Core, Platform.Abstractions | **None** — `.csproj` only |
| `MyVpn.Platform.Windows` | Windows executors: WFP via `fwpuclnt.dll`, NetIO routing, `SetInterfaceDnsSettings`/NRPT, Wintun adapter recovery, WinINET/WinHTTP proxy, named-pipe client. | Core, Platform.Abstractions | **None** — `.csproj` only |
| `MyVpn.Platform.MacOS` | macOS executors: PF anchors, `PF_ROUTE`/`route`, `scutil`/`/etc/resolver`, utun lifecycle, XPC helper client, `networksetup` proxy. | Core, Platform.Abstractions | **None** — `.csproj` only |
| `MyVpn.Ipc` | Typed request/response contract plus the authenticated transport (Unix socket / named pipe) and peer-credential verification. | Core | **None** — `.csproj` only |
| `MyVpn.Service` | Privileged host: TUN lifecycle, routes, firewall/kill switch, DNS, process routing, Xray supervision. No "run this command" or "apply raw config" operation. | Core, Application, Infrastructure, Platform.Abstractions, all platform projects, Ipc | **None** — `.csproj` only, **and no entry point** |
| `MyVpn.Cli` | Headless driver: integration testing of the real pipeline, `diagnose`, power-user use. Exercises the same application services as the GUI. | Core, Application, Infrastructure, Platform.Abstractions, all platform projects, Ipc | **None** — `.csproj` only, **and no entry point** |
| `MyVpn.UI` | Avalonia desktop shell, MVVM, DI, theming and localization. Never touches the firewall, routes, DNS, the Xray process or any privileged API. | Core, Application, Infrastructure, Platform.Abstractions, Ipc | **None** — `.csproj` only, **and no entry point** |
| `tests/MyVpn.Core.Tests` | Unit tests for Core. | Core | **None** — `.csproj` only |
| `tests/MyVpn.Infrastructure.Tests` | Tests for the infrastructure adapters. | Core, Application, Infrastructure | **None** — `.csproj` only |
| `tests/MyVpn.Platform.Tests` | Tests for the pure platform renderers. | Core, Platform.Abstractions, all platform projects | **None** — `.csproj` only |
| `tests/MyVpn.Integration.Tests` | End-to-end pipeline tests that may spawn processes; privileged cases are marked `Category = "RequiresRoot"`. | Core, Application, Infrastructure, Ipc | **None** — `.csproj` only |

### What is actually implemented inside `MyVpn.Core`

Everything under `src/` outside `MyVpn.Core` is a project shell. `MyVpn.Core` is
real and contains:

| Area | Types |
|---|---|
| `Results/` | `Result`, `Result<T>` (map/bind, no silent default), `MyVpnError` (`Code`, `MessageKey`, `Severity`, `TechnicalDetail`, `RemediationKey`, `Args`), `ErrorSeverity`, `ErrorCodes` (the stable diagnostics contract — never localized) |
| `Domain/` | `VpnConnectionState` (`Disconnected`…`Faulted`) and its extensions (`IsTransitional`, `IsTunnelUp`, **`RequiresKillSwitch`**), `VpnStateMachine` (table-driven legal transitions, history, `CanStartConnect`, `ForceTransitionTo` for crash recovery), `VpnStateChange`, `ServerProfile` + `ServerEndpoint` (validated, with `EffectiveServerName`), `ServerScore` + `ScoreWeights` (latency, jitter, loss, success rate, unexpected disconnects, throughput — explicitly not ping-only), `Enums` (`ProxyProtocol`, `TransportKind`, `SecurityKind`, `TlsFingerprint`, `VlessFlow`, `TunnelMode`, `KillSwitchMode`, `Ipv6Mode`, `ProcessRoutingMode`, `DnsMode`, `AppTheme`, `UiDensity`, `AppLanguage`) |
| `Settings/` | `AppSettings` (immutable record, `SchemaVersion`, nested validating records, aggregating `Validate()`) with `DnsSettings`, `CustomRoutingRule`, `RoutingSettings`, `TunSettings`, `MuxSettings`, `ProxySettings`, `ProcessRoutingProfile`, `ProcessSelector`, `ProcessRoutingSettings`, `ConnectivitySettings`, `UpdateSettings`, `LoggingSettings`, `SubscriptionSettings`, `PrivacySettings`; plus `LogVerbosity`, `UpdateChannel`, `TransportStrategy`, `ProcessSelectorKind` |
| `Subscriptions/` | The header-safety subsystem: `RawHeaderBag` (bounded capture, RFC 9110 token validation, C0/`0x7F` rejection, SHA-256 fingerprints), `HeaderLimits`, `RawHeader`, `RejectedHeader`, `HeaderCatalog` (**65 headers**: 12 `Auto`, 48 `RequiresConfirmation`, 5 `Refused`), `SubscriptionHeaderRegistry` (ordered, isolated, gate-enforcing), `HeaderApplyGate`, `DuplicatePolicy`, `HeaderValueKind`, `ChangeRisk`, `HeaderDescriptor`, `SubscriptionMetadata`, `PendingChange` (value-bound `ConsentToken`), `ParseResult`, `HeaderParseContext`, `ISubscriptionHeaderParser`, `SubscriptionHeaderParserBase` and seven parsers (`ProfileIdentityParser`, `UserInfoHeaderParser`, `LinkHeaderParser`, `AnnouncementParser`, `ScheduleParser`, `ConfirmationGatedParser`, `RefusedHeaderParser`), `ToggleState` + `HeaderValueParsing`, `SubscriptionUserInfo` |
| `Geo/` | `GeoAssetKind` + extensions, `GeoAssetHealth`, `GeoAssetInfo`, `GeoAssetValidator`, `GeoAssetValidationResult`, `GeoDataConstants`, `GeoDataStatus`, `GeoRuleAvailability`, `ProtoReader` (allocation-light, `ref struct`) |
| `Net/` | `CidrBlock` (IPv4/IPv6, IPv4-mapped handling), `NetworkText`, `UrlSafety` + `UrlRejectionReason` (https-only, no embedded credentials, loopback/RFC1918/link-local/CGNAT/metadata refusal, re-checkable against a resolved address) |
| `Parsing/` | `ShareLinkParser` + `ShareLinkFailure` + `ShareLinkBatch` (per-line errors, never aborts the whole payload), `Base64Tolerant` (standard and URL-safe, padded or not), `CountryInference` (flag emoji, bracketed code, or English/Russian/Chinese name; `null` rather than guess) |
| `Xray/` | `XrayVersion` (tolerant date-based parser and comparer), `XrayVersionSupport`, `XrayVersionPolicy` (`FirstWithTun = 26.1.13`, `MinimumForTun = 26.4.15`, `Recommended = 26.9.9`, `KnownBroken = [26.4.13]`) |

## Connect / disconnect sequence

The numbered flow the implementation must follow. Ordering is the correctness
property: the fail-closed policy is armed before the default route moves, and
released only after it is restored (ADR-0006), so the failure mode is "no
network", never "traffic leaks".

### Connect

1. **Acquire the settings snapshot.** The connect use case receives the
   immutable `AppSettings` value, so a later UI change cannot mutate the
   configuration this tunnel was built from.
2. **Validate the profile.** `ServerProfile.Validate()` — address, port,
   protocol-specific credential, REALITY public key, gRPC service name. A
   malformed profile fails here with a per-server error, not inside Xray.
3. **Pre-flight the environment.**
   * Locate and probe the Xray binary: absolute path, SHA-256, parsed version,
     capabilities. Refuse below `26.4.15`; reject `26.4.13`; warn below
     `26.9.9` (ADR-0002).
   * Inspect geo assets and compute `GeoRuleAvailability` (ADR-0003).
   * Probe privileges (Wintun/WFP, `/dev/net/tun` + `CAP_NET_ADMIN`, utun root)
     and report `privilege.*` if unavailable (ADR-0005).
4. **Resolve the server address *before* any filtering.** Endpoint addresses are
   resolved while DNS still works; otherwise a fail-closed policy would lock out
   the server (ADR-0011).
5. **Generate a typed Xray config** (pure, with golden-JSON tests) from the
   resolved plan: TUN inbound with only the eight real fields, `mux`/`sockopt`
   coherence assertions, routing rules gated by `GeoRuleAvailability`, and the
   asset directory injected through **two** channels (process environment and
   the root `env` object).
6. **Validate the generated config with the real core:** `xray run -c <file>
   -test`. Non-zero maps to `config.rejected_by_core`, with Xray's stderr
   surfaced as technical detail. Only then is the candidate promoted to the live
   path.
7. **Snapshot current network state** into the privileged helper's journal:
   default route and next hop, per-interface DNS, firewall state (PF ruleset and
   enable token, WFP snapshot diagnostics), system proxy for every service.
8. **Arm the kill switch** in one transaction, with the resolved endpoint
   addresses already allow-listed. From here on, egress is fail-closed.
9. **Start the core and bring the interface up.** Xray creates the TUN, assigns
   addresses from `gateway`, installs `autoSystemRoutingTable` and binds its own
   outbound sockets to the physical interface via `autoOutboundsInterface`.
10. **Install the uplink host route** (`/32`/`/128` to the server via the
    physical next hop) as the second, independent loop-prevention layer.
11. **Configure DNS** on the tunnel link only: `resolvectl` per-link on Linux,
    `SetInterfaceDnsSettings`/NRPT on Windows, `scutil`/`/etc/resolver` on macOS.
    Never rewrite `/etc/resolv.conf`; never touch `nsswitch.conf`.
12. **Verify, don't assume.** Confirm the interface exists with the requested
    name/MTU/addresses, that the server's own route still egresses the physical
    interface, that DNS answers through the tunnel, and that the `sockopt`
    binding did not silently fail (`failed to set Interface` / `failed to set
    SO_MARK` are fatal). Health is an application-level request through the
    tunnel — **never** a TCP `connect()` or an ICMP `ping`, both of which the TUN
    stack satisfies locally.
13. **Transition state.** `VpnStateMachine` moves `Preparing → Connecting →
    Connected` (or `Degraded`), and only then is the journal marked clean and the
    UI told the tunnel is up. `RequiresKillSwitch` stays true for `Degraded`,
    `Reconnecting`, `Disconnecting` and `Faulted`.

### Disconnect (reverse order, idempotent, re-run on every service start)

1. Restore DNS from the snapshot, remove any split-DNS entries, flush caches.
2. Restore the system proxy from its snapshot.
3. Restore the original default route, then delete the server host route.
4. Release the kill switch **last** — restore the saved firewall state and
   release only MyVpn's own enable token (`pfctl -X <token>`, never `pfctl -d`);
   close the WFP session (dynamic objects vanish) or delete persistent objects
   by key.
5. Stop the core, close the TUN fd (the interface and its routes disappear with
   it), and sweep for orphans by PID + start time.
6. Clear the journal and transition to `Disconnected`.

Crash recovery is the same teardown, driven from the on-disk journal at the next
helper start, **before** any command is accepted. On Linux a
`ExecStopPost=--cleanup` pass and a `PartOf=` companion unit cover `SIGKILL`; on
macOS launchd `KeepAlive` plus the journal replay; on Windows the journal is the
only mechanism, because there is no OS rollback for routes or interface DNS.

## Diagnostics model

Diagnostics are structured data, not log scraping, and every failure carries a
stable machine code plus a localization key so the UI never shows raw technical
text.

* **`ErrorCodes` is the contract.** Values such as `geodata.corrupt`,
  `xray.version_unsupported`, `killswitch.apply_failed`, `dns.leak_detected`,
  `privilege.not_elevated`, `ipc.unauthorized` appear in exported bundles and on
  the IPC wire and are never localized. `MyVpnError` adds the human-facing
  `MessageKey`, `Args`, `Severity` (`Warning` / `Error` / `Critical`) and a
  `RemediationKey`.
* **Severity drives presentation**, not the UI's guesswork: a warning is a
  banner, an error is an inline failure, a critical escalates to a modal with a
  repair action.
* **`TechnicalDetail` is for logs and the diagnostics bundle only**, and the
  exporter is responsible for redacting secrets from it before export.
* **Capability reporting is part of diagnostics.** Every platform capability
  answers with a level — supported, supported-with-caveats, unsupported, or
  requires-managed-deployment — plus the statement and its evidence. The
  per-process routing matrix (ADR-0007) is reported this way so the UI can say
  "not available on this build" honestly.
* **The geo diagnostics report is the model for the rest.** It answers, in one
  boolean, the only question that matters (`WouldXrayFindAssets`): it renders the
  difference between "the file our validators approved" and "the path Xray will
  actually open", alongside candidate paths, the effective source (process env,
  config env, executable directory, FHS) and per-asset health, size and
  checksum.
* **A diagnostics bundle** collects: the resolved plan (effective mux/sockopt/
  cone/route settings — not just the requested ones), the Xray version and
  binary hash, the config-schema golden comparison, the journal state, the
  firewall artefact actually loaded, the DNS snapshot, and the redacted log tail.
* **Log output is bounded.** Core output is pumped into a bounded channel with an
  overflow counter, so a chatty core cannot grow memory without bound, and the
  log tail carried in a bundle is capped.
* **Known log signals are matched deliberately** rather than being left to the
  user: `failed to set Interface` / `failed to set SO_MARK` (loop prevention did
  not apply → fail), `no usable outbound interface found` (loop risk → fail),
  `failed to open geosite.dat` / `failed to check code … from geosite.dat` (geo
  asset problem → repair prompt), `XTLS rejected UDP/443 traffic` /
  `XUDP rejected UDP/443 traffic` (expected under a QUIC-suppressing plan), and
  `XUDP hit`/`XUDP new` (session migration working).

## Implemented vs planned

This table is the honest answer to "what exists in `src/` today". Verified by
inspecting the tree and by building it.

| Capability | State | Notes |
|---|---|---|
| Domain model, value objects, state machine | **Implemented** | `MyVpn.Core/Domain/` |
| `Result`/`MyVpnError`/`ErrorCodes` | **Implemented** | `MyVpn.Core/Results/` |
| Settings model + validation | **Implemented** | `MyVpn.Core/Settings/AppSettings.cs`; no persistence yet |
| Subscription header safety (gates, bounds, parsers) | **Implemented** | `MyVpn.Core/Subscriptions/`; 65 headers catalogued |
| `subscription-userinfo` parsing | **Implemented** | Tolerant of `;`/`,`, floats, ms-vs-s epochs |
| Share-link parsing (`vless`/`vmess`/`trojan`/`ss`) | **Implemented** | `MyVpn.Core/Parsing/ShareLinkParser.cs` |
| Geo-asset structural validation (protobuf walk) | **Implemented** | `MyVpn.Core/Geo/GeoAssetValidator.cs` |
| Geo-data manager, download, manifest, atomic install | **Planned** | ADR-0003 |
| Xray version policy + parser | **Implemented** | `MyVpn.Core/Xray/XrayVersion.cs` |
| Xray binary locator/probe, config generator, `-test` pre-flight | **Planned** | ADR-0002 |
| Xray process supervision, restart policy, bounded log pump | **Planned** | `ErrorCodes` for it already exist |
| CIDR and URL-safety primitives | **Implemented** | `MyVpn.Core/Net/` |
| Platform capability interfaces + pure renderers | **Planned** | only `.csproj` comments so far |
| Kill switch per platform | **Planned** | ADR-0006 |
| Privileged service + authenticated IPC | **Planned** | ADR-0005; only `.csproj` |
| Per-process routing | **Planned** | ADR-0007; capability matrix not yet implemented |
| Transport/NAT strategy selection | **Planned** | ADR-0011; `TransportStrategy`/`MuxSettings` exist as settings only |
| UI (views, view models, localizer, theme service) | **Planned** | ADR-0010 |
| CLI (`diagnose`, `check-config`, …) | **Planned** | no entry point |
| Any automated test | **Planned** | all four test projects are `.csproj`-only; `dotnet test` reports "No test is available" |
| Whole-solution build | **Broken today** | `MyVpn.Service`, `MyVpn.Cli` and `MyVpn.UI` have no `Main`, so `dotnet build MyVpn.sln` fails with three `CS5001` errors. The CI workflow documents this as a tracked gap and builds the existing graph instead. |
| Geo asset + Xray bundling, installers, signing | **Planned** | CI packaging is gated on the entry points existing |

## Known gaps and inaccuracies in the current tree

Recorded here because they affect anyone reading the code or the docs:

1. **The solution does not build.** Three entry-point projects
   (`MyVpn.Service`, `MyVpn.Cli`, `MyVpn.UI`) are shells with `OutputType`
   `Exe`/`WinExe` and no `Program.cs`, producing `CS5001`. This is the blocking
   gap for CI, packaging and running anything at all.
2. **No tests exist**, despite every test project being configured and
   `Directory.Build.props` treating warnings as errors. The rich `MyVpn.Core`
   implementation is entirely untested.
3. **Several `.csproj` comments describe planned behaviour in the present
   tense** — for example `MyVpn.Ipc.csproj` states that "the transport binds to
   a Unix domain socket … and performs peer-credential verification", and
   `MyVpn.Platform.Abstractions.csproj` enumerates capability interfaces that do
   not exist. The comments are a design statement, not a description of the
   code; ADR-0005 and ADR-0007 are the authoritative records.
4. **`MyVpn.UI.csproj` references files that do not exist** — `app.manifest`,
   `Localization/locales/*.json` and `Assets/**`. Globs match nothing today, so
   the compile is unaffected, but a Windows publish will need `app.manifest`, and
   the localizer will need at least one locale file (ADR-0010).
5. **`GeoDataStatus` still describes a relative asset directory as "the
   definitive signature of the issue #9765 defect"**, which contradicts the
   verified root cause: the configured value was absolute and was simply never
   delivered to the elevated process (ADR-0003, `docs/research/02` §1.9).
   `GeoAssetInfo` already documents the correct cause, so the two types disagree.
   `PathNotAbsolute` is a useful guard against a *different* failure mode and
   should say so.
6. **`MuxSettings.XudpProxyUdp443` is a `bool`**, but Xray's field is the
   tri-state string `"reject" | "allow" | "skip"` (ADR-0011). A boolean cannot
   express `"skip"`. Changing it is a settings-schema change and needs a
   migration.
7. **`TransportStrategy` cannot express a full transport plan** (cone, mux
   coherency, interface binding, fallback order). It is a preference, not a plan
   (ADR-0011).
8. **`TunSettings.AutoRoute` / `StrictRoute` / `RouteOnly` are not Xray JSON
   fields.** `autoRoute` and `strictRoute` do not exist in Xray at all, and
   `routeOnly` exists only inside `sniffing`. They are MyVpn's own policy and
   must never be emitted as TUN keys (ADR-0002).
9. **`docs/research/` line counts differ from some in-report claims**, and
   `08-macos-networking.md` has a duplicated heading and a section explicitly
   marked incomplete. The reports are evidence archives; treat their structure as
   provisional.

## References

* `docs/adr/` — ADR-0001 (decision record), ADR-0002 (Xray-only native TUN),
  ADR-0003 (geo assets), ADR-0004 (`net8.0` targeting), ADR-0005 (helper + IPC),
  ADR-0006 (kill switch), ADR-0007 (process routing), ADR-0008 (header safety),
  ADR-0009 (licensing/provenance), ADR-0010 (UI), ADR-0011 (transport/NAT).
* `docs/research/` — the eight primary-source reports these decisions rest on.
* `Directory.Build.props`, `Directory.Packages.props`, `MyVpn.sln` — build
  conventions and the project list.
* `NOTICE`, `LICENSE` — third-party notices and the project licence.
* `.github/workflows/ci.yml` — the pipeline that builds, tests, analyses and
  packages this tree, including the tracked-gap comments and the clean-room
  provenance guard.
