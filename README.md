# MyVpn

A cross-platform desktop VPN client built on **Xray-core only**, using Xray's
**native TUN inbound** as the sole network core. Written in C# / .NET 8 with
Avalonia UI, Clean Architecture + MVVM + dependency injection, a Platform
Abstraction Layer, and a separate privileged helper service.

> **Status: working client, pre-release.** The solution builds clean (zero warnings,
> zero analyzer diagnostics, `TreatWarningsAsErrors=true`) and the full suite of
> **1270 tests passes green in two consecutive runs**, including a rootless end-to-end
> test that brings up a real Xray TUN tunnel, real nftables Kill Switch rules and real
> routes inside a throwaway network namespace. It has been exercised against a live
> subscription in proxy mode. It is **not a finished 1.0**: runtime verification on
> Windows and macOS has not happened, the privileged service and its IPC transport are
> not implemented, and TUN mode has not been run against a real remote server. See
> [Current status](#current-status-honest) before you rely on anything.

## What it is

MyVpn takes a subscription or a share link, generates an Xray-core
configuration, launches the core under a privileged helper, and gives the user a
tunnel with a fail-closed kill switch, DNS takeover and (where the OS actually
allows it) per-application routing. It is a *from-scratch* client: prior art in
this ecosystem was studied for architecture and failure modes, not copied
([`NOTICE`](NOTICE), [ADR-0009](docs/adr/ADR-0009-licensing-and-provenance.md)).

## Hard requirements

These are non-negotiable and are enforced in code, CI and the decision record:

| Requirement | How it is satisfied |
|---|---|
| **Xray-core only** | Xray is the sole network core, launched as a separate unmodified process and configured through a generated JSON file. |
| **Native TUN inbound** | `"protocol": "tun"` — Xray's own TUN inbound, not a third-party TUN front-end. Only the eight documented fields are emitted (`name`, `desc`, `mtu`, `gateway`, `dns`, `userLevel`, `autoSystemRoutingTable`, `autoOutboundsInterface`); invented fields such as `address`, `autoRoute`, `strictRoute`, `sniffingOverride` and TUN-level `routeOnly` are never written. |
| **No sing-box** | sing-box is excluded as the network core and is not named under `src/` or `tests/`. A CI job fails if the token appears there. |

Xray version policy: native TUN first appeared in **`v26.1.13`**; **`v26.4.13`**
is rejected by exact version because its `mtu` field was `repeated uint32` (a
scalar `"mtu"` is invalid there); the floor is **`v26.4.15`** and the
recommended version is **`v26.9.9`**. The reasoning and the primary-source
evidence are in [ADR-0002](docs/adr/ADR-0002-use-xray-core-only-native-tun.md).

## Supported platforms

| Platform | Architectures | TUN mechanism | Kill switch |
|---|---|---|---|
| Windows 10 / 11 | x64, arm64 | Xray native TUN (Wintun) | WFP via `fwpuclnt.dll` |
| Linux (Ubuntu, Debian, Fedora, Arch) | x64, arm64 | Xray native TUN (`/dev/net/tun`) | nftables, single atomic transaction |
| macOS 13+ | Intel (x64), Apple Silicon (arm64) | Xray native TUN (utun) | PF anchors — **Apple declares PF "not API"** and this is documented as best-effort |

Per-process routing is honest about its limits: Linux supports it properly
(cgroup v2 + nftables + policy routing), Windows only partially and
version-gated, and **true per-application tunnelling on macOS is not achievable
for a self-distributed client** — see
[ADR-0007](docs/adr/ADR-0007-process-routing-capability-matrix.md).

## Architecture summary

```
Core → Application → Infrastructure → Platform.{Linux,Windows,MacOS} → {UI, CLI, Service}
```

* **`MyVpn.Core`** — domain model, value objects, the VPN state machine, the
  settings model, pure validators and parsers. **Zero dependencies**, no I/O.
* **`MyVpn.Application`** — ports (capability interfaces) and use cases.
* **`MyVpn.Infrastructure`** — Xray engine, config generation, geo data,
  subscriptions, settings, diagnostics.
* **`MyVpn.Platform.Abstractions`** — capability interfaces plus **pure plan
  renderers** (nftables text, WFP filter descriptors, PF anchor text), so the OS
  integration is unit-testable without root.
* **`MyVpn.Platform.*`** — thin executors that need privilege.
* **`MyVpn.UI` / `MyVpn.Cli` / `MyVpn.Service`** — hosts. **The UI is never
  elevated**; privileged work happens in the service behind a narrow,
  authenticated, typed command set. No "run this command" or "apply this raw
  config" operation exists on the wire.

All projects target plain `net8.0`, including the platform layers, so the whole
solution can be built and unit-tested on any runner; OS behaviour is selected by
runtime capability probing and unsafe OS calls are guarded
([ADR-0004](docs/adr/ADR-0004-net8-platform-targeting.md)).

Full detail, the connect/disconnect sequence and the diagnostics model:
[`docs/architecture/overview.md`](docs/architecture/overview.md).

## Build and test

Requires the **.NET 8 SDK** (`8.0.x`). In this development environment the SDK
lives under `$HOME/.dotnet`, so put it on `PATH` first:

```bash
export PATH="$HOME/.dotnet:$PATH"
dotnet --version          # expect 8.0.x
```

Restore and build the whole solution:

```bash
dotnet restore MyVpn.sln
dotnet build MyVpn.sln -c Release --no-restore
```

The build is a real gate: `Directory.Build.props` sets
`TreatWarningsAsErrors=true` and `EnableNETAnalyzers=true`, so a green build
means zero warnings and zero analyzer diagnostics as well as zero errors.

Test. The suite is green; the last verification was two consecutive full runs, both
1270 passed / 0 failed:

```bash
dotnet test MyVpn.sln -c Release --no-build --collect:"XPlat Code Coverage"
```

| Project | Tests | What it covers |
|---|---|---|
| `MyVpn.Core.Tests` | 811 | domain, settings, parsing, geo validation, config building |
| `MyVpn.Platform.Tests` | 383 | platform executors and their pure plan renderers |
| `MyVpn.Infrastructure.Tests` | 66 | engine, geo manager, adapters, diagnostics |
| `MyVpn.Integration.Tests` | 8 | share link → config → real loopback Xray server |
| `MyVpn.Rootless.Tests` | 2 | real TUN, real routes, real nftables inside `unshare` |

Privileged tests (real TUN, real firewall, real routes) carry the xunit trait
`Category = "RequiresRoot"`. `MyVpn.Rootless.Tests` deliberately does **not**: it runs
both tunnel ends inside `unshare -rmn`, so a real kernel data path is exercised without
root. Let the namespace set up its own veth pair — running it under a plain `unshare -rn`
with no uplink makes the route assertions vacuous.

Note that these tests must not be run concurrently with each other: they share the
host's network-namespace resources, and a second concurrent run has been observed to make
the far side of the tunnel miss its readiness deadline.

Formatting and analyzers:

```bash
dotnet format whitespace MyVpn.sln --verify-no-changes --no-restore
dotnet format analyzers  MyVpn.sln --verify-no-changes --no-restore
```

Note that `Directory.Build.props` sets `TreatWarningsAsErrors=true` and
`EnableNETAnalyzers=true`, so the compiler is already a hard gate. The
`dotnet format` check is currently **non-blocking** in CI because the tree has
never been formatted; it becomes a merge gate once the baseline is clean.

## Current status (honest)

Verified by inspecting the source tree and building it.

**Implemented:**

* `Result` / `Result<T>` / `MyVpnError` / `ErrorCodes` (stable, never-localized
  codes).
* `VpnConnectionState` + `VpnStateMachine`, including
  `RequiresKillSwitch` — the kill switch stays engaged in `Faulted` and during
  `Disconnecting`.
* `ServerProfile` / `ServerEndpoint` with structural validation; `ServerScore`
  (deliberately not ping-only).
* The complete settings model (`AppSettings` plus nested validating records,
  schema-versioned).
* The **subscription header safety subsystem**: bounded header capture, RFC 9110
  token validation, control-character rejection, SHA-256 consent fingerprints,
  a 65-header catalog (12 auto-apply / 48 require-confirmation / 5 refused) and
  an ordered, isolated, gate-enforcing registry.
* Geo-asset **structural** validation (a protobuf walk that rejects truncation,
  HTML error pages and wrong files) and the geo rule-availability gate.
* Share-link parsing, tolerant Base64, country inference, `CidrBlock`,
  `UrlSafety` (https-only, no credentials, SSRF refusal), and the Xray version
  policy.
* `MyVpn.Core.Configuration`: the typed Xray configuration model and
  `XrayConfigBuilder`. Emits only the **documented** TUN fields (`name`, `desc`,
  `mtu`, `gateway`, `dns`, `userLevel`, `autoSystemRoutingTable`,
  `autoOutboundsInterface`) and never `address`/`autoRoute`/`strictRoute`/
  `sniffingOverride`; routes port 53 to a `dns` outbound (there is no DNS
  *inbound* protocol); applies the `mark` sockopt to the proxy outbound only;
  models `xudpProxyUDP443` as the tri-state it actually is; and **omits any
  `geoip:`/`geosite:` rule whose asset is unusable** so a damaged geo database
  degrades routing policy instead of preventing the connection.
* `MyVpn.Infrastructure`: `GeoDataManager` (manifest, status, atomic
  stage→verify→validate→backup→rename install, rollback, repair, and the
  dual-channel environment injection) and `XrayAssetResolution` (a mirror of
  Xray's asset lookup order, used as a pre-launch assertion).
* `MyVpn.Infrastructure`: `XrayEngineManager` plus its support types —
  `XrayBinaryLocator` (search order, executable-bit check),
  `XrayTestRunInterpreter` (exit code 23 = configuration rejected ⇒ **do not
  restart**), `RestartLimiter` (sliding-window restart budget) and the engine
  itself: argv launch, explicit environment, `xray run -test` pre-flight,
  version probe, stdout/stderr capture with a bounded buffer, `SIGTERM` graceful
  stop, crash classification and bounded automatic restart.
* `MyVpn.Infrastructure.Diagnostics`: `DiagnosticRunner` (per-check isolation,
  injectable timeout, aggregate report) and nine checks covering core binary,
  configuration file, geo data, core process/version, TUN interface, kill
  switch, DNS, system proxy and server reachability. Every result carries a
  localization key, never a raw English sentence.
* `MyVpn.Platform.Abstractions`: the capability interfaces (`IKillSwitch`,
  `IRouteManager`, `IDnsConfigurator`, `IProcessRouter`, `ISystemProxy`,
  `IPrivilegedHost`, `ITunDeviceManager`, `INetworkStateManager`,
  `IPlatformServices`), their plan/state value objects, the platform capability
  matrix types, and `KillSwitchPlanBuilder`.
* `MyVpn.Platform.Linux`: `NftablesKillSwitchRenderer` (a pure renderer whose
  output is verified by installing it into a throwaway kernel network namespace
  in the test suite).
* Working `MyVpn.Cli` commands: `myvpn geo doctor` and `myvpn diagnose` (with
  meaningful exit codes: 3 = geo data unusable, 4 = warnings, 5 = errors).
* Entry points for `MyVpn.UI` (Avalonia `App`/`MainWindow`, a
  `MainWindowViewModel` and a JSON localization service with `en`/`ru`/`zh-Hans`
  locales, 479 keys in `en` and 396 in each translation, switchable at runtime) and
  `MyVpn.Service` (privilege and capability pre-flight).
* `MyVpn.Application`: the connect path. `VpnSession` sequences validate → locate →
  resolve → geo → build → stage → **arm the Kill Switch → start the core → point the
  desktop at the tunnel** → verify with a real request, and tears down in reverse. A
  failed first connect returns to `Disconnected` rather than `Faulted`, and refuses to
  connect without the Kill Switch when the user asked for one and the server address
  cannot be pinned. Rationale and rejected alternatives: `ADR-0012`.
* `MyVpn.Infrastructure` adapters: `AppPaths`, `AtomicConfigFileStore`,
  `CoreLocatorAdapter`, `CoreSupervisorAdapter`, `GeoDataProviderAdapter`,
  `DnsServerEndpointResolver`, `HttpProxyConnectionVerifier` (the check that
  distinguishes a live process from a working tunnel) and `SubscriptionFetcher`.
* Working `myvpn connect --subscription … --index N [--mode proxy|tun] [--core PATH]
  [--kill-switch off|on-demand|always-on]`. Verified against a live subscription:
  exit address distinct from the host's own, across XHttp+TLS, XHttp+REALITY and
  gRPC+REALITY profiles.
* **Executor layers for all three platforms**, plus an `IPlatformServices` factory each:
  * **Linux** — `NftablesKillSwitch` (verified by applying and reading back inside a real
    kernel network namespace), `LinuxRouteManager`, `LinuxDnsConfigurator`,
    `LinuxSystemProxy`, `LinuxTunDeviceManager`, `LinuxNetworkStateManager`.
  * **Windows** — `WindowsWfpKillSwitch` with a pure plan→WFP-descriptor translator,
    `WindowsSystemProxy` (WinINet registry), `WindowsRouteManager`, `WindowsDnsConfigurator`,
    `WindowsTunDeviceManager`, `WindowsNetworkStateManager`.
  * **macOS** — `PfAnchorRenderer` (pure) and `MacPfKillSwitch`, `MacSystemProxy`,
    `MacRouteManager`, `MacDnsConfigurator`, `MacTunDeviceManager`,
    `MacNetworkStateManager`.
  Every external command is an argv vector; there is no `sh -c` in any platform layer, and
  the Windows system-proxy and TUN executors deliberately use P/Invoke instead of shelling
  out. Kill-switch rule sets are rendered by pure functions that are unit-tested, and the
  executors read the platform back rather than trusting an exit code.
* A test suite: 811 cases in `MyVpn.Core.Tests`, 383 in
  `MyVpn.Platform.Tests`, 66 in `MyVpn.Infrastructure.Tests`, 8 in
  `MyVpn.Integration.Tests` and 2 rootless end-to-end cases — **1270 total, all
  green.**

**Planned:**

* **Runtime verification on Windows and macOS.** The executors compile and their pure parts
  are unit-tested, but nothing has been executed on those operating systems: WFP, PF,
  WinINet, `networksetup`, `route.exe`/`route`, `netsh` and the adapter APIs are all
  unverified at run time. CI runners for those platforms have the necessary privileges, so
  this is a matter of adding the jobs, not of hardware.
* **TUN mode against a real remote server.** It is exercised end to end against a real Xray
  core inside a network namespace (`MyVpn.Rootless.Tests`, green), and proxy mode is verified
  against a live subscription — but a full-tunnel session to a real remote endpoint has not
  been run.
* **Process routing on Windows and macOS.** Linux enforcement exists (cgroup v2 + nftables +
  policy routing). Elsewhere `ApplyAsync` refuses rather than silently doing nothing. See
  ADR-0007 for the per-platform capability matrix and why the ceilings differ.
* **The authenticated IPC transport** in `MyVpn.Ipc` and the real privileged
  service implementation behind it. Until it exists, the Kill Switch reports
  "present but needs privileges" rather than pretending to be armed, and the platform
  executors run in-process.
* **The remaining UI**: theme service, settings persistence, OS-keystore secret storage, and
  the Advanced Mode surfaces. The main screen, server list, subscription import, diagnostics
  and settings views exist, and Connect drives the real `VpnSession`.
* **System-proxy mode, IPv6 data path and reconnect cycles** are not yet covered by tests.
* The **systemd-resolved** DNS backend (the `resolv.conf` backend is the one that is tested).
* Geo-data **download** (fetching from a source with SHA-256 from a signed
  manifest). Atomic install/rollback/repair exist; the network fetch does not.
* Installers, bundling, code signing and artifact provenance.
* Localization: the `header.*` labels (83 keys) exist in English only and currently fall
  back to English in `ru`/`zh-Hans`; `build/check-localization.py --strict-headers` is the
  flag that will tighten this once they are translated.

**Known inaccuracies in the current tree** (details in
[`docs/architecture/overview.md`](docs/architecture/overview.md#known-gaps-and-inaccuracies-in-the-current-tree)):

* Some `.csproj` comments describe planned behaviour in the present tense.
* `TunSettings.AutoRoute` / `StrictRoute` / `RouteOnly` are MyVpn policy, not
  Xray JSON fields. The builder maps `AutoRoute` onto the routing rules and `RouteOnly`
  onto `sniffing.routeOnly` (a real Xray field), and never emits them as TUN-inbound keys.
* `MyVpn.Core.Tests` references `src/MyVpn.UI`, so some UI types are exercised from the
  Core test project; `tests/MyVpn.UI.Tests` renders the real windows headlessly with
  `Avalonia.Headless` (real Skia pixels, every tab, language switching) and
  [`docs/screenshots/`](docs/screenshots/) shows the output.
* The UI has never run on a real desktop — only headlessly. Chinese text renders as
  boxes unless the system provides a CJK font, because the app bundles Inter only
  (visible in `docs/screenshots/07-status-zh-hans.png`).

## Security model

* **The UI is never elevated.** All privileged work lives in a system service
  reached over a narrow, typed, authenticated IPC surface.
* **Peers are authenticated per connection, not per session.** Windows: an
  explicit named-pipe DACL, `PIPE_REJECT_REMOTE_CLIENTS`, first-instance
  squatting protection, and a per-connection PID → process handle → image path →
  Authenticode → token SID/session/integrity check. Linux: systemd system
  service + D-Bus policy + polkit, with the caller's UID taken from the bus
  daemon, never from an argument. macOS: `SMAppService` daemon + XPC peer
  **team-identity** requirements, never PID/EUID. ALPC and `pkexec`-for-runtime
  are both rejected with reasons
  ([ADR-0005](docs/adr/ADR-0005-privileged-helper-and-ipc.md)).
* **The wire protocol is a closed command set.** No generic "run this command",
  "open this path" or "apply this raw config" operation exists.
* **The kill switch fails closed**, is armed before the default route moves and
  released only after it is restored, is atomic per platform, and has a mandatory
  Emergency Cleanup path
  ([ADR-0006](docs/adr/ADR-0006-killswitch-per-platform.md)).
* **A subscription cannot reconfigure the client.** No response header may
  influence routing, TUN, DNS or credentials automatically — zero exceptions.
  Values arrive as display metadata or as a value-bound `PendingChange`
  requiring explicit consent, or they are refused outright
  ([ADR-0008](docs/adr/ADR-0008-subscription-header-safety.md)).
* **Geo assets are never blindly trusted.** The asset directory is injected
  through two independent channels, resolution is asserted before launch,
  content is validated structurally, installs are atomic with rollback, and a
  `geoip:`/`geosite:` rule is never emitted for an unusable asset
  ([ADR-0003](docs/adr/ADR-0003-geodata-asset-management.md)).
* **Honest limitations are stated, not hidden.** Per-process routing on macOS is
  documented as unachievable; Apple declares PF "not API"; Windows always-on
  filters are silently disabled at boot unless the provider sets `serviceName`
  and the service auto-starts; "FullCone" is a server-side egress property with
  **no** JSON key and does not change your local NAT type.

## Licensing

MyVpn is licensed **GPL-3.0-only** ([`LICENSE`](LICENSE)).

The `only` is deliberate and load-bearing, for two independent reasons. The `LICENSE`
file is the bare GNU GPL version 3 text with no version-election statement, so no file in
this repository actually grants the "or any later version" option — declaring
`-or-later` would claim a permission that does not exist. And this project may incorporate
code **adapted from v2rayN**, which is itself GPL-3.0-**only**, so the additional
permission could not be extended over those parts in any case. Details:
[ADR-0009](docs/adr/ADR-0009-licensing-and-provenance.md) and
[`docs/provenance.md`](docs/provenance.md).

* **Xray-core** is **MPL-2.0**. It is used as a separate unmodified executable, so
  it imposes no copyleft on MyVpn's source; when bundled, the upstream `LICENSE`
  is shipped verbatim and the exact version and SHA-256 are recorded in
  `artifacts/manifest.json`.
* **Geo data** comes from `v2fly/geoip` (**CC-BY-SA 4.0**) and
  `v2fly/domain-list-community` (**MIT**), never from GPL-3.0 geo datasets.
* **v2rayN**, studied as prior art, is **GPL-3.0-only**; MyVpn is clean-room and
  no code or asset from it is copied. A CI job enforces that.
* **Happ** is proprietary; only its publicly documented subscription header
  formats are implemented.
* **Wintun** source is GPL-2.0 while the prebuilt signed `wintun.dll` is under a
  separate proprietary prebuilt-binaries licence: it may be redistributed only
  unmodified, via its API, with its licence file, and never renamed.

Full detail: [`NOTICE`](NOTICE) and
[ADR-0009](docs/adr/ADR-0009-licensing-and-provenance.md).

## Documentation

* [`docs/adr/`](docs/adr/) — Architecture Decision Records 0001–0012, each citing
  the research and the underlying primary sources.
* [`docs/architecture/overview.md`](docs/architecture/overview.md) — layers, the
  dependency rule, module inventory, connect/disconnect sequence, diagnostics
  model, and the implemented-vs-planned table.
* [`docs/research/`](docs/research/) — eight primary-source research reports
  (v2rayN architecture, issue #9765 geo data, the Xray TUN inbound, the NAT/UDP
  matrix, Happ headers, and Windows/Linux/macOS networking).
* [`NOTICE`](NOTICE), [`LICENSE`](LICENSE).
* [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — a four-runner build/test
  matrix (`windows-x64`, `linux-x64`, `linux-arm64`, `macos-apple-silicon`), plus an
  on-demand `macos-intel` leg on `macos-15-intel` (GitHub is retiring the `macos-13`
  image and its remaining Intel capacity is queue-starved, so Intel verification runs
  on request rather than holding the pipeline), full-solution build, static analysis,
  CodeQL, dependency and secret scanning, licence inventory, the localization and
  clean-room provenance guards, packaging, and conditional signing.
