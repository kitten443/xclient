# MyVpn

A cross-platform desktop VPN client built on **Xray-core only**, using Xray's
**native TUN inbound** as the sole network core. Written in C# / .NET 8 with
Avalonia UI, Clean Architecture + MVVM + dependency injection, a Platform
Abstraction Layer, and a separate privileged helper service.

> **Status: foundation, not a finished 1.0.** The solution builds cleanly, the
> domain layer and the platform-abstraction contracts are implemented, and a
> test suite exists — but some tests are currently failing, the integration
> suite is empty, and the platform executors, IPC transport and real UI wiring
> are still planned. See [Current status](#current-status-honest) before you
> rely on anything.

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

Test. The suite exists and runs; **9 of the 696 `MyVpn.Core.Tests` cases
currently fail**, so this is expected to be red:

```bash
dotnet test MyVpn.sln -c Release --no-build --collect:"XPlat Code Coverage"
```

Known failures at the last verification (all in `tests/MyVpn.Core.Tests`, and
all genuine disagreements between the tests and the implementation rather than
flakiness): `GeoAssetValidatorTests` (4 cases — including one expecting failure
code `truncated_entry` where the validator returns `malformed_entry`),
`ProtoReaderTests.Reads_a_single_byte_varint`, `CidrBlockTests.Parses_a_bracketed_ipv6_literal`,
`ServerScoreTests.Score_is_always_within_zero_and_one_hundred`,
`UrlSafetyTests.A_relative_url_is_rejected`, and
`RawHeaderBagTests.Rejected_headers_record_the_reason_and_length`.

`tests/MyVpn.Integration.Tests` is configured but contains no tests yet, so that
leg passes vacuously (`dotnet test` reports "No test is available" and exits 0).

Privileged tests (real TUN, real firewall, real routes) are expected to carry the
xunit trait `Category = "RequiresRoot"`. On Linux CI the pipeline filters them
out with `--filter "Category!=RequiresRoot"`; Windows and macOS runners have
passwordless elevation and run everything.

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
  locales, 196 keys each) and `MyVpn.Service` (privilege and capability
  pre-flight).
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
* `MyVpn.Platform.Linux` executors: `ICommandRunner` (argv only, never a shell),
  `NftablesKillSwitch` (verified by applying and reading back inside a real kernel
  network namespace) and `LinuxSystemProxy` (GSettings, including the `none`/`manual`/
  `auto` mode triad so a corporate PAC configuration is restored faithfully).
* A test suite: 782 cases in `MyVpn.Core.Tests`, 66 in
  `MyVpn.Infrastructure.Tests`, 34 in `MyVpn.Platform.Tests`, 5 in
  `MyVpn.Integration.Tests` — 887 total.

**Planned:**

* Geo-data **download** (fetching from a source with SHA-256 from a signed
  manifest). Atomic install/rollback/repair exist; the network fetch does not.
* Linux **route** and **DNS** executors, and `INetworkStateManager` (the "Restore
  network" button). In progress.
* **TUN mode end to end.** The config builder emits it and the executors are being
  written; it has not yet been exercised against a real server.
* **Windows and macOS executors** — deliberately not started. They cannot be compiled
  or run on the development platform, so they would be unverifiable code. Write-only
  platform layers should be added when a runner for those systems is available.
* **Process routing** on any platform (see ADR-0007 for the honest capability matrix).
* The authenticated IPC transport in `MyVpn.Ipc` and the real privileged
  service implementation behind it. Until it exists, the Kill Switch reports
  "present but needs privileges" rather than pretending to be armed.
* The real UI: DI composition, remaining view models/views, theme service,
  settings persistence and OS-keystore secret storage. The main screen exists but its
  Connect button still drives the state machine directly instead of `VpnSession`.
* Geo-data **download**.
* Integration tests (`tests/MyVpn.Integration.Tests` is empty).
* Installers, bundling, code signing and artifact provenance.

**Known inaccuracies in the current tree** (details in
[`docs/architecture/overview.md`](docs/architecture/overview.md#known-gaps-and-inaccuracies-in-the-current-tree)):

* **9 of 696 `MyVpn.Core.Tests` cases fail**, so `dotnet test` is red. They are
  genuine test/implementation disagreements (see the build section above).
* `tests/MyVpn.Integration.Tests` contains no tests, so its CI leg passes
  vacuously.
* Some `.csproj` comments describe planned behaviour in the present tense.
* `MyVpn.UI.csproj` still references `Assets/**`, which does not exist yet
  (`app.manifest` and `Localization/locales/*.json` now do).
* `GeoDataStatus` still calls a relative asset path "the definitive signature of
  the issue #9765 defect", which contradicts the verified root cause — the value
  was absolute and was never delivered to the elevated process.
* `MuxSettings.XudpProxyUdp443` is a `bool`, but Xray's field is the tri-state
  `"reject" | "allow" | "skip"`.
* `TunSettings.AutoRoute` / `StrictRoute` / `RouteOnly` are MyVpn policy, not
  Xray JSON fields, and must never be emitted as such.

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

MyVpn is licensed **GPL-3.0-or-later** ([`LICENSE`](LICENSE)).

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

* [`docs/adr/`](docs/adr/) — Architecture Decision Records 0001–0011, each citing
  the research and the underlying primary sources.
* [`docs/architecture/overview.md`](docs/architecture/overview.md) — layers, the
  dependency rule, module inventory, connect/disconnect sequence, diagnostics
  model, and the implemented-vs-planned table.
* [`docs/research/`](docs/research/) — eight primary-source research reports
  (v2rayN architecture, issue #9765 geo data, the Xray TUN inbound, the NAT/UDP
  matrix, Happ headers, and Windows/Linux/macOS networking).
* [`NOTICE`](NOTICE), [`LICENSE`](LICENSE).
* [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — build, unit and
  integration tests, static analysis, CodeQL, dependency and secret scanning,
  licence inventory, the clean-room provenance guard, packaging and conditional
  signing.
