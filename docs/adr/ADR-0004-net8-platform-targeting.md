# ADR-0004 — Plain `net8.0` for every project (no OS-specific target monikers)

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —
- **Implementation status:** Implemented. `Directory.Build.props` sets
  `<TargetFramework>net8.0</TargetFramework>` repository-wide, and no
  `.csproj` overrides it. Already referenced from that file's comment.

## Context

MyVpn targets Windows 10/11 (x64, arm64), Linux (x64, arm64) and macOS (Intel
and Apple Silicon). It has three platform-specific implementation projects
(`MyVpn.Platform.Windows`, `MyVpn.Platform.Linux`, `MyVpn.Platform.MacOS`) whose
job is to execute platform-neutral *plans* through OS APIs, including P/Invoke
into Win32/`fwpuclnt.dll`, Linux netlink/nftables and macOS `libSystem`/XPC.

The obvious .NET convention would be to give each platform project an
OS-specific target framework moniker:

```xml
<TargetFramework>net8.0-windows</TargetFramework>   <!-- MyVpn.Platform.Windows -->
<TargetFramework>net8.0-macos</TargetFramework>     <!-- MyVpn.Platform.MacOS -->
```

That convention buys compile-time availability of the Windows-specific BCL
surface (`Microsoft.Win32.*`, `System.ServiceProcess`, `net8.0-windows` APIs)
and of the macOS workload bindings.

It costs something that matters more here. With OS-specific monikers:

* The solution only restores and builds on the matching OS. A GitHub Actions
  runner cannot build the Windows project on Linux, so the CI matrix cannot
  verify that every project in the tree at least compiles on every runner.
* A single runner cannot run the whole test suite. Unit tests over *pure*
  platform logic — the plan renderers that turn a `NetworkPlan` into nftables
  text, WFP filter descriptors, or PF anchor text — are the majority of the
  testable platform surface, and they would become unrunnable off-platform.
* Developer machines and contributors with a single OS would be unable to build
  or test the whole solution, which is a real cost for a project that expects
  contributors on all three platforms.

There is also a security-relevant observation: the solution must be structured
so that a Linux test run can never execute Windows-only code and vice versa. An
OS-specific TFM does not provide that guarantee by itself (the code is present
either way); an explicit runtime guard does.

`Directory.Build.props` already encodes this decision in a comment referencing
this ADR. This record makes the reasoning and the compensating controls
explicit.

## Decision

**Every project targets plain `net8.0`.** No `net8.0-windows`, no
`net8.0-macos`, no `net8.0-ios`/`net8.0-tvos`, no `RuntimeIdentifier` in
project files. This applies to the platform implementation projects too, which
reference only `MyVpn.Core` and `MyVpn.Platform.Abstractions`.

The compensating controls are not optional:

1. **OS behaviour is selected at runtime by capability probing**, not by which
   assembly was compiled. A plan executor is only constructed when the
   corresponding capability probe says the OS API is present and usable. The
   probe result is what the UI and the connection flow branch on; "we are on
   Windows" is never sufficient.
2. **Unsafe OS calls are `RuntimeInformation`-guarded.** Every P/Invoke or
   OS-specific syscall site is preceded by a guard on
   `RuntimeInformation.IsOSPlatform(...)` (and, where relevant, an architecture
   guard), so a Linux test run cannot execute Windows-only code. The guard is at
   the call site, not only in the factory that normally avoids calling it,
   because reflection, a mis-wired DI registration, or a future refactor can
   reach the call site otherwise.
3. **Platform code is split into pure renderers and thin executors.** A
   *renderer* converts a platform-neutral plan into a textual/descriptor form
   and is a pure function with no I/O and no OS API. An *executor* applies the
   rendered artifact and is the only part that needs privilege. Renderers carry
   the bulk of the platform logic and are unit-tested on every runner; executors
   are exercised only in the privileged test tier.
4. **P/Invoke declarations compile without the OS targeting pack.** `DllImport`
   signatures, `LibraryImport` source generators, and `[StructLayout]` types do
   not require `net8.0-windows`; they require correct types. Anything that only
   exists in an OS-specific BCL surface (for example `System.ServiceProcess`)
   is either avoided in favour of P/Invoke or confined to a small
   `RuntimeInformation`-guarded adapter.
5. **Analyzers as the compiler gate.** `TreatWarningsAsErrors=true` and
   `EnableNETAnalyzers=true` are set repository-wide, so platform-compatibility
   analyzers that fire without an OS-specific TFM still fail the build.

`MyVpn.UI` is the one place where an OS-specific moniker might be argued for
(`WinExe`, `ApplicationManifest`, `BuiltInComInteropSupport`). It keeps plain
`net8.0` too: Avalonia is cross-platform, `OutputType` is `WinExe` on every
platform (the name is a historical artifact; `dotnet build` accepts it on
Linux), and `app.manifest` is consumed by the Windows apphost at publish time
rather than at compile time.

## Consequences

**Positive**

* The whole solution restores, builds and unit-tests on any single runner. The
  CI matrix therefore has a real "compiles everywhere" leg on Windows x64, Linux
  x64 + arm64, macOS Intel and macOS Apple Silicon, rather than only the leg
  matching the current OS.
* Pure platform logic (plan renderers, parsers, validators) is testable on every
  developer machine and on every CI leg.
* The platform seam is explicit and reflectable, which makes the
  ADR-0007 capability matrix enforceable rather than aspirational.

**Negative / costs**

* No compile-time access to OS-specific BCL surfaces. Compensated by P/Invoke
  and by keeping OS-specific code behind capability interfaces. Where a BCL type
  is genuinely wanted, it must be confined and guarded.
* No compile-time check that Windows-only code is not called on Linux. The
  runtime guard is the enforcement mechanism, and it is weaker than a compiler
  error: it is a test-time property (a Linux test that drives a Windows-only
  path must fail rather than silently succeed) rather than a build-time one.
* A `RuntimeIdentifier`-specific publish is still required for packaging
  (`-r win-x64`, `-r linux-arm64`, …). That is a publish-time concern and lives
  in the packaging job, not in project files.
* Single-file/trimming are harder to reason about across all platform code
  paths, so `PublishTrimmed=false` is the deliberate default (see the CI
  packaging job).

**Verification obligations**

* A CI leg must exercise each platform project's pure renderers on all three
  OSes. Because the test projects are all `net8.0`, this works without a matrix
  exclusion.
* Any new P/Invoke must be paired with a `RuntimeInformation` guard and a test
  that the guard rejects the wrong platform. This is a review checklist item.

## Alternatives considered

* **`net8.0-windows` / `net8.0-macos` on the platform projects only.** Rejected:
  breaks "build the whole solution on any runner", makes most platform unit tests
  unrunnable off-platform, and does not by itself prevent a Linux test from
  reaching Windows code.
* **Multi-target the platform projects (`net8.0;net8.0-windows`).** Rejected:
  doubles build time and produces two distinct assemblies whose behaviour
  differs by TFM, which is exactly the ambiguity this ADR avoids; the OS
  capability probe is a better single source of truth.
* **Separate solutions per OS.** Rejected: no single definition of "the
  product"; dependencies and DI wiring would drift.
* **`net8.0` only for libraries, monikers for the executables.** Considered.
  Rejected for consistency: the executables depend on the platform projects, so
  monikers anywhere re-introduce the cross-OS build restriction for everything
  downstream.
* **`OperatingSystem.IsWindows()` instead of `RuntimeInformation`.** Not a real
  alternative — either works, and the codebase should standardise on one.
  `RuntimeInformation` is chosen because it also answers architecture and
  framework questions that the platform layers need (for example, arm64 vs x64
  netlink struct layout, and the Wintun DLL to stage).

## References

* `Directory.Build.props` — the decision and its rationale, referencing this ADR.
* `MyVpn.sln` — 15 projects, all inheriting `net8.0`.
* `src/MyVpn.Platform.Abstractions/MyVpn.Platform.Abstractions.csproj` — the
  capability interfaces + pure plan renderers this ADR's control #3 relies on.
* `docs/research/06-windows-networking.md` §1.1 (P/Invoke surface for
  `fwpuclnt.dll`), §1.3 (named pipes, `NamedPipeServerStreamAcl`),
  §1.5 (NetIO APIs) — the OS-specific surfaces that must remain
  `RuntimeInformation`-guarded.
* `docs/research/07-linux-networking.md` §2.6 (netlink vs `ip` invocation),
  §2.9 (interface implementations), §2.10 (validation method).
* `docs/research/08-macos-networking.md` §1.1.5 (XPC from .NET, and the
  native-helper alternative), §2.4 (capability-level API).
* `docs/architecture/overview.md` — the "Implemented vs planned" table and the
  dependency rule.
