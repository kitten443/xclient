# Provenance register

This project may incorporate code **adapted from third-party sources**. This file is the
authoritative record of what came from where, and — equally important — of what must
never be copied and why.

It exists because two failures are possible and only one of them is obvious. Copying
without attribution is a licence violation. Copying the *wrong* component is worse: it
silently reintroduces a defect the project was created to eliminate, and no test will
catch it because the defect looks like working code.

## Policy

1. **Default: original implementation.** Every component is written from scratch unless
   there is a concrete reason to adapt an existing one — usually years of accumulated
   platform quirks that are expensive to rediscover.
2. **Every adapted component is registered below** before it is merged, with its upstream
   file, licence, and the nature of the change.
3. **Every adapted file carries a header** naming the upstream source, its licence, and
   what was changed. The CI `provenance-guard` job fails a file that references upstream
   code without one.
4. **Components on the do-not-copy list are never copied**, regardless of convenience.
   They are listed with the specific verified defect that makes them unusable.

## Upstream licences

| Project | Licence | Verified how |
|---|---|---|
| [v2rayN](https://github.com/2dust/v2rayN) | **GPL-3.0-only** | `LICENSE` is the bare GPLv3 text with no "or later" clause (674 lines, clause absent); GitHub reports spdx `GPL-3.0` |
| [Xray-core](https://github.com/XTLS/Xray-core) | MPL-2.0 | GitHub repository metadata; consumed as a separate process, never linked |
| Wintun | GPL-2.0 / prebuilt-binary licence | see `NOTICE`; the unmodified signed DLL may be redistributed, its embedded driver may not be extracted |

Because v2rayN is GPL-3.0-**only**, the combined distribution is offered under
`GPL-3.0-only` (see `Directory.Build.props`). Our own files retain their "or later"
grant, but that additional permission cannot be extended over someone else's
GPL-3.0-only code.

## Register

| Date | Component | Upstream | Nature of change |
|---|---|---|---|
| — | *(none yet)* | — | — |

## Do-not-copy list

Each entry is a component whose upstream implementation is **known to be defective in a
way this project exists to fix**. Adapted code must not be taken from these, even
partially.

### 1. Xray process launch and environment delivery

**Upstream:** `ServiceLib/Common/CoreAdminManager.cs`, `CoreInfo.cs`.

**Why not:** this is the direct cause of v2rayN issue #9765. The TUN path launched the
core through `exec sudo -S -- <xray> run -c <cfg>` while constructing the process with
`environmentVars: null`, so `XRAY_LOCATION_ASSET` never reached the child — and `sudo`'s
`env_reset` would have stripped it anyway. Xray then fell back to its own directory,
failed to find `geoip.dat`, and refused to start.

**What we do instead:** launch by argv with no shell, set the environment explicitly, and
assert before launch that the core will resolve the same asset directory we validated.
See `XrayEngineManager`, `GeoDataManager.EnsureWorkingCopyAsync` and ADR-0003.

### 2. Shell-script generation for privileged execution

**Upstream:** the generated elevation script and its `AppendQuotes()` helper.

**Why not:** the helper performs no escaping while the result is executed as root. A
configuration value containing a quote becomes root command execution.

**What we do instead:** every platform command is an argv vector. There is no `sh -c`
anywhere in the platform layer, and `ICommandRunner` has no way to express one.

### 3. Core supervision

**Upstream:** `ServiceLib/Handler/ProcessService.cs`.

**Why not:** the `Exited` handler only unsubscribes. There is no restart, no crash
surfacing, and no use of `xray run -test`, so a rejected configuration produces silence
or an endless manual-retry loop.

**What we do instead:** a pre-flight that distinguishes exit code 23 (configuration
rejected — retrying cannot help) from a crash, a sliding-window restart budget, and a
`RestartLoopBlocked` state that is reported rather than hidden.

### 4. Geo-data installation

**Upstream:** the batch download and install path.

**Why not:** no checksum, no content-type check, no protobuf validation, and no atomic
per-file rename. A captive portal or a misconfigured mirror can write an HTML error page
over `geoip.dat`, and an interrupted download leaves a truncated file in place.

**What we do instead:** structural protobuf validation before the file becomes live,
SHA-256 verification, stage → verify → validate → backup → rename, and rollback.

### 5. Application updater

**Upstream:** `AmazTool`.

**Why not:** no hash and no signature verification, and no containment check on paths
inside the update package.

**What we do instead:** updates are not implemented yet. When they are, they must be
signed, checksum-verified, atomic and rollback-capable (ADR/requirements), and no
archive entry may escape the target directory.

### 6. Settings persistence

**Upstream:** the split between a mutable `guiNConfig.json` and a `guiNDB.db`, with
multiple save sites and no single writer.

**Why not:** concurrent writers with no ownership produce lost updates and partially
applied settings that are extremely hard to reproduce.

**What we do instead:** one immutable `AppSettings` snapshot, validated as a whole, with
a single writer.

### 7. Per-process routing on macOS

**Upstream:** not implemented upstream either — this entry exists to prevent someone
adding it later on the assumption that it is merely missing.

**Why not:** it is **not achievable** for a self-distributed client. PF `user`/`group`
are match criteria only and cannot appear on `nat`/`rdr`; `route-to` is directional-only,
does not rewrite source addresses and is unproven; `ipfw` is absent from current XNU;
`NEAppRule` is read-only to the provider and installed by a managed profile;
`NEFilterDataProvider` cannot relay traffic. See ADR-0007.

### 8. Windows per-process redirection

**Upstream:** not implemented upstream either.

**Why not:** without a kernel-mode WFP callout driver, `ALE_APP_ID` can only permit or
block an application — it cannot redirect it into the tunnel. `ALE_CONNECT_REDIRECT`
requires a callout driver. `FwpmConnectionPolicyAdd0` is a documented user-mode
exception but its minimum Windows build is undocumented, so it is a version-gated spike,
never a v1 dependency. See ADR-0007.

## Components that ARE worth adapting

Listed so the useful parts are not lost behind the restrictions above. Each still
requires a register entry and an attribution header.

* **Share-link parsing edge cases** — years of accumulated variation between panels that
  is expensive to rediscover from bug reports. Our parser already covers the documented
  forms; upstream covers more malformed ones.
* **Protocol and transport JSON templates** — the precise field combinations per
  protocol/transport combination.
* **Platform quirks** — which flags and command forms actually work on each OS, and which
  ones are silently ignored.
* **System proxy handling** — the per-desktop variations (GSettings, KDE, WinINet,
  `networksetup`) are pure tedium and are well covered upstream.

## Attribution header format

Place this immediately above the namespace declaration of an adapted file:

```csharp
// ---------------------------------------------------------------------------------
// Adapted from v2rayN (https://github.com/2dust/v2rayN), GPL-3.0-only.
// Upstream file: <path in the upstream repository>
// Changes: <what was changed and why>
// ---------------------------------------------------------------------------------
```

The header is required, not optional: the CI guard fails an unattributed file, and a
missing notice is both a licence violation and a false statement of authorship.
