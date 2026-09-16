# ADR-0003 — Geo-data asset management

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —
- **Implementation status:** Partially implemented. The pure half exists in
  `src/MyVpn.Core/Geo/` (`GeoAssetKind`, `GeoAssetInfo`, `GeoAssetValidator`,
  `ProtoReader`, `GeoDataConstants`, `GeoDataStatus`, `GeoRuleAvailability`).
  The I/O half (manager, store, downloader, manifest, launch-time environment
  injection, pre-flight assertion) is planned.

## Context

v2rayN issue #9765 is the canonical failure of this class: Xray refuses to start
because it cannot open `geosite.dat`, and the user is shown an opaque
`Failed to start` message plus Xray's stderr. The research report
(`docs/research/02-issue-9765-geodata.md`) established the root cause from the
maintainer's own statements, the source fix commit, and the Xray-core source. It
is worth stating precisely because the intuitive diagnosis is wrong.

### The verified root cause (and what it was not)

**It was NOT a relative path.** On macOS and Linux, v2rayN launched the Xray
process elevated through a generated shell script whose body was

```
exec sudo -S -- <xray> run -c <config>
```

while the wrapper process was constructed with `environmentVars: null`. The
intended value of `XRAY_LOCATION_ASSET` was already **absolute**
(`Utils.GetBinPath("")` → `Path.Combine(StartupPath(), "bin")`, where
`StartupPath()` is `AppDomain.CurrentDomain.BaseDirectory`). It was simply
**never delivered to the child**. `sudo`'s default `env_reset` would have
stripped it even if it had been set on the parent.

Xray then fell back to its own default asset location, which is the **directory
containing the Xray executable** (`<data dir>/bin/xray`), while the `.dat` files
live in `<data dir>/bin`. It stat'ed a non-existent path and refused to start.

* Maintainer diagnosis, issue #9765, 2026-07-16: 「geosite.dat 找不到确定是 环境变量未设置导致的，已经修复。」
  ("the missing geosite.dat is confirmed to be caused by the environment
  variable not being set; it is fixed").
* Fix commit `2dust/v2rayN@223642dd67e976dcea88eb7a268ffd3d15d875e6`, first
  shipped in **v2rayN 7.24.0**, which injects variables into the generated
  shell line as `exec sudo -S -- env KEY=VALUE …`.
* The user-visible symptom, from #9715 (Arch Linux) and #9718 (macOS):

  ```
  > common/geodata: failed to open geosite.dat
  > stat /home/user/vpn/v2rayN-linux-64/bin/xray/geosite.dat: no such file or directory
  ```

**Explicitly not the cause:** a missing or undownloaded `.dat` (both files were
present in `bin/`); a relative `XRAY_LOCATION_ASSET`; Xray's FHS search being
broken (it behaved exactly as coded); or Windows (there is no elevated-launch
path there, so the bug was macOS/Linux- and TUN-only).

**Documentation/source divergence to model correctly.** Xray's docs for
`XRAY_LOCATION_ASSET` say the fallback order is `./`, `/usr/local/share/xray`,
`/usr/share/xray`. The actual non-Windows code uses
`dir(os.Executable())` followed by `/usr/local/share/xray`, `/usr/share/xray`
and `/opt/share/xray`; Windows has **no** FHS fallback. MyVpn models the
**code**, not the doc.

### Version floor for the second channel

Xray gained a root-config `env` object in commit `d5bc58d` ("Root config: Add
`env` config (#6400)", 2026-07-10); the **first tag containing it is
`v26.7.11`**. `Config.Build()` runs `os.Setenv` for every `env` entry before any
module — including routing/geodata — is built, so a config-carried
`XRAY_LOCATION_ASSET` is immune to `sudo env_reset`, launchd, systemd and any
wrapper. It is also independent of local `sudo` policy, which is why
`sudo -E`/`env_keep` is not a fix.

### Why existence checks are insufficient

`geoip.dat`/`geosite.dat` are raw protobuf streams with **no magic header and no
checksum**. Xray streams them and compares a length-prefixed code. A file that
exists and is non-empty can still be unusable: truncated by an interrupted
download, an HTML/JSON captive-portal page saved as `.dat`, zero-filled, or the
wrong file entirely. v2rayN's updater used `File.Copy(tmp, dest, overwrite:
true)` — **not atomic** — with no checksum, no format validation and no
rollback, which is how a partial file is produced in the first place. A further
trap: a *valid* protobuf that simply lacks the requested code produces an error
that looks identical to truncation (`failed to check code IR from geosite.dat >
EOF`, issues #10153/#6218), so structural validation alone is not enough.

## Decision

### 1. Inject the asset directory through two independent channels

Every Xray launch sets **both**:

* `XRAY_LOCATION_ASSET=<absolute asset directory>` in the real child-process
  environment (`ProcessStartInfo.Environment`), and
* `"env": { "XRAY_LOCATION_ASSET": "<absolute asset directory>" }` in the
  generated root config (requires Xray ≥ `v26.7.11`; gated on the detected
  version).

Either alone suffices; both together survive an env-reset wrapper, a service
manager and a packaging quirk. `XRAY_LOCATION_CERT` gets the same treatment
whenever MyVpn manages a certificate file.

### 2. Resolve once, to an absolute path, and never recompute

Paths are resolved once into an absolute `AssetDirectory`, validated with
`Path.IsPathFullyQualified`, and thereafter used only in absolute form. No
component derives an asset path from the current working directory, the bundle
location, an environment variable at point of use, or
`AppContext.BaseDirectory` — the last is unstable under macOS App Translocation,
a read-only AppImage squashfs mount, and a per-launch mount path. The
installation directory is a read-only **seed**; the writable working copy lives
in the per-user state directory
(`%LOCALAPPDATA%\MyVpn` / `~/Library/Application Support/MyVpn` /
`$XDG_DATA_HOME/myvpn`), overridable by `MYVPN_STATE_DIR` for tests and portable
mode.

### 3. Assert resolution before launch (the direct #9765 gate)

Before spawning Xray, MyVpn runs a **pure mirror of Xray's lookup order** —
env directory, then executable directory, then (non-Windows only)
`/usr/local/share/xray`, `/usr/share/xray`, `/opt/share/xray` — and compares the
predicted path with the validated absolute path it intends Xray to use. A
mismatch aborts the launch with `geodata.launch_environment_mismatch` and both
paths in the technical detail. This converts a silent runtime failure into a
deterministic startup error, and it is the regression guard for #9765.

### 4. Validate content, not existence

`GeoAssetValidator` (already implemented, pure, allocation-light, no
dependencies) walks the protobuf wire format: field 1 must be length-delimited
entry sub-messages, each carrying a printable-ASCII code in its field 1. It
rejects empty, below a plausible minimum size (`4096` bytes), truncated tags,
entries running past EOF, wrong wire types, malformed entries, and files with no
entries. Unknown top-level fields are skipped so a future schema extension is
not rejected. This reliably rejects truncation, wrong-file and captive-portal
content while remaining forward-compatible. A **required-code** check (do the
codes the active routing profile references actually exist?) is planned, because
that is the #10153/#6218 failure that structural validation cannot catch.

### 5. Integrity and provenance

Each asset records a SHA-256 (lowercase hex), size, source URL, upstream version
and timestamp. A downloaded payload is not installed unless it validates
structurally **and** matches the expected SHA-256 when one is known. A checksum
mismatch means "do not install", never "retry harder". Per-asset state is
tracked independently for `geoip.dat` and `geosite.dat`: an update that
succeeds for one and fails for the other must not leave a half-updated pair
treated as good.

### 6. Atomic stage → commit → backup → rollback

1. **Stage** into `<asset dir>/.staging/<kind>.<guid>.download` — the same
   filesystem, so the later rename is atomic — hashing while streaming and
   flushing to disk.
2. **Commit**: `File.Move(live, backup, overwrite: true)` then
   `File.Move(staged, live, overwrite: false)`. If the second move fails, the
   first is undone immediately. The live file is **never modified in place**.
3. If the live file is locked (a running Xray holding it on Windows), the commit
   is deferred with `install.deferred = true` and retried after the core stops.
4. A failed validation or download leaves the previous generation byte-identical.

### 7. Never emit a rule that can fail

The config builder consults `GeoDataStatus` and emits a `geoip:`/`geosite:` rule
**only** for an asset whose health is `Valid`. When an asset is unusable it
substitutes an explicit, documented fallback rule set and raises a repair
prompt. A corrupt geo asset degrades routing; it must never prevent the tunnel
from starting — which is exactly what Xray does today.

### 8. Update out-of-band, never mid-session

A geo update must not tear down an active connection. A completed update marks
`RestartRequired` and is applied at the next safe boundary (or through Xray's
geodata hot-reload, available from `v26.4.25`), never by stopping a running
core. Updates prefer an offline repair from the shipped seed before any network
fetch, and never overwrite a newer good generation with an older bundled one
(issue #6218).

### 9. No shell, no string interpolation of paths

Child processes are launched with an `argv` array and an explicit environment,
through `ProcessStartInfo.ArgumentList` / the privileged-process launcher.
No generated shell script, no `sudo -E`, no `KEY="VALUE"` interpolation. This
closes the shell-injection class in v2rayN's own fix (its `AppendQuotes()` does
not escape `"`, backtick, `$`, `\` or `$( )`, and macOS state paths contain
spaces).

## Consequences

**Positive**

* The #9765 failure mode cannot recur silently: the config channel survives an
  env-resetting wrapper, and the pre-flight assertion catches a mismatch before
  the core starts.
* A truncated, HTML or wrong-file asset is detected and refused rather than
  installed; a crash mid-update cannot leave a partial live file.
* A corrupt asset degrades routing instead of bricking the connection.

**Negative / costs**

* Two channels must be kept coherent, and the config channel is version-gated
  (`≥ v26.7.11`); a test must assert that removing either channel makes the
  regression test fail.
* Staging plus one backup generation means roughly three times the asset bytes
  on disk (tens of MB per asset as observed upstream), so a pre-flight disk-space
  check is required.
* The writable working copy duplicates data that a system package also ships in
  `/usr/share`; disk budget and first-run seeding must be deliberate.

**Still UNVERIFIED / to be proven on hardware**

* Windows file-locking behaviour for `MoveFileEx` while Xray holds the asset
  open (mitigated by deferred commit, not eliminated).
* macOS App Translocation for our specific signed/notarized build (mitigated by
  never using bundle-derived asset paths at all).
* Whether any regional preset's asset actually contains the codes it is expected
  to (the required-code check is the answer; it is not implemented yet).

## Alternatives considered

* **Copy the `.dat` files next to `xray.exe`** (v2rayN's official workaround).
  Rejected: it works around the symptom, breaks in a read-only AppImage/deb/rpm
  layout, and still leaves the user with an unvalidated file.
* **Rely on `sudo -E` / `env_keep`.** Rejected: policy-dependent, refused unless
  sudoers allows it, and useless under launchd/systemd. The maintainers rejected
  it for the same reason.
* **Use only the config `env` channel.** Rejected: requires Xray ≥ `v26.7.11`,
  and older-but-supported builds are within the supported range.
* **Use only the process environment channel.** Rejected: it is exactly the
  channel that an elevated launch loses.
* **Check the file with `File.Exists`/`Length > 0`.** Rejected: passes for
  truncated, HTML and wrong-file content — the three most common real cases.
* **Take a `Google.Protobuf` dependency and deserialize the real schema.**
  Rejected: a large dependency and attack surface for a structural check that
  the existing allocation-light `ProtoReader` already performs without exposing
  schema types to untrusted input.
* **Validate by running Xray and reading its error.** Rejected: that is the
  status quo whose user-facing failure this ADR exists to remove.
* **Resolve relative to the executable, like Xray does.** Rejected: unstable
  under translocation, AppImage and per-machine installs.

## References

* `docs/research/02-issue-9765-geodata.md` — **primary grounding**: §1.1 the
  confirmed root cause and the fix commit, §1.2 exact error strings and
  reporting component, §1.3 affected platforms/versions, §1.4 fix and release
  (v2rayN 7.24.0), §1.5 `XRAY_LOCATION_ASSET` exact semantics and the
  `v26.7.11` config-`env` floor, §1.6 geo-data format and failure modes, §1.7
  packaging as a cause, §1.8 post-update behaviour (#6218, #10153), §1.9 the
  correction to this repository's scaffolding, §1.10 what is *not* the cause,
  §2.5/§2.8 storage and launch contract, §3 risks R1–R16.
* `docs/research/03-xray-tun-inbound.md` §1.4/§1.6 — Xray does not do DNS
  takeover on Linux/macOS; the config `env` object's place in the root schema.
* Implemented code: `src/MyVpn.Core/Geo/GeoAssetValidator.cs`,
  `src/MyVpn.Core/Geo/GeoDataConstants.cs`, `src/MyVpn.Core/Geo/GeoAssetInfo.cs`,
  `src/MyVpn.Core/Geo/GeoDataStatus.cs`, `src/MyVpn.Core/Geo/ProtoReader.cs`,
  `src/MyVpn.Core/Geo/GeoAssetKind.cs`.
* Upstream: `2dust/v2rayN` fix commit
  `223642dd67e976dcea88eb7a268ffd3d15d875e6`;
  `XTLS/Xray-core@c412e77a` files `common/platform/platform.go`,
  `common/platform/others.go`, `common/platform/windows.go`,
  `common/platform/filesystem/file.go`, `common/geodata/geodat_loader.go`,
  `infra/conf/xray.go`; commits `d5bc58d` (`env` ≥ v26.7.11) and `3bc24a3`
  (geodata auto-update ≥ v26.4.25).
* Official docs: <https://xtls.github.io/en/config/env.html>.
* Issues: #9765, #9764, #9715, #9718, #10153, #6218, #9318 —
  <https://github.com/2dust/v2rayN/issues>.
* Apple App Translocation (general packaging risk):
  <https://developer.apple.com/documentation/>; AppImage read-only mount:
  <https://docs.appimage.org/reference/architecture.html>.
