# Issue #9765 — Geo-Data Failure Class: Root-Cause Research

| Field | Value |
|---|---|
| **Report** | `docs/research/02-issue-9765-geodata.md` |
| **Author** | Issue #9765 Root-Cause Research Agent |
| **Date** | 2026-09-16 |
| **Subject** | `2dust/v2rayN#9765` + the general class of Xray geo-data failures |
| **Method** | GitHub REST API + HTML `react-app.embeddedData` fallback (API was rate-limited mid-run), `git` source inspection of `2dust/v2rayN` and `XTLS/Xray-core` cloned to `/tmp`, official Xray docs |
| **Verdict** | **Root cause confirmed from maintainer statements, a source fix commit, and the Xray-core source.** |

> **Authority note.** Everything in §1 marked **[READ]** was read directly in the issue text, the
> Xray-core / v2rayN source, or official docs. Items marked **[INFERRED]** are conclusions drawn
> from that source. Items marked **[UNVERIFIED]** could not be confirmed from primary sources.

---

## 1. Findings

### 1.1 The exact root cause (confirmed)

**On macOS and Linux, when TUN mode runs through the Xray core, v2rayN launched Xray through an
elevated `sudo` path that never delivered the process environment — so `XRAY_LOCATION_ASSET` was
lost. Xray then fell back to its default asset directory, the *directory containing the Xray
executable* (`<data dir>/bin/xray`), while the geo databases live in `<data dir>/bin`. The geodata
loader failed with `no such file or directory`, routing-configuration building failed, and the core
refused to start.** **[READ]**

The definitive evidence chain:

**(a) The maintainer's own diagnosis, in the issue thread.**

Issue #9765 was filed by the repository owner (`2dust`, `author_association: OWNER`) on
2026-07-16T02:06:33Z. In the same thread:

> "可能是这里调用的问题，没有设置环境变量，先把这里加上环境变量测下"
> — @2dust, 2026-07-16T02:52:49Z, linking
> `v2rayN/ServiceLib/Manager/CoreAdminManager.cs#L32` **[READ]**

> "geosite.dat 找不到确定是 环境变量未设置导致的，已经修复。"
> — @2dust, 2026-07-16T03:47:57Z **[READ]**

(Translation: *"It's probably the call here — no environment variable is set; add the environment
variable here and test."* / *"The missing geosite.dat is confirmed to be caused by the environment
variable not being set; it is fixed."*)

**(b) The fix commit explicitly cites this issue.**

```
commit 223642dd67e976dcea88eb7a268ffd3d15d875e6
Author: 2dust
Date:   Thu Jul 16 11:39:47 2026 +0800

    Fix

    https://github.com/2dust/v2rayN/issues/9765

 v2rayN/ServiceLib/Manager/CoreAdminManager.cs | 13 ++++++++++++-
 1 file changed, 12 insertions(+), 1 deletion(-)
```
**[READ]**

The diff replaces the unconditional elevation line

```csharp
sb.AppendLine($"exec sudo -S -- {cmdLine}");
```

with a branch that forwards `coreInfo.Environment` to the elevated process:

```csharp
// Passing environment variables to the sudo command, here it only xray or sing-box.
if (coreInfo.Environment.Count > 0)
{
    var envArgs = string.Join(" ", coreInfo.Environment.Where(kv => kv.Value.IsNotEmpty()).Select(kv => $"{kv.Key}={kv.Value.AppendQuotes()}"));
    sb.AppendLine($"exec sudo -S -- env {envArgs} {cmdLine}");
}
else
{
    sb.AppendLine($"exec sudo -S -- {cmdLine}");
}
```
**[READ — `git show 223642dd`]**

**(c) The mechanism in v2rayN source.**

- `CoreAdminManager.RunProcessAsLinuxSudo` (line 32 in the pinned commit, matching the maintainer's
  link) built `exec sudo -S -- <xray> run -c <config>` and constructed its `ProcessService` with
  `environmentVars: null` — before the fix the method did not touch `coreInfo.Environment` at all.
  **[READ]**
- `CoreManager.RunProcess` routes to that method only when
  `ShouldRunAsSudo(isTunLaunch, coreType, isNonWindows)` is true; that predicate is
  `isTunLaunch && coreType is sing_box or mihomo or Xray && non-Windows`. **[READ]**
- `CoreManager.RunProcessNormal` (the non-elevated path) *does* materialise
  `coreInfo.Environment` into a `Dictionary<string,string>` and pass it to `ProcessService`, which
  writes it into `ProcessStartInfo.Environment`. **[READ]**
- `CoreInfoManager` defines, for `ECoreType.Xray`:
  `{ Global.XrayLocalAsset, Utils.GetBinPath("") }` and `{ Global.XrayLocalCert, Utils.GetBinPath("") }`,
  with `Global.XrayLocalAsset = "XRAY_LOCATION_ASSET"`. **[READ]**
- `Utils.GetBinPath("")` returns `Path.Combine(StartupPath(), "bin")`, and `StartupPath()` returns
  the *absolute* `AppDomain.CurrentDomain.BaseDirectory` (or the absolute LocalApplicationData path
  when `V2RAYN_LOCAL_APPLICATION_DATA_V2=1`). So the value v2rayN intended to export was already an
  absolute directory; it was simply never delivered. **[READ]**

**(d) The Xray-core fallback that turns the missing variable into a wrong path.**

From `common/platform/platform.go` and `common/platform/others.go` (`!windows`):

```go
const (
    AssetLocation   = "xray.location.asset"
    ...
)
func (f EnvFlag) GetValue(defaultValue func() string) string {
    if v, found := os.LookupEnv(f.Name); found { return v }          // "xray.location.asset"
    if len(f.AltName) > 0 {
        if v, found := os.LookupEnv(f.AltName); found { return v }   // "XRAY_LOCATION_ASSET"
    }
    return defaultValue()
}
func getExecutableDir() string {
    exec, err := os.Executable()
    ...
    return filepath.Dir(exec)
}
```
```go
// GetAssetLocation searches for `file` in the env dir, the executable dir, and certain locations
func GetAssetLocation(file string) string {
    assetPath := NewEnvFlag(AssetLocation).GetValue(getExecutableDir)
    defPath := filepath.Join(assetPath, file)
    for _, p := range []string{
        defPath,
        filepath.Join("/usr/local/share/xray/", file),
        filepath.Join("/usr/share/xray/", file),
        filepath.Join("/opt/share/xray/", file),
    } {
        if _, err := os.Stat(p); os.IsNotExist(err) { continue }
        return p
    }
    return defPath   // asset not found — let the caller throw out the error
}
```
**[READ — `XTLS/Xray-core@c412e77a`, `common/platform/others.go`, `common/platform/platform.go`]**

With `XRAY_LOCATION_ASSET` absent, `assetPath = dir(xray executable) = <data dir>/bin/xray`. The
FHS fallbacks (`/usr/local/share/xray`, `/usr/share/xray`, `/opt/share/xray`) do not exist in a
zip/portable v2rayN install, so the function returns `<data dir>/bin/xray/geosite.dat` — exactly the
path in the users' logs. **[INFERRED — deterministic consequence of the read code]**

On Windows, `common/platform/windows.go` has **no FHS fallback** (env dir or executable dir only),
and v2rayN has no elevated-launch path on Windows (`ShouldRunAsSudo` requires non-Windows). That is
why the bug is macOS/Linux-only and TUN-only. **[READ + INFERRED]**

### 1.2 The exact failure, error message and reporting component

The clearest reproduction is issue **#9715**, *"[Bug]: TUN mode looking for geodat files in a wrong
location"* (Arch Linux, v2rayN v7.23.3, filed 2026-07-09):
**[READ — https://github.com/2dust/v2rayN/issues/9715]**

> ```
> Failed to start: main: failed to load config files: [/home/user/vpn/v2rayN-linux-64/binConfigs/config.json]
> > infra/conf: failed to build routing configuration
> > infra/conf: invalid field rule
> > common/geodata: illegal domain rule: geosite:category-ads-all
> > common/geodata: failed to open geosite.dat
> > stat /home/user/vpn/v2rayN-linux-64/bin/xray/geosite.dat: no such file or directory
> ```

macOS equivalent, issue **#9718** (macOS 26.5.1 / v2rayN 7.23.3 / Xray 26.6.27, 2026-07-10):
**[READ — https://github.com/2dust/v2rayN/issues/9718]**

> ```
> Failed to start: ... > infra/conf: failed to build routing configuration
> > infra/conf: invalid field rule
> > common/geodata: illegal domain rule: geosite:google
> > common/geodata: failed to open geosite.dat
> > stat /Users/xxx/Library/Application Support/v2rayN/bin/xray/geosite.dat: no such file or directory
> ```
> "我看了下，确实没有这个文件；这个文件在 `/Users/xxx/Library/Application Support/v2rayN/bin` 目录下；
> 7.22.x时还是好的，更新后就报错了" — *"I checked: that file really isn't there; it is in the
> `.../bin` directory. It was fine in 7.22.x, and broke after updating."*

| Aspect | Finding |
|---|---|
| **What fails** | Xray's routing-configuration build, while resolving a `geosite:`/`geoip:` rule → geodata loader → asset open. |
| **Component that reports it** | Xray-core: `infra/conf` (routing build) → `common/geodata` → `common/platform/filesystem`. The GUI only surfaces Xray's stderr as *"Failed to start, please check the prompt information"*. |
| **Exact strings** | `failed to open geosite.dat` (from `geodat_loader.go:19`, `errors.New("failed to open ", file).Base(err)`) plus the raw `stat <path>: no such file or directory` from `os.Stat`. **[READ]** |
| **Fatal?** | **Hard fail.** Xray does not fall back to an embedded list. `Config.Build()` returns the error; the process exits; no tunnel is established. Confirmed by the users' logs and by the absence of any fallback branch in `getAssetFileLocation` / `checkFile` / `Find`. **[READ]** |

### 1.3 Affected platforms and versions reported by users

| Issue | Date | OS | v2rayN | Xray | Triggering rule | Path in error |
|---|---|---|---|---|---|---|
| [#9715](https://github.com/2dust/v2rayN/issues/9715) | 2026-07-09 | Arch Linux | 7.23.3 | (n/s) | `geosite:category-ads-all` | `.../bin/xray/geosite.dat` |
| [#9718](https://github.com/2dust/v2rayN/issues/9718) | 2026-07-10 | macOS 26.5.1 | 7.23.3 | 26.6.27 | `geosite:google` | `.../bin/xray/geosite.dat` |
| [#9764](https://github.com/2dust/v2rayN/issues/9764) | 2026-07-15 | macOS + Debian 12 | 7.23.4 | 26.6.1 | `geoip:private` etc. | `.../bin/xray/{geo,geosite}.dat` |
| [#9765](https://github.com/2dust/v2rayN/issues/9765) | 2026-07-16 | macOS / Linux | "v7.23.4+" | — | unified write-up | `.../xray/geosite.dat` |

**[READ — all four issues]**

Additional version data points from the #9765 thread **[READ]**:

- @imanbabaei, 2026-07-25: *"The error still exists in the latest macOS version 7.23.4. As a quick
  workaround, copy the `geoip.dat` and `geosite.dat` files from
  `/Users/USERNAME/Library/Application Support/v2rayN/bin` to
  `/Users/USERNAME/Library/Application Support/v2rayN/bin/xray`."* — Note: 7.23.4 **predates** the fix
  (see §1.4); whether this user had actually installed 7.24.0 is **[UNVERIFIED]**.
- @crazyjtt03, 2026-07-26: *"7.24.2出现tun问题。7.23.4没有问题"* — a TUN problem on 7.24.2 while
  7.23.4 was fine. Whether this is the same root cause, a different TUN regression, or user
  environment is **[UNVERIFIED]**; the reported direction is the *opposite* of the geodata defect.
- @BBplux, 2026-08-29: posted TUN traffic logs where domestic sites work and foreign sites do not
  with TUN on, but work via system proxy with TUN off. This is a **routing/DNS symptom, not the
  asset-path failure**; no `geosite.dat` error appears. **[UNVERIFIED as related.]**

The maintainer's write-up attributes the change to **v7.23.4**:
**[READ — issue #9765 body]**

> "从 **v7.23.4** 开始，TUN 实现方式与「TUN 设置」中的选项相关：启用「旧版 TUN 保护」→ 使用
> **sing-box TUN**；不启用「旧版 TUN 保护」→ 使用 **xray TUN**"
> — *"Since v7.23.4, the TUN implementation depends on the option in TUN settings: with 'legacy TUN
> protection' enabled → sing-box TUN; without it → xray TUN."*

> "在 **macOS / Linux** 下，使用 **xray TUN** 时，`XRAY_LOCATION_ASSET` 相关路径存在已知问题。
> 部分环境会导致 xray 进程去错误目录查找 geodata 文件（如 `xray/geosite.dat`），从而启动失败。"
> — *"On macOS/Linux, when using xray TUN, there is a known problem with the `XRAY_LOCATION_ASSET`
> path. In some environments the xray process looks for geodata files in the wrong directory (e.g.
> `xray/geosite.dat`), so startup fails."*

Note that #9715 and #9718 were both filed against **7.23.3**, so the defect predates 7.23.4 slightly;
7.23.4 is when it was formally acknowledged and the default TUN path was discussed. The precise
first-affected build was not determinable from the issue text. **[UNVERIFIED]**

### 1.4 The fix and its release (important for MyVpn's compatibility matrix)

**[READ]**

- Fix commit: `223642dd67e976dcea88eb7a268ffd3d15d875e6`, 2026-07-16, explicitly cites #9765.
- v2rayN tags: `7.23.4` = `1de83f96…` (2026-07-11, **no** env passthrough);
  `7.24.0` = `5dd5b258…` (2026-07-16, **includes** the passthrough).
- Therefore the fix first shipped in **v2rayN 7.24.0**. Issue #9715 was closed with a maintainer
  comment linking `https://github.com/2dust/v2rayN/releases/tag/7.24.0`. **[READ]**
- Issue #9764 — the precise engineering write-up titled *"[Bug]: macOS/Linux 开启 TUN 后通过 sudo
  启动 Xray 时丢失 XRAY_LOCATION_ASSET"* ("macOS/Linux: XRAY_LOCATION_ASSET is lost when Xray is
  launched through sudo after enabling TUN") — was filed 2026-07-15 by a community member and closed
  the same day the fix landed. Its analysis independently matches the maintainer's and cites the same
  three source locations. **[READ]**

The current (post-fix) v2rayN code still constructs the wrapper `ProcessService` with
`environmentVars: null` and instead injects the variables into the generated bash line via
`exec sudo -S -- env KEY=VALUE …`. **[READ]**

### 1.5 `XRAY_LOCATION_ASSET`: exact semantics

Official documentation, `https://xtls.github.io/en/config/env.html` **[READ]**:

> **Resource File Path** — Name: `XRAY_LOCATION_ASSET`. Default value: Specific FHS directories or
> the directory containing the Xray executable.
> "This variable specifies the **directory** containing the `geoip.dat` and `geosite.dat` files.
> If it is not specified, the program looks for resource files in the following order:
> `./`, `/usr/local/share/xray`, `/usr/share/xray`."

> The `env` item [in the root config] sets the exact name written in the configuration … The `env`
> item takes effect only after the configuration files have been located, read, and merged. Some
> environment variables must be set through a shell or service manager before Xray starts, for
> example: `XRAY_JSON_STRICT`, `XRAY_LOCATION_CONFIG`, `XRAY_LOCATION_CONFDIR`, `GOGC`,
> `GOMEMLIMIT`, `GOMAXPROCS`, `GOTRACEBACK`.

Key semantics, all **[READ]** from source unless noted:

| Question | Answer |
|---|---|
| **Dir or file?** | **Directory.** `getAssetFileLocation` joins the directory with the canonical file name: `Path.Combine(assetPath, "geosite.dat")`. Passing a file path yields `<yourfile>/geosite.dat`. |
| **Variable name** | Xray checks `xray.location.asset` first (exact, lowercase-dotted — a legal POSIX env name), then the normalised `XRAY_LOCATION_ASSET` (`NormalizeEnvName` upper-cases and replaces `.`→`_`). |
| **Absolute or relative?** | Not validated as absolute. A relative value is joined as-is and therefore depends on the process **working directory**, which is exactly the class of fragility MyVpn must eliminate. The `/usr/{local/,}share/xray` and `/opt/share/xray` candidates are absolute. |
| **Path-traversal guard** | `getAssetFileLocation` rejects the *file name* unless `filepath.IsLocal(file)` and `file != "."` ("asset path must stay in asset directory"). This guards the asset *name*, **not** the env value. |
| **Regular file** | Required: `if !info.Mode().IsRegular() { return errors.New("asset is not a regular file") }` — a directory named `geosite.dat` fails here. |
| **Default order (non-Windows)** | `dir(executable)/<file>` (or the env dir), then `/usr/local/share/xray/<file>`, `/usr/share/xray/<file>`, `/opt/share/xray/<file>`; if none exists, returns the env/exe-derived path so the error names it. |
| **Default order (Windows)** | `dir(executable)/<file>` or env dir only. No FHS fallback. |
| **Process inheritance** | An ordinary child process inherits it from its parent (`ProcessStartInfo.Environment` works). An elevated child loses it: `sudo` defaults to `env_reset`, so unless `env_keep`/`-E` applies, the variable is stripped. This is precisely the #9765 mechanism. |
| **Config `env` item** | Usable for `XRAY_LOCATION_ASSET`: `Config.Build()` runs `for key, value := range c.Env { os.Setenv(key, value) }` **before** post-processing and before any module — including routing/geodata — is built (`infra/conf/xray.go`). The docs' "must be set earlier" list deliberately excludes `XRAY_LOCATION_ASSET`. |
| **Config `env` availability** | Added in `XTLS/Xray-core` commit `d5bc58d` *"Root config: Add `env` config (#6400)"* (2026-07-10); first tag containing it is **v26.7.11**. Older Xray builds ignore/serve no `env` item. This matters: v2rayN 7.23.4 shipped Xray **26.6.1** (#9764), which is too old for the config-`env` workaround. |

> ⚠️ **Documentation/source discrepancy [READ]:** the docs say the first fallback is `./` (the
> working directory). The actual code on non-Windows uses `dir(os.Executable())`, and on Windows
> only the env dir or the executable dir. MyVpn must model the **code**, not the doc. In a deb
> install the launcher does `cd /opt/v2rayN`, yet Xray still looked in `/opt/v2rayN/bin/xray`, which
> is consistent only with the code behaviour.

### 1.6 Geo-data path resolution, and missing / corrupt / truncated files

All **[READ]** from `XTLS/Xray-core@c412e77a`, `common/geodata/geodat_loader.go`,
`common/platform/filesystem/file.go`, `common/geodata/geodat.proto`, `common/geodata/rule_parser.go`.

**Format.** `geoip.dat` / `geosite.dat` are **raw protobuf streams with no magic header or
checksum**. The file is a sequence of records `[tag=0x0A][varint bodyLen][body]` where `body` is a
serialized `GeoSite` / `GeoIP` message whose field 1 is the ASCII code (`GeoSiteList`/`GeoIPList`
entries). Xray reads them with a streaming scanner (`find`) that compares the length-prefixed code
against the rule's requested code (`strings.ToUpper`).

**Failure matrix.**

| Condition | Xray behaviour | Observed error |
|---|---|---|
| File absent | `os.Stat` ENOENT in `getAssetFileLocation` | `failed to open geosite.dat` + `stat <path>: no such file or directory` |
| Zero-byte file | `OpenAsset` succeeds (stat OK, regular file); `find` hits `ReadByte` → `io.EOF` | `failed to open geosite.dat` + `EOF`, or `failed to check code X from geosite.dat` + `EOF` |
| Truncated file | `io.ReadFull` short-read → `io.ErrUnexpectedEOF`; or a declared length beyond EOF | `failed to load code X from geosite.dat: unexpected EOF` / `failed to check code X from geosite.dat` |
| Wrong format (HTML/JSON/gzip saved as `.dat`) | `decodeVarint` on arbitrary bytes yields a bogus length → `invalid body length`, or `io.ReadFull` fails | `failed to load code X from geosite.dat` |
| Directory where a file is expected | `!info.Mode().IsRegular()` | `asset is not a regular file` |
| Valid protobuf, requested code absent | `find` scans to EOF without a match and returns `io.EOF` | **`failed to check code IR from geosite.dat` + `EOF`** — see #10153 |
| Older Xray with absent code | dedicated lookup error | `list not found in geosite.dat: RU-BLOCKED-ALL` (#6218, 2024) / `code not found in geosite.dat: CATEGORY-AI` (#9318) |

**No fallback anywhere.** There is no built-in list, no network retry, no "ignore unknown rule"
mode. The only mitigations in Xray are:
- the FHS directory search (§1.5), which helps distro packages that install assets to
  `/usr/share/xray` but not zip/portable/bundle layouts;
- Xray's own optional geodata auto-update + hot-reload (`infra/conf/geodata.go`,
  `app/geodata`, commit `3bc24a3` *"Geodata: Support automatically updating .dat files and hot
  reloading (#5992)"*, first tag `v26.4.25`), configured with a `cron` expression, an outbound, and
  `{url,file}` assets. It still resolves `file` through the same asset location and
  `filesystem.StatAsset`, so it does not rescue a missing path. **[READ]**

**Very important diagnostic trap [INFERRED from the read code]:** when a valid `.dat` simply lacks a
requested code, current Xray reports `… > EOF`. This looks identical to a truncated download. Any
MyVpn validator that only checks "parses as protobuf" will pass such a file and the user will still
get an opaque `EOF`. Code-level validation against the *codes referenced by the active routing
profile* is required.

### 1.7 Packaging as a cause

v2rayN's own distribution was read from the repo. Its relevant facts:

| Layout | Asset location | Risk |
|---|---|---|
| **Windows zip / winget** | `bin/geoip.dat`, `bin/geosite.dat`, core at `bin/xray/xray.exe` | **Not affected by #9765** — no elevation path; env passed via `ProcessStartInfo`. Installed under `%LOCALAPPDATA%` (winget) is detected as non-writable, switching the state dir. **[READ: `Utils.HasWritePermission`]** |
| **Linux zip / portable** | same relative layout under the extracted directory | Affected: TUN → sudo → env lost. Also the extracted dir may be read-only. |
| **macOS `.app`** | `package-osx.sh` copies the whole payload, including `bin/`, into `v2rayN.app/Contents/MacOS/`, and drops `NotStoreConfigHere.txt` there so state moves to `~/Library/Application Support/v2rayN`. **[READ]** | The user's error path (`~/Library/Application Support/v2rayN/bin/xray/…`) confirms Xray's binary and assets end up in the *state* dir, not the bundle. Unsigned app → Gatekeeper/quarantine → **App Translocation**: an unsigned, quarantined app is executed from a random read-only `/private/var/folders/.../AppTranslocation/<uuid>/d/` path, so any absolute path derived from the bundle changes every launch. v2rayN mitigates this with `NotStoreConfigHere.txt`; **MyVpn must not rely on bundle-relative paths at all.** **[INFERRED from Apple's documented behaviour] [UNVERIFIED for this specific build]** |
| **macOS signing** | `package-osx.sh` performs **no** `codesign`/`notarize`; `upload-sign.yml` only GPG-signs release artifacts. **[READ]** | Confirms the translocation preconditions for the shipped `.dmg`. |
| **deb** | Installs to `/opt/v2rayN`; `unify_geo_layout()` **moves** `geoip*.dat`, `geosite.dat`, `Country.mmdb`, `geoip.metadb` out of `bin/xray/` into `bin/`; the launcher does `cd /opt/v2rayN`. **[READ: `package-debian.sh`]** | Two amplifiers: (1) moving the files out of `bin/xray/` **empties Xray's exe-dir fallback**, so the env var becomes load-bearing; (2) `/opt/v2rayN` is root-owned, so the in-app "update geo files" cannot write there without elevation. |
| **rpm** | same `unify_geo_layout` pattern via `package-rhel*.sh`. **[READ]** | Same as deb. |
| **AppImage** | **Not produced by v2rayN** — no AppImage entry point or script exists in the repo. | General class only: an AppImage is a read-only squashfs mounted at `/tmp/.mount_<name><rand>/`, so (a) assets inside the mount cannot be updated in place — an update would silently fail or require a per-user writable copy — and (b) the mount path changes per launch, so a stored absolute path breaks. This is a **MyVpn** design concern, not an observed v2rayN report. **[INFERRED] [UNVERIFIED for v2rayN]** |
| **Windows installer / MSI / NSIS** | **Not present** in the repo (only zip + winget). | Same status: general class only; the concrete risk is `Program Files` being non-writable and per-machine. **[INFERRED]** |

The maintainer's own instructions in #9715 confirm the packaging dimension:
**[READ — https://github.com/2dust/v2rayN/issues/9715]**

> "你可以从 bin 文件夹将 geoip.dat 和 geosite.dat 拷贝一份给 xray 文件夹，等到xray tun稳定、可用，
> 我们会修改打包脚本"
> — *"You can copy geoip.dat and geosite.dat from the bin folder into the xray folder; once xray tun
> is stable and usable we will modify the packaging script."*

and in #9765:

> "### 方案 1：复制 geodata 文件到 xray 目录 … 将 `bin` 目录下的文件复制一份到 `bin/xray` 目录"
> "### 方案 2：改用 sing-box TUN … 可绕开该问题"

### 1.8 Behaviour after a client update

Three distinct post-update failure modes exist in this class:

1. **Path change / stale absolute path (the #9765 neighbourhood).** In #9718 the user states
   *"7.22.x时还是好的，更新后就报错了"* — fine on 7.22.x, broken after updating — and reports that
   deleting `~/Library/Application Support/v2rayN` and reinstalling did **not** fix it. That rules
   out stale user config as the cause here and points at the code path change (TUN→Xray), but it
   demonstrates the general hazard: an absolute asset path persisted by an older build can outlive
   the directory it named. **[READ + INFERRED]**
2. **Installer overwrites user geo data with older bundled data.** Issue
   [#6218](https://github.com/2dust/v2rayN/issues/6218), *"v2rayN autoupdate replaces regional
   geoip/geosite files with the default ones"*: **[READ]**
   > *"the updater unpacks geoip/geosite files from the downloaded archive and replaces the regional
   > files. These default files don't have the regional tags in them. As the result, the app doesn't
   > work after the restart because xray-core reports missing tags in routing settings."*
   > Log: `failed to load geosite: RU-BLOCKED-ALL > infra/conf: list not found in geosite.dat: RU-BLOCKED-ALL`
   Maintainer response: *"This application is only for users in mainland China and has not been tested
   in other regions."* — i.e. unresolved as designed behaviour.
3. **Valid but wrong/stale asset after a "successful" update.** Issue
   [#10153](https://github.com/2dust/v2rayN/issues/10153) (Arch Linux, v7.25.1, Xray 26.7.11):
   **[READ]**
   > *"When Regional preset = Iran is selected, Xray fails to start because the installed geosite.dat
   > does not contain the required IR rule. … The GeoFiles installed by v2rayN were still old:
   > `geoip.dat 17M 2026-08-11`, `geosite.dat 11M 2026-08-11`. After manually installing the latest
   > Iran GeoFiles from Chocolate4U/Iran-v2ray-rules the original geosite:ir configuration worked."*
   > Log: `common/geodata: illegal domain rule: geosite:ir > common/geodata: failed to check code IR
   > from geosite.dat > EOF`

**Why the v2rayN update path is fragile [READ — `UpdateService.DownloadGeoFiles`]:**

```csharp
var tmpFileName = tmpFilePathDict[request.FilePath];
if (File.Exists(tmpFileName))
{
    File.Copy(tmpFileName, request.FilePath, true);   // overwrite in place, not atomic
    File.Delete(tmpFileName);
}
```

- No checksum verification and no format validation — only `File.Exists`.
- `File.Copy(tmp, dest, true)` on an existing file is **not atomic**: a crash or power loss between
  truncate and write leaves a partial `.dat`, which is exactly the "truncated file → EOF" failure.
- No rollback: the previous good file is destroyed.
- `geoip.dat` and `geosite.dat` are handled in a single batch with a single success flag, so a
  half-updated pair is possible.
- Regional presets switch the source URL but the "did the content actually change / does it contain
  the codes I need" question is never asked — the direct cause of #10153 and #6218.

### 1.9 Correction to the existing MyVpn scaffolding

The repo already contains a seeded `src/MyVpn.Core/Geo/` module
(`GeoAssetKind`, `GeoAssetInfo`, `GeoAssetValidator`, `ProtoReader`, `GeoDataConstants`,
`GeoDataStatus`, `GeoRuleAvailability`) that references #9765. One comment is **factually wrong**
and should be corrected by whoever owns `src/` (this report is boundary-limited to `docs/research/`):

> `GeoAssetInfo.cs`: `/// <summary>The configured path was relative, which is the root cause of issue #9765.</summary>`

The configured value was **absolute** (`Utils.GetBinPath("")` → absolute), and the failure was that
it was **never delivered to the elevated process**; the wrong path came from *Xray's* absolute
fallback to the executable directory. `GeoAssetHealth.PathNotAbsolute` remains a useful guard, but it
would **not** have detected #9765. **[READ — v2rayN source as cited in §1.1]**

Similarly, `GeoDataConstants`' remark that relying on Xray's default "is the second half of the
issue #9765 failure mode" is accurate.

### 1.10 What is *not* the root cause

- **Not** a missing/undownloaded geo file: both files were present in `<data dir>/bin`; the
  workaround of copying them next to the binary fixed it (#9765, #9715, #9718). **[READ]**
- **Not** a relative `XRAY_LOCATION_ASSET` value: the intended value was absolute. **[READ]**
- **Not** Xray's FHS search being broken: it behaved exactly as coded; the assets were simply not in
  any of the searched directories. **[READ]**
- **Not** Windows: no elevated path exists there. **[READ]**

---

## 2. Architecture proposal

### 2.1 Design principles

1. **Absolute paths, resolved once, never recomputed.** No component derives an asset path from the
   current working directory, the bundle location, or an environment variable at use time.
2. **The environment contract is explicit and layered.** Xray is *always* told where the assets are,
   through **two independent channels**: a real process environment variable, and the root config
   `env` object (Xray ≥ v26.7.11). Either channel alone is sufficient; both together survive sudo,
   launchd, systemd, AppImage and bundle quirks.
3. **Never emit a rule that can fail.** The config builder consults `GeoDataStatus` and emits
   `geoip:`/`geosite:` rules **only** for assets that are validated good. Otherwise it substitutes an
   explicit, documented fallback ruleset and raises a repair prompt. A corrupt asset degrades
   routing; it never prevents the tunnel from starting.
4. **Validate content, not existence.** Structural protobuf walk + minimum size + optional SHA-256 +
   required-code presence check.
5. **Install atomically, keep the previous generation, roll back on any failure.**
6. **Update out-of-band.** Updating geo data must never tear down an active connection; a completed
   update marks "reload/restart pending" and is applied on the next safe boundary (or via Xray's
   hot-reload API), never mid-session.
7. **Ship the assets, but never write into the install directory.** The install directory is a
   read-only *seed*; the writable working copy lives in the per-user state directory.
8. **No shell.** Privileged/child process launches pass arguments as an `argv` array; no generated
   bash scripts, no string interpolation of paths.

### 2.2 Layering (matches the existing solution and `Directory.Build.props`)

```
MyVpn.Core/Geo                     (pure; no I/O, no packages — existing + new value types)
      ↑
MyVpn.Infrastructure/Geo           (file system, HTTP, JSON manifest, orchestration)
      ↑
MyVpn.Application                  (commands: inspect / update / repair / diagnostics)
      ↑
MyVpn.UI  ·  MyVpn.Cli  ·  MyVpn.Service (privileged install helper)
MyVpn.Platform.*                   (privileged launch + per-OS state-directory conventions)
```

### 2.3 Path model

```csharp
namespace MyVpn.Core.Geo;

/// <summary>
/// Absolute, validated locations of the geo-data working set.
/// Constructed once at startup and thereafter treated as immutable.
/// </summary>
public sealed record GeoDataPaths
{
    /// <summary>Absolute directory exported as <c>XRAY_LOCATION_ASSET</c>.</summary>
    public required string AssetDirectory { get; init; }

    /// <summary>Absolute directory holding the previous known-good generation.</summary>
    public required string BackupDirectory { get; init; }

    /// <summary>Absolute directory holding the read-only generation shipped with the app (may be null).</summary>
    public string? SeedDirectory { get; init; }

    public string GeoIpPath => Path.Combine(AssetDirectory, "geoip.dat");
    public string GeoSitePath => Path.Combine(AssetDirectory, "geosite.dat");
    public string ManifestPath => Path.Combine(AssetDirectory, "geodata.manifest.json");

    /// <summary>
    /// Creates the paths, rejecting anything that is not fully rooted.
    /// This is the only factory; the constructor is not usable from outside.
    /// </summary>
    public static Result<GeoDataPaths> Create(string assetDirectory, string backupDirectory, string? seedDirectory)
    {
        if (!Path.IsPathFullyQualified(assetDirectory) || !Path.IsPathFullyQualified(backupDirectory))
            return Result.Fail<GeoDataPaths>(
                ErrorCodes.GeoAssetPathNotAbsolute,
                "error.geodata.path_not_absolute",
                ErrorSeverity.Critical,
                $"asset='{assetDirectory}' backup='{backupDirectory}'");

        return Result.Ok(new GeoDataPaths
        {
            AssetDirectory = Path.GetFullPath(assetDirectory),
            BackupDirectory = Path.GetFullPath(backupDirectory),
            SeedDirectory = seedDirectory is null ? null : Path.GetFullPath(seedDirectory),
        });
    }
}
```

The per-OS *convention* that produces those directories lives in the platform layer, in this order:

| Priority | Source | Notes |
|---|---|---|
| 1 | Explicit user override in settings | Must be absolute. |
| 2 | `MYVPN_STATE_DIR` (env) | Used by tests and portable mode. |
| 3 | Per-user state dir | Windows `%LOCALAPPDATA%\MyVpn`; macOS `~/Library/Application Support/MyVpn`; Linux `$XDG_DATA_HOME/myvpn` or `~/.local/share/myvpn`. |
| — | **Never** `AppContext.BaseDirectory` | Bundle/translocation/AppImage/squashfs make it unstable. |

### 2.4 Xray resolution mirror (pure, unit-testable)

This is the piece that makes #9765 *impossible to reintroduce silently*: MyVpn predicts, before
spawning, exactly which path Xray will choose, and compares it with the path MyVpn validated.

```csharp
namespace MyVpn.Core.Geo;

public sealed record XrayAssetResolution(
    string ResolvedPath,
    string ResolvedFrom,          // "env" | "executable-dir" | "fhs" | "not-found"
    bool Exists,
    IReadOnlyList<string> CandidatePaths);

/// <summary>
/// Faithful, dependency-free model of Xray-core's asset lookup
/// (common/platform/{platform,others,windows}.go).
/// </summary>
public static class XrayAssetResolution
{
    public const string AssetLocationVariable = "XRAY_LOCATION_ASSET";

    public static XrayAssetResolution Resolve(
        string assetFileName,
        string? assetLocationValue,
        string xrayExecutablePath,
        bool isWindows,
        Func<string, bool> fileExists);
}
```

Expected behaviour to encode (from §1.6): env dir → executable dir when the env value is absent;
then, **non-Windows only**, `/usr/local/share/xray`, `/usr/share/xray`, `/opt/share/xray`; return the
env/exe-derived candidate when nothing exists so the error message matches Xray's.

### 2.5 Storage, validation, checksums

```csharp
namespace MyVpn.Core.Geo;

/// <summary>Structural + optional checksum validation. Pure.</summary>
public interface IGeoAssetValidator
{
    bool HasPlausibleSize(long sizeBytes);

    GeoAssetValidationResult Validate(GeoAssetKind kind, ReadOnlySpan<byte> content);

    /// <summary>
    /// Codes referenced by the active routing/DNS profile that must be present.
    /// Catches the #10153/#6218 class: a structurally valid file that lacks the codes in use.
    /// </summary>
    GeoCodeCoverage ValidateRequiredCodes(
        GeoAssetKind kind,
        ReadOnlySpan<byte> content,
        IReadOnlyCollection<string> requiredCodes);
}

public sealed record GeoCodeCoverage(bool IsComplete, IReadOnlyList<string> MissingCodes);

/// <summary>Expected content identity for one asset.</summary>
public sealed record GeoChecksumEntry(
    GeoAssetKind Kind,
    string Sha256,           // lowercase hex
    long SizeBytes,
    string SourceUrl,
    string? Version,
    DateTimeOffset InstalledAt);

/// <summary>Persisted manifest of the currently installed generation.</summary>
public sealed record GeoChecksumManifest(
    int SchemaVersion,
    IReadOnlyList<GeoChecksumEntry> Entries,
    string? GenerationId);

public interface IGeoChecksumManifestStore
{
    Task<Result<GeoChecksumManifest?>> LoadAsync(CancellationToken ct = default);
    Task<Result> SaveAsync(GeoChecksumManifest manifest, CancellationToken ct = default);
    Task<Result> ClearAsync(CancellationToken ct = default);
}

/// <summary>File-system operations for one asset directory. The only place that touches geo files.</summary>
public interface IGeoAssetStore
{
    GeoDataPaths Paths { get; }

    Result<GeoFileSnapshot> Inspect(GeoAssetKind kind);
    Result<byte[]> ReadAll(GeoAssetKind kind);

    /// <summary>
    /// Streams content into a uniquely named file <b>in the asset directory</b> so the later
    /// rename is same-filesystem and therefore atomic. Never touches the live file.
    /// </summary>
    Task<Result<string>> StageAsync(GeoAssetKind kind, Stream content, string? expectedSha256, CancellationToken ct = default);

    /// <summary>Atomically promotes a staged file, moving the current good file to the backup generation.</summary>
    Task<Result<GeoInstallReceipt>> CommitAsync(GeoAssetKind kind, string stagedPath, CancellationToken ct = default);

    /// <summary>Restores the backup generation after a failed validation or a bad update.</summary>
    Task<Result> RollbackAsync(GeoAssetKind kind, CancellationToken ct = default);

    Task<Result<GeoBackupGeneration?>> GetBackupGenerationAsync(GeoAssetKind kind, CancellationToken ct = default);

    /// <summary>True when the directory exists and a probe file can be created and deleted.</summary>
    Task<Result<bool>> IsWritableAsync(CancellationToken ct = default);
}

public sealed record GeoFileSnapshot(GeoAssetKind Kind, string AbsolutePath, bool Exists, long SizeBytes, DateTimeOffset? LastWriteTime);

public sealed record GeoInstallReceipt(GeoAssetKind Kind, string InstalledPath, string? BackupPath, string Sha256, long SizeBytes);

public sealed record GeoBackupGeneration(string Directory, long SizeBytes, string? Sha256, DateTimeOffset CreatedAt);
```

**Atomic replacement contract (implemented in `FileSystemGeoAssetStore`):**

1. `StageAsync` writes to `<asset dir>/.staging/<kind>.<guid>.download`, flushes to disk
   (`FileStream.FlushAsync` + `Flush(true)`), and while streaming computes SHA-256, deleting the
   staging file and returning `geodata.checksum_mismatch` if the expected hash does not match.
2. `CommitAsync` performs, in order: `File.Move(live, backup, overwrite: true)` then
   `File.Move(staged, live, overwrite: false)`. Both renames are same-directory, hence atomic on
   NTFS and POSIX. If step 2 fails, step 1 is undone immediately.
3. If the live file is locked (a running Xray holding it on Windows), `CommitAsync` retries with
   backoff and finally returns `geodata.install_failed` with `install.deferred = true`; the update is
   retried after the core stops. **The existing good file is never modified in place.**
4. If the manifest is unreadable, `InspectAsync` still runs structural validation and downgrades the
   checksum criterion to a warning — a corrupt manifest must not brick the app.

### 2.6 Acquisition

```csharp
namespace MyVpn.Core.Geo;

public sealed record GeoDownloadResult(
    GeoAssetKind Kind,
    string StagedPath,
    long SizeBytes,
    string Sha256,
    string SourceUrl,
    string? Version);

public interface IGeoAssetSource
{
    string Id { get; }
    string DisplayNameKey { get; }

    Task<Result<GeoDownloadResult>> DownloadAsync(
        GeoAssetKind kind,
        IGeoAssetStore store,
        CancellationToken ct = default);
}

/// <summary>Chooses the source for the user's regional preset. Fixes #10153/#6218.</summary>
public interface IGeoAssetSourceCatalog
{
    IReadOnlyList<GeoSourceDescriptor> Sources { get; }
    Result<IGeoAssetSource> Resolve(string presetId);

    /// <summary>Codes that the chosen preset is expected to provide, e.g. ["IR"] for the Iran preset.</summary>
    IReadOnlyCollection<string> RequiredCodes(string presetId);
}

public sealed record GeoSourceDescriptor(
    string Id,
    string DisplayNameKey,
    string BaseUrlTemplate,     // ".../{0}.dat"
    bool IsBuiltIn,
    string? RegionCode);
```

The HTTP implementation enforces: HTTPS only; explicit `Content-Length` and a hard size ceiling;
a total timeout and a bounded retry; a rejection of `text/*` content types; and it streams straight
into `IGeoAssetStore.StageAsync`. A captive-portal HTML page therefore fails validation before it can
replace anything.

### 2.7 The manager

```csharp
namespace MyVpn.Core.Geo;

public sealed record GeoInspectOptions(bool ComputeSha256 = true, bool CheckWritability = true, IReadOnlyCollection<string>? RequiredCodes = null);

public sealed record GeoUpdateRequest(
    GeoAssetKind? Only = null,               // null = both; independent update is supported
    string? SourcePresetId = null,
    bool AllowNetwork = true,
    bool RepairFromSeedFirst = true,
    string Reason = "user");                 // "user" | "scheduled" | "repair" | "startup"

public sealed record GeoUpdateProgress(GeoAssetKind Kind, string Stage, double? Fraction);

public sealed record GeoUpdateOutcome(
    GeoDataStatus Status,
    GeoAssetKind[] Updated,
    GeoAssetKind[] Unchanged,
    GeoAssetKind[] Failed,
    bool RestartRequired);

public sealed record GeoRepairOutcome(GeoDataStatus Status, GeoRepairStep[] Steps, bool Succeeded);

public sealed record GeoRepairStep(string Id, bool Succeeded, string? Detail);

public interface IGeoDataManager
{
    /// <summary>Resolves paths, validates every asset, records checksums, never downloads.</summary>
    Task<Result<GeoDataStatus>> InspectAsync(GeoInspectOptions? options = null, CancellationToken ct = default);

    /// <summary>Downloads, validates and atomically installs. Safe to call while connected.</summary>
    Task<Result<GeoUpdateOutcome>> UpdateAsync(
        GeoUpdateRequest request,
        IProgress<GeoUpdateProgress>? progress = null,
        CancellationToken ct = default);

    /// <summary>One-click repair: seed copy → re-download → rollback, in that order.</summary>
    Task<Result<GeoRepairOutcome>> RepairAsync(
        IProgress<GeoUpdateProgress>? progress = null,
        CancellationToken ct = default);

    Task<Result> RollbackAsync(GeoAssetKind kind, CancellationToken ct = default);

    /// <summary>Routing features that may be emitted into an Xray config right now.</summary>
    GeoRuleAvailability GetRuleAvailability(GeoDataStatus status);

    /// <summary>Environment entries that must be set on the spawned Xray process.</summary>
    IReadOnlyDictionary<string, string> GetXrayProcessEnvironment(GeoDataStatus status);

    /// <summary>Diagnostic bundle for "why can't Xray find my geo data".</summary>
    Task<Result<GeoDiagnosticsReport>> ExportDiagnosticsAsync(CancellationToken ct = default);
}
```

**`RepairAsync` algorithm (deterministic, never destroys the last good copy):**

1. Re-resolve `GeoDataPaths`; if not absolute → `geodata.path_not_absolute`, stop (this is the
   direct #9765 guard).
2. If writable: for each unhealthy asset, try the **seed** copy shipped with the app (offline
   repair), validate + checksum, atomic commit.
3. Still unhealthy and `AllowNetwork`: download from the resolved source, validate, verify checksum,
   atomic commit.
4. If a download/validation fails, `RollbackAsync` restores the backup generation.
5. Re-run `InspectAsync`; report per-asset outcome.
6. If the core is running and an asset changed, mark `RestartRequired` (or call Xray's hot-reload);
   **never** stop the tunnel as part of a geo repair.

### 2.8 The launch-time contract (the actual #9765 fix for MyVpn)

```csharp
namespace MyVpn.Core.Xray;

/// <summary>Given a validated geo status, produces everything the launch path must inject.</summary>
public interface IXrayGeoEnvironment
{
    /// <summary>Real process environment entries (absolute values).</summary>
    IReadOnlyDictionary<string, string> BuildProcessEnvironment(GeoDataStatus status);

    /// <summary>Writes the root <c>"env"</c> object into the outgoing config (Xray >= 26.7.11).</summary>
    void ApplyToConfigEnvironment(Utf8JsonWriter writer, GeoDataStatus status);
}
```

Launch rules, in priority order:

1. **Both channels.** Set `XRAY_LOCATION_ASSET=<absolute asset dir>` in
   `ProcessStartInfo.Environment` **and** emit `"env": { "XRAY_LOCATION_ASSET": "<absolute asset dir>" }`
   in the generated config. The config channel is immune to `sudo env_reset`, launchd, systemd and any
   wrapper, because Xray applies it itself (`os.Setenv`) before building routing. The process channel
   covers Xray builds older than v26.7.11.
2. **`XRAY_LOCATION_CERT`** likewise whenever a cert file is managed by MyVpn (v2rayN lost this too,
   per #9764).
3. **No shell.** Privileged launch goes through `IPrivilegedProcessLauncher` with an `argv` array
   (a small privileged helper / service / `systemd-run` / polkit / `SMJobBless`-style helper), never
   a generated `bash` script and never `sudo -E`.
4. **Pre-flight assertion.** Before spawning, run `XrayAssetResolution.Resolve(...)`; if the predicted
   path does not equal `status`'s validated absolute path, refuse to launch and surface
   `geodata.path_not_absolute` / a dedicated `geodata.launch_environment_mismatch`, with both paths in
   the detail. This turns a silent runtime failure into a deterministic startup error.

```csharp
namespace MyVpn.Platform.Abstractions;

public interface IPrivilegedProcessLauncher
{
    /// <summary>Starts a process with an explicit argv array and explicit environment. No shell is involved.</summary>
    Task<Result<IPrivilegedProcess>> StartAsync(PrivilegedLaunchRequest request, CancellationToken ct = default);
}

public sealed record PrivilegedLaunchRequest(
    string ExecutablePath,
    IReadOnlyList<string> Arguments,                     // argv, not a command line
    IReadOnlyDictionary<string, string> Environment,
    string WorkingDirectory,
    bool RequireElevation);
```

### 2.9 Diagnostics mode

```csharp
namespace MyVpn.Core.Geo;

public sealed record GeoAssetDiagnostic(
    GeoAssetKind Kind,
    string AbsolutePath,
    bool Exists,
    long SizeBytes,
    string? ActualSha256,
    string? ExpectedSha256,
    GeoAssetHealth Health,
    int EntryCount,
    IReadOnlyList<string> SampleCodes,
    IReadOnlyList<string> MissingRequiredCodes,
    string? FailureDetail,
    string? ErrorCode);

public sealed record GeoDiagnosticsReport(
    string SchemaVersion,
    DateTimeOffset GeneratedAt,
    GeoDataPaths Paths,
    bool AssetDirectoryWritable,
    string XrayExecutablePath,
    string? XrayResolvedAssetDirectory,      // what Xray would actually use
    IReadOnlyList<string> CandidatePaths,    // full ordered list Xray would probe
    IReadOnlyList<GeoAssetDiagnostic> Assets,
    string? EffectiveAssetLocationSource)    // "process-env" | "config-env" | "default-executable-dir" | "fhs"
{
    public GeoAssetHealth WorstHealth { get; init; }
    public bool WouldXrayFindAssets { get; init; }   // the single most useful boolean in the report
}
```

Exposed as `myvpn geo status --json`, `myvpn geo update`, `myvpn geo repair`, and
`myvpn geo doctor` (human summary). The report must render, in plain language, the difference between
*"the file our validators approved"* and *"the path Xray will actually open"* — the exact gap that
produced #9765.

---

## 3. Risks

| # | Risk | Evidence / basis | Mitigation |
|---|---|---|---|
| R1 | **Shell injection / quoting breakage in the elevated path.** v2rayN's fix interpolates `KEY="VALUE"` into a `bash` script run under `sudo`; `AppendQuotes()` is `$"\"{value}\""` with **no escaping**, so a path containing `"`, `` ` ``, `$`, `\` or `$( )` is interpreted by the shell as root. macOS state dirs contain spaces, and unusual usernames are possible. | **[READ — `Extension.cs:74`, `CoreAdminManager.cs` diff]** | Never generate shell text; pass `argv` arrays. If a shell is unavoidable, quote with a vetted escaper and reject control characters. |
| R2 | **`sudo -E` / `env_keep` is policy-dependent.** Environments with `env_reset` + a restrictive `env_keep` (the default) strip the variable; `-E` is refused unless sudoers allows it. | **[READ — v2rayN's own analysis in #9764: "不建议仅改成 `sudo -E`，原因是 … sudo 是否保留指定环境变量还会受到本机 sudo 策略影响"]** | Dual channel: process env **and** config `env`. The config channel is policy-independent. |
| R3 | **Config `env` needs Xray ≥ v26.7.11.** Older bundles silently ignore it. v2rayN 7.23.4 shipped Xray 26.6.1. | **[READ — Xray commit `d5bc58d`, tags `v26.7.11`+; #9764 reports 26.6.1]** | Keep the process-env channel; gate the config-`env` channel on the detected Xray version and assert it in a test. |
| R4 | **Doc/code divergence on the default directory.** Docs say `./`; non-Windows code uses the executable dir, plus three FHS paths; Windows has none. | **[READ]** | Model the code (`XrayAssetResolution`), and add a contract test that pins the modelled order. Re-verify on Xray upgrades. |
| R5 | **Read-only install directory.** deb/rpm `/opt/v2rayN`, AppImage squashfs, macOS bundle, Windows `Program Files`: an in-place geo update either fails or needs elevation. | **[READ — `package-debian.sh` installs to `/opt/v2rayN`, root-owned; `package-osx.sh` copies payload into the bundle]** | Writable working copy in the per-user state dir; the install dir is a read-only seed; detect non-writable dir and say so in plain language. |
| R6 | **macOS App Translocation.** Unsigned/quarantined apps run from a random read-only path; bundle-derived absolute paths change every launch and become stale. | **[INFERRED — Apple-documented Gatekeeper behaviour; `package-osx.sh` does not codesign]** | Never derive asset paths from the bundle; only the stable state dir. **[UNVERIFIED for a specific v2rayN build.]** |
| R7 | **Windows file locking during atomic replace.** A running Xray may hold `geosite.dat` open; `MoveFileEx` fails with a sharing violation. | **[INFERRED]** | Defer the commit until the core is stopped (`install.deferred`), keep the staged file, retry; never truncate the live file. |
| R8 | **Cross-filesystem rename is not atomic.** A temp file on another volume makes `Move` a copy. | **[INFERRED — standard POSIX/NTFS semantics]** | Stage in a `.staging` directory *inside* the asset directory. |
| R9 | **Manifest is a single point of failure.** A corrupt/unreadable manifest could make every asset look invalid. | **[INFERRED]** | Manifest loss downgrades checksum verification to structural validation with a warning; the manifest is rewritten from the validated files. |
| R10 | **Valid-but-wrong content is worse than missing.** A structurally valid `.dat` lacking `ir`/`ru-blocked`/`category-ai` passes existence and format checks, and Xray reports a misleading `EOF`. | **[READ — #10153, #6218, #9318, and `geodat_loader.go` `find()` returning EOF for an absent code]** | Required-code coverage check against the codes actually referenced by the active profile; content version/date retention so an update cannot silently downgrade. |
| R11 | **Update overwrites newer user data with older bundled data.** | **[READ — #6218]** | Never overwrite a newer good generation with an older seed; compare version/size/date and keep the newer; never auto-overwrite a source that the user selected. |
| R12 | **Breaking an active connection.** A geo update that restarts the core drops the tunnel. | Design requirement | Update out-of-band; mark `RestartRequired`; apply on the next safe boundary or via hot-reload; a failed update must never terminate the running core. |
| R13 | **Supply-chain integrity.** HTTPS alone does not protect against a compromised mirror; a manifest fetched over the same channel is only weak integrity. | **[INFERRED]** | Pin expected SHA-256 in the shipped manifest/build metadata; support an offline seed; treat a checksum mismatch as "do not install", never as "retry harder". |
| R14 | **Elevated asset install widens the attack surface.** Installing into a root-owned directory requires a privileged write path. | **[INFERRED]** | Prefer a user-writable state dir so no elevation is needed for geo data; if elevation is required, use a narrow, argument-validated helper/IPC with no shell. |
| R15 | **Disk budget.** `geoip.dat` + `geosite.dat` are tens of MB; correct operation needs live + staging + backup. | **[READ — #10153 reports 17 MB + 11 MB]** | Pre-flight free-space check; single backup generation; clean staging on startup. |
| R16 | **Non-ASCII / spaces / long paths.** macOS `Application Support`, Windows user profiles, non-Latin usernames. | **[READ — #9764 explicitly warns about "Application Support" spaces]** | Always pass paths as `argv` elements and via `ProcessStartInfo.ArgumentList`; never parse them back out of a command string. |

---

## 4. Implementation plan

Phases are ordered so that the *safety-critical* work (never launch against an unvalidated asset;
never emit a broken config) lands before the convenience work.

### Phase 0 — Contract freeze (0.5 day)
- Add the value types and interfaces in §2.3–§2.9 to `MyVpn.Core.Geo` (pure, no I/O).
- Correct the `GeoAssetInfo.PathNotAbsolute` comment per §1.9.
- Write `docs/adr/ADR-00xx-geodata-asset-management.md` recording: absolute-path rule, dual
  env-injection channels, Xray ≥ v26.7.11 caveat, atomic-install/rollback, seed-vs-state-dir,
  "never emit a rule for an unusable asset".
- **Exit:** interfaces compile; `MyVpn.Core` still has zero package references.

### Phase 1 — Deterministic guards (1–2 days)
- Implement `XrayAssetResolution` (pure mirror of `common/platform/*.go`).
- Implement `IGeoAssetValidator` over the existing `GeoAssetValidator`/`ProtoReader`, plus
  `ValidateRequiredCodes`.
- Implement `GeoDataPaths.Create` + the per-OS state-directory resolver in the platform projects.
- **Exit:** unit tests in §6.1 and §6.2 green; the #9765 scenario is asserted as a *detected*
  condition with an actionable message.

### Phase 2 — Safe storage (1–2 days)
- `FileSystemGeoAssetStore`: staging, checksum-on-stream, atomic commit, backup generation,
  rollback, writability probe, free-space check.
- `JsonGeoChecksumManifestStore` with corruption tolerance.
- **Exit:** §6.3 tests green, including simulated crash between rename steps and a read-only
  directory.

### Phase 3 — Launch contract integration (1 day)
- `IXrayGeoEnvironment`; wire the Xray config builder to emit the root `env` object and the config
  gate to honour `GeoRuleAvailability`.
- Wire `IPrivilegedProcessLauncher` (argv-based, explicit environment) into the TUN elevation path.
- Add the launch pre-flight assertion (§2.8 rule 4).
- **Exit:** §6.4 integration tests green, including an "env-resetting wrapper" that reproduces the
  sudo behaviour; removing the config/env injection makes those tests fail (regression guard).

### Phase 4 — Acquisition and repair (2 days)
- `HttpGeoAssetSource` with size caps, timeouts, HTTPS-only, content-type rejection.
- `IGeoAssetSourceCatalog` with regional presets and their required codes.
- `GeoDataManager.UpdateAsync` / `RepairAsync` / `RollbackAsync` / `ExportDiagnosticsAsync`.
- **Exit:** §6.5 tests green; a truncated/HTML/checksum-mismatched download leaves the previous
  generation byte-identical.

### Phase 5 — UX and diagnostics (1–2 days)
- Plain-language message catalogue for every `GeoAssetHealth`/`ErrorCodes.GeoAsset*`.
- One-click **Repair geo data** action; `myvpn geo doctor --json`.
- Startup banner: if `WouldXrayFindAssets == false`, show the repair prompt *before* the user tries
  to connect.
- **Exit:** no user-facing string contains a raw Xray error; `myvpn geo doctor` on a deliberately
  broken install names the exact wrong path and the exact fix.

### Phase 6 — Packaging and migration (1–2 days)
- Ship the seed generation read-only with the app; never write into the install directory.
- Installer/updater rule: never overwrite a newer good generation (R11, #6218).
- Post-update migration: on first run of a new version, re-resolve paths, validate, and repair from
  seed if the previous absolute path is gone (R6, §1.8).
- **Exit:** §6.6 tests green for portable zip, `.app`, deb/rpm-style `/opt` + `/usr/share`, and a
  read-only asset directory.

**Definition of done for the whole effort:** a test can be run at any time that lays out
`bin/{geoip,geosite}.dat` + `bin/xray/xray`, launches through the real elevated path, and asserts the
child resolves the assets directory — plus a companion test that shows the check fails when the
environment/config injection is removed. With those two tests in place, #9765 cannot silently return.

---

## 5. Files / modules affected

> This report is written under the `docs/research/` boundary; nothing below was modified by this
> agent. Paths are proposals relative to the repository root.

**`MyVpn.Core` (pure — new files in the existing `Geo/` folder)**
- existing: `Geo/GeoAssetKind.cs`, `Geo/GeoAssetInfo.cs`, `Geo/GeoAssetValidator.cs`, `Geo/GeoDataConstants.cs`, `Geo/GeoDataStatus.cs`, `Geo/ProtoReader.cs` (reused; one comment corrected).
- new: `Geo/GeoDataPaths.cs`, `Geo/XrayAssetResolution.cs`, `Geo/IGeoAssetValidator.cs`, `Geo/IGeoAssetStore.cs`, `Geo/IGeoChecksumManifestStore.cs`, `Geo/IGeoAssetSource.cs`, `Geo/IGeoAssetSourceCatalog.cs`, `Geo/IGeoDataManager.cs`, `Geo/GeoUpdateModels.cs`, `Geo/GeoDiagnosticsReport.cs`, `Xray/IXrayGeoEnvironment.cs`.
- `Results/ErrorCodes.cs`: already contains the `geodata.*` family; add `geodata.launch_environment_mismatch` and `geodata.required_code_missing`.

**`MyVpn.Infrastructure` (new `Geo/` and `Xray/` folders)**
- `Geo/GeoDataManager.cs`, `Geo/FileSystemGeoAssetStore.cs`, `Geo/ProtoGeoAssetValidator.cs`, `Geo/JsonGeoChecksumManifestStore.cs`, `Geo/HttpGeoAssetSource.cs`, `Geo/GeoAssetSourceCatalog.cs`, `Geo/GeoDiagnosticsExporter.cs`, `Geo/GeoStateDirectoryResolver.cs`.
- `Xray/XrayConfigBuilder.cs` (emit `env`, gate geo rules), `Xray/XrayGeoEnvironment.cs`, `Xray/XrayProcessLauncher.cs` (absolute `XRAY_LOCATION_ASSET`, pre-flight resolution assertion).

**`MyVpn.Platform.Abstractions` / `MyVpn.Platform.{Windows,Linux,MacOS}`**
- `IPrivilegedProcessLauncher` + per-OS argv-based elevation (no shell).
- Per-OS state-directory and read-only-install detection conventions.
- Linux/macOS: `XRAY_LOCATION_ASSET` delivery through the elevation mechanism; Windows: `ProcessStartInfo.Environment` + `ArgumentList`.

**`MyVpn.Application` / `MyVpn.Service` / `MyVpn.UI` / `MyVpn.Cli`**
- Application: `InspectGeoDataQuery`, `UpdateGeoDataCommand`, `RepairGeoDataCommand`, `ExportGeoDiagnosticsQuery`; startup pre-flight gate.
- Service: privileged asset-install endpoint (only if the state dir is not user-writable).
- UI: geo-data panel (per-asset health, version/date/source), one-click repair, plain-language errors.
- Cli: `geo status|update|repair|doctor`.

**Tests**
- `tests/MyVpn.Core.Tests/Geo/*`, `tests/MyVpn.Infrastructure.Tests/Geo/*`, `tests/MyVpn.Integration.Tests/Geo/*`, `tests/MyVpn.Platform.Tests/*`, plus `tests/**/Fixtures/Geo/*` (tiny committed `.dat` slices).

**Docs / packaging**
- `docs/adr/ADR-00xx-geodata-asset-management.md`.
- Packaging scripts/build: place the seed generation read-only; write the working copy to the state dir; never overwrite a newer good generation.

---

## 6. Tests

All tests are deterministic: no network, no real Xray binary, no reliance on wall-clock time
(`TimeProvider`), pinned SHA-256 vectors, and tiny committed fixtures. Fixtures are produced once by
slicing a real `.dat` at fixed offsets and are checked into the repo.

### 6.1 Validation — `MyVpn.Core.Tests/Geo/GeoAssetValidatorTests.cs`
| Test | Assertion |
|---|---|
| `Valid_fixture_passes` | `IsValid`, `EntryCount > 0`, sample codes non-empty. |
| `Zero_byte_file_is_Empty` | failure code `empty`; maps to `geodata.empty`. |
| `One_byte_file_is_Corrupt` | `too_small`/`truncated_tag`. |
| `Truncated_at_every_4k_boundary_fails` | for each cut point, `IsValid == false` and the failure code is a truncation code (guards "interrupted download"). |
| `Html_error_page_is_Corrupt` | realistic captive-portal HTML body → `truncated_tag`/`malformed_entry`; never `Valid`. |
| `Json_payload_is_Corrupt` | `{"error":"not found"}` → invalid. |
| `Gzip_payload_is_Corrupt` | gzip magic bytes → invalid. |
| `Random_bytes_never_crash` | 1 000 seeded random buffers → returns a result, never throws. |
| `Entry_without_code_is_rejected` | `entry_without_code`. |
| `Huge_declared_length_is_rejected` | `truncated_entry`, no allocation blow-up. |
| `Required_codes_present_succeeds` | `ValidateRequiredCodes(["CN","PRIVATE"])` complete. |
| `Required_code_absent_reports_missing` | missing `IR` → `IsComplete == false`, `MissingCodes == ["IR"]` — the #10153 case. |

### 6.2 Path resolution — `MyVpn.Core.Tests/Geo/XrayAssetResolutionTests.cs`
| Test | Assertion |
|---|---|
| `Env_value_wins` | env dir + existing file → `ResolvedFrom == "env"`. |
| `No_env_non_windows_uses_executable_dir` | exe `bin/xray/xray`, file in `bin/` → resolved candidate is `<exe dir>/geosite.dat`, `ResolvedFrom == "executable-dir"`, `Exists == false`. **This is #9765 in one test.** |
| `No_env_linux_prefers_fhs_when_present` | `/usr/share/xray/geosite.dat` exists → that path, `ResolvedFrom == "fhs"`. |
| `No_env_windows_has_no_fhs_fallback` | Windows → only env/exe dir; `/usr/share/xray` never probed. |
| `Candidate_order_is_pinned` | exact ordered list matches the modelled `common/platform/others.go` order. |
| `Relative_env_value_is_flagged` | `XRAY_LOCATION_ASSET=bin` → `GeoDataPaths.Create` fails with `geodata.path_not_absolute`. |
| `Path_with_spaces_and_non_ascii_round_trips` | `~/Library/Application Support/MyVpn/…`, `C:\Users\Иван\…`, `"/tmp/a b/c$d\"e` — never shell-interpreted in the resolution model. |

### 6.3 Storage — `MyVpn.Infrastructure.Tests/Geo/FileSystemGeoAssetStoreTests.cs`
| Test | Assertion |
|---|---|
| `Commit_is_atomic_under_simulated_crash` | crash injected between the two renames → live file is either old or new, never partial; rollback restores a consistent generation. |
| `Failed_validation_never_touches_live_file` | live SHA-256 unchanged after a rejected install. |
| `Checksum_mismatch_rejected` | `geodata.checksum_mismatch`; staged file removed. |
| `Rollback_restores_previous_bytes` | byte-for-byte identical to the backup. |
| `Read_only_directory_reports_not_writable` | `geodata.directory_not_writable`; no exception escapes. |
| `Missing_directory_is_created` | first-run bootstrap succeeds. |
| `Manifest_corruption_degrades_to_structural_validation` | garbage manifest → assets still validated, warning raised, manifest rewritten. |
| `Same_filesystem_staging` | staged path is inside the asset directory (asserted, not assumed). |
| `Insufficient_disk_space_is_reported` | injected free-space probe → `geodata.install_failed`, live file untouched. |
| `Deferred_commit_when_file_locked` | simulated sharing violation → `install.deferred == true`, staged file retained. |
| `Geoip_and_geosite_update_independently` | geosite succeeds + geoip fails → geosite new, geoip old, both `IsUsable`. |

### 6.4 Launch contract (the regression guard for #9765) — `MyVpn.Integration.Tests/Geo/`
| Test | Assertion |
|---|---|
| `Child_receives_absolute_XRAY_LOCATION_ASSET` | using a fake "xray" that dumps its environment, the child sees `XRAY_LOCATION_ASSET == <abs asset dir>`. |
| `Env_resetting_wrapper_does_not_lose_the_value` | the launcher is wrapped in a helper that reproduces `sudo env_reset` (`env -i`); the child **still** resolves the assets, proving the config-`env` channel works. |
| `Config_env_object_is_emitted` | the generated config root contains `env.XRAY_LOCATION_ASSET` equal to the validated absolute path. |
| `Preflight_mismatch_blocks_launch` | force a mismatch between the validated path and the predicted Xray path → launch refused with `geodata.launch_environment_mismatch` and both paths in the detail. |
| `No_shell_metacharacter_is_interpreted` | asset dir containing `$`, backtick, `"`, `;`, newline → the child observes the literal path; no command executes (guards R1). |
| `Xray_older_than_26_7_11_still_works_via_process_env` | version-gated config-`env` omitted; process env alone suffices. |
| `Config_never_references_an_unavailable_asset` | with geosite corrupt, the emitted config contains no `geosite:` token; a fallback ruleset is present; the core starts. |
| `Issue9765_layout_resolves_correctly` | exact layout `bin/{geoip,geosite}.dat` + `bin/xray/xray`, elevation path enabled → resolves to `bin`, not `bin/xray`; the companion "remove the injection" variant fails, proving the test detects regressions. |

### 6.5 Acquisition and repair — `MyVpn.Infrastructure.Tests/Geo/`
| Test | Assertion |
|---|---|
| `Valid_download_installs` | checksum recorded, manifest updated, live file new. |
| `Http_404_fails_without_changing_anything` | live SHA-256 unchanged. |
| `Truncated_response_rejected` | `Content-Length` larger than the body → validation failure, no install. |
| `Captive_portal_html_rejected` | `text/html` body rejected before validation. |
| `Oversized_response_aborted` | size ceiling enforced; connection aborted early. |
| `Timeout_is_retried_then_reported` | bounded retries, then `geodata.download_failed`. |
| `Checksum_mismatch_rolls_back` | previous generation restored. |
| `Repair_prefers_seed_over_network` | offline repair succeeds with the network stub throwing. |
| `Repair_never_deletes_the_last_good_copy` | seed corrupt and network down → old generation still present and usable. |
| `Concurrent_updates_serialise` | two `UpdateAsync` calls do not interleave commits; one becomes a no-op. |
| `Regional_preset_required_codes_enforced` | Iran preset without `IR` → update rejected as incomplete, not silently "successful" (#10153). |
| `Older_bundled_generation_does_not_overwrite_newer` | new live + old seed → no overwrite (#6218). |

### 6.6 Layouts and migration — `MyVpn.Integration.Tests/Geo/` + `MyVpn.Platform.Tests/`
| Test | Assertion |
|---|---|
| `Portable_zip_layout` | assets beside the binary directory; writable; resolution absolute. |
| `Macos_app_bundle_layout` | `MyVpn.app/Contents/MacOS/bin/...` plus the `NotStoreConfigHere.txt` analogue → state dir is under Application Support, outside the bundle; `AppContext.BaseDirectory` never used for assets. |
| `Macos_translocated_bundle_path_is_irrelevant` | simulate a changing random bundle path between two launches → stored asset paths identical; no stale path. |
| `Read_only_appimage_style_asset_dir` | `chmod 0555` asset dir → update returns `geodata.directory_not_writable` with a plain-language message; the app keeps running on the seed generation. |
| `Deb_rpm_opt_layout` | `/opt/myvpn` (root-owned) seed + user state dir → updates go to the state dir; no elevation required. |
| `Post_update_path_migration` | generation installed under dir A; app version bumps and the state dir moves to B → assets migrated or re-seeded, absolute path updated, no reference to A remains in settings, env, or the generated config. |
| `Stale_absolute_path_from_previous_install_is_repaired` | settings point at a deleted directory → detected as `Missing`, one-click repair restores service. |
| `Plain_language_messages` | every `GeoAssetHealth` maps to a non-technical message key; the raw Xray string appears only in `FailureDetail`. |

---

## Appendix A — Evidence index

| Ref | URL / locator | Used for |
|---|---|---|
| Issue #9765 | https://github.com/2dust/v2rayN/issues/9765 | maintainer write-up, TUN switch, error samples, workaround |
| #9765 comments | `api.github.com/repos/2dust/v2rayN/issues/9765/comments` | "没有设置环境变量" / "确定是环境变量未设置导致的，已经修复" |
| Issue #9764 | https://github.com/2dust/v2rayN/issues/9764 | independent root-cause analysis; macOS 7.23.4 + Xray 26.6.1; Debian 12 |
| Issue #9715 | https://github.com/2dust/v2rayN/issues/9715 | exact Linux error log; packaging-script comment |
| Issue #9718 | https://github.com/2dust/v2rayN/issues/9718 | exact macOS error log; "fine in 7.22.x, broke after update" |
| Issue #10153 | https://github.com/2dust/v2rayN/issues/10153 | valid-but-stale geodata → `check code IR … EOF` |
| Issue #6218 | https://github.com/2dust/v2rayN/issues/6218 | updater overwrites regional geodata with bundled defaults |
| Issue #9318 | https://github.com/2dust/v2rayN/issues/9318 | missing code → `code not found in geosite.dat` |
| Fix commit | `2dust/v2rayN@223642dd67e976dcea88eb7a268ffd3d15d875e6` | env passthrough via `sudo … env`; message cites #9765 |
| v2rayN source | `CoreAdminManager.cs`, `CoreManager.cs`, `CoreInfoManager.cs`, `UpdateService.cs`, `Utils.cs`, `Extension.cs` | elevation path, env dict, non-atomic download, naive quoting |
| v2rayN packaging | `package-osx.sh`, `package-debian.sh`, `package-rhel*.sh`, `.github/workflows/*` | asset placement, `/opt/v2rayN`, no codesign, no AppImage/MSI |
| Xray source | `common/platform/{platform,others,windows}.go`, `common/platform/filesystem/file.go`, `common/geodata/geodat_loader.go`, `common/geodata/geodat.proto`, `common/geodata/rule_parser.go`, `infra/conf/xray.go`, `infra/conf/geodata.go` | lookup order, format, failure modes, `env` ordering, Xray-side updater |
| Xray releases | tags `v26.6.1`, `v26.7.11`, `v26.9.9`; commits `d5bc58d`, `3bc24a3` | `env` ≥ v26.7.11; geodata auto-update ≥ v26.4.25 |
| Xray docs | https://xtls.github.io/en/config/env.html | `XRAY_LOCATION_ASSET` is a directory; documented fallback order; `env` item scope |
| Apple / AppImage docs | https://developer.apple.com/documentation/ (App Translocation); https://docs.appimage.org/reference/architecture.html | general packaging risks R5/R6 |

## Appendix B — UNVERIFIED items (explicit)

1. Whether the post-7.24.2 TUN problem reported by @crazyjtt03 in #9765 is the same root cause.
2. Whether @imanbabaei's "still exists in 7.23.4" observation was made on a build that predates the
   7.24.0 fix (it almost certainly does — 7.23.4 has no env passthrough — but this is not stated).
3. The relationship of the 2026-08-29 TUN symptom (@BBplux) to the geodata defect; no asset error
   appears in that log.
4. The exact first affected v2rayN build. Reports exist for 7.23.3 (#9715, #9718) while the
   maintainer's note is framed as "v7.23.4+".
5. macOS App Translocation for the specific unsigned v2rayN `.dmg`; inferred from Apple's documented
   Gatekeeper behaviour plus the absence of codesigning in the repo, not observed in the issues.
6. AppImage and Windows-installer consequences: **not produced by v2rayN** (no such packaging in the
   repository); those sub-sections are general-class analysis for MyVpn, not v2rayN reports.
7. Whether any v2rayN release bundles an Xray build ≥ v26.7.11 (needed for the config-`env` channel).
   Xray 26.6.1 is confirmed for the 7.23.4 report; later bundles were not inspected.
