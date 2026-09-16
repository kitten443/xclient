# 01 — v2rayN Architecture Study (reference research for MyVpn)

| | |
|---|---|
| **Deliverable** | `docs/research/01-v2rayn-architecture.md` |
| **Subject** | [2dust/v2rayN](https://github.com/2dust/v2rayN) — studied as architectural prior art, **not** as a source of copyable code |
| **Studied revision** | commit `cef40d38eec545dbe5a736602549d2b72c4f64bc` (branch `master`), obtained with `git clone --depth 1` |
| **Clone location** | `/tmp/v2rayN` (never inside the workspace, per task boundaries) |
| **MyVpn constraints assumed** | .NET 8, Avalonia UI, Clean Architecture, native Xray TUN inbound, **Xray-core only** (sing-box forbidden) |
| **Path convention** | Unless stated otherwise, `ServiceLib/...`, `v2rayN.Desktop/...`, `v2rayN/...` are relative to the **solution directory** `/tmp/v2rayN/v2rayN`. On GitHub the same files are at `https://github.com/2dust/v2rayN/blob/master/v2rayN/<path>` (the repository root contains a single `v2rayN/` directory that holds the solution). |
| **Verification discipline** | Every factual claim cites a file path plus line range or a URL. Anything I could not verify is explicitly marked **UNVERIFIED**. No third-party source is pasted; only behaviour is described. |
| **Sibling research in this directory** | `02-issue-9765-geodata.md`, `03-xray-tun-inbound.md`, `04-nat-udp-matrix.md`, `05-happ-subscription-headers.md`, `06-windows-networking.md`, `07-linux-networking.md`, `08-macos-networking.md` were produced by other agents in parallel. I did **not** read them, so this report is deliberately self-contained; where our scopes overlap (geo failure modes, Xray TUN schema, per-OS networking) the deeper treatment is in those files and my §2/§5 are phrased to be consistent with the existing `src/MyVpn.*` scaffold rather than to supersede them. |

Reproduce the study:

```bash
rm -rf /tmp/v2rayN && git clone --depth 1 https://github.com/2dust/v2rayN /tmp/v2rayN
cd /tmp/v2rayN && git log -1 --format='%H %ad %s'
find . -name '*.csproj' | sort
```

> Note: this environment has **no `dotnet` SDK**, so nothing below was compiled or executed; all findings are static-reading findings. Claims that require runtime confirmation are marked **UNVERIFIED (runtime)**.

---

## 1. Findings

### 1.1 Repository shape at a glance

Real projects found by `find . -name '*.csproj'` (8 projects + 1 git submodule):

| Project (path under `/tmp/v2rayN/v2rayN/`) | Type / TFM | Responsibility (verified by reading its `.csproj` and code) |
|---|---|---|
| `ServiceLib/ServiceLib.csproj` | Library, `net10.0` (inherited) | The whole non-UI brain: config model + persistence, Xray/sing-box config generation, subscription parsing, core process management, geo updates, **and all ViewModels shared by both GUIs** |
| `v2rayN/v2rayN.csproj` | `WinExe`, `net10.0-windows10.0.19041.0`, `UseWPF` | Windows-only WPF shell (MaterialDesignThemes, `H.NotifyIcon.Wpf`) |
| `v2rayN.Desktop/v2rayN.Desktop.csproj` | `WinExe`, `net10.0` (inherited), `AssemblyName=v2rayN` | Cross-platform Avalonia shell (Semi.Avalonia theme, DialogHost, AvaloniaEdit, DataGrid) |
| `AmazTool/AmazTool.csproj` | `Exe` | Self-update / restart helper (`rebootas`, unzip update archive over install dir) |
| `ServiceLib.Tests/ServiceLib.Tests.csproj` | `Exe`, TUnit | Unit tests (config generation, URI formats, download headers) |
| `ServiceLib.UdpTest/ServiceLib.UdpTest.csproj` | Library | SOCKS5 UDP test probes (NTP/DNS/STUN/MCBE) |
| `GlobalHotKeys` (submodule → `https://github.com/2dust/GlobalHotKeys`, pinned `162d401dfe0140b41d1fa349b9aadb4060e739b1`) | Library | Windows global hotkeys. **Not initialized** by a plain `--depth 1` clone (`git submodule status` → `-162d401...`) |
| `AmazTool` + `ServiceLib.UdpTest` are referenced from the solution; submodule URL is in `/tmp/v2rayN/.gitmodules` | | |

Evidence: `/tmp/v2rayN/v2rayN/v2rayN.sln`, `/tmp/v2rayN/v2rayN/v2rayN.slnx`, `/tmp/v2rayN/v2rayN/Directory.Build.props`, `/tmp/v2rayN/.gitmodules`.

Key structural facts:

* Target framework is **`net10.0`** for everything, Windows-specific bits in a WPF-only `net10.0-windows10.0.19041.0` project (`Directory.Build.props:9-10`, `v2rayN/v2rayN.csproj:5`). MyVpn deliberately uses plain `net8.0` for all projects (see `Directory.Build.props` in this workspace, ADR-0004 reference) — that is a legitimate divergence, not an oversight.
* Version `7.25.1` (`Directory.Build.props:4`), `PackageLicenseExpression` = `GPL-3.0` (`Directory.Build.props:14`). Nullable reference types are only `annotations`, not `enable` (`Directory.Build.props:11`) — i.e. nullable warnings are produced but flow analysis is not enforced as errors, which is consistent with the `[Obsolete]` fields and `string?`/`string` mixes in `ProfileItem`.
* Central package management (`Directory.Packages.props`) — Avalonia 12.1.2, ReactiveUI 24.2.0 + source generators, NLog, `sqlite-net-e`, Downloader, CliWrap, YamlDotNet, IPNetwork2, QRCoder, ZXing, TUnit.
* 282 `.cs` files, ~51 300 lines; largest files: `ServiceLib/Resx/ResUI.Designer.cs` (5403), `ServiceLib/Handler/ConfigHandler.cs` (**3003**), `ServiceLib/Common/Utils.cs` (1411), `ServiceLib/ViewModels/ProfilesViewModel.cs` (904), `ServiceLib/Services/CoreConfig/V2ray/V2rayOutboundService.cs` (881).

### 1.2 Layering as it actually is

There is no clean-architecture layering. `ServiceLib` is a single assembly that mixes domain data, persistence, process control, platform interop **and** presentation logic (ViewModels, `ReactiveUI`). The two shells add only Views + a few shell-specific services:

```
v2rayN (WPF)      v2rayN.Desktop (Avalonia)
   Views/*.xaml       Views/*.axaml + ViewModels/ThemeSettingViewModel.cs
        \                    /
         \                  /
          ServiceLib  (Models, Configs, Handlers, Services, Managers, ViewModels, Resx)
             |
        SQLite (guiNDB.db) + JSON (guiNConfig.json) + guiLogs/ + bin/ + binConfigs/
```

The only real "ports" are implicit: `AppManager.Instance` (global singleton, `ServiceLib/Manager/AppManager.cs:3-11`), `Config` (mutable POCO tree), `CoreConfigContext` (a genuine immutable-ish snapshot record — the one place where the codebase has moved toward a testable design).

### 1.3 Xray process lifecycle

**Binary discovery — `CoreInfoManager`** (`ServiceLib/Manager/CoreInfoManager.cs`)

* A hard-coded table of `CoreInfo` records (`:104-292`): per-core `CoreExes` (candidate file names), `Arguments` format string, GitHub release URLs/`ReleaseApiUrl`, per-OS download URL templates, `Match`, `VersionArg`, and an `Environment` dictionary.
* Xray entry (`:149-171`):
  * `CoreExes = ["xray"]` (`:152`)
  * `Arguments = "run -c {0}"` (`:153`)
  * `Environment`: `XRAY_LOCATION_ASSET` and `XRAY_LOCATION_CERT` → `Utils.GetBinPath("")` (`:166-170`, constants at `ServiceLib/Global.cs:91-93`)
* Resolution is a "first file that exists wins" loop over `CoreExes` with `.exe` appended on Windows (`GetCoreExecFile`, `:32-51`; `Utils.GetExeName`, `ServiceLib/Common/Utils.cs:1272-1287`). Failure returns `ResUI.NotFoundCore` with a hint pointing at `bin/<coretype>/<last exe name>` and the release URL (`:45-50`). There is **no version sniffing, no checksum, no capability probe** for Xray at this stage.
* Candidate binaries live in `StartupPath()/bin/<coretype lowercase>/` (`Utils.GetBinPath`, `Utils.cs:1175-1200`); configs in `StartupPath()/binConfigs/` (`Utils.cs:1238-1254`); the app's "StartupPath" is the executable directory, or `%LOCALAPPDATA%/v2rayN` when the app dir is not writable (`Utils.cs:1118-1126`, chosen at `AppManager.cs:65-68` via the private env var `V2RAYN_LOCAL_APPLICATION_DATA_V2`, `Global.cs:90`).
* On non-Windows, `CoreManager.Init` best-effort `chmod +x`es every known core binary (`CoreManager.cs:37-60`).

**Launch — `CoreManager` + `ProcessService`**

* `CoreManager.LoadCore` (`CoreManager.cs:65-104`): generate config → `CoreStop()` → (Windows + TUN) `WindowsUtils.RemoveTunDevice()` → `CoreStart` → `WaitForProxyPort(preContext)` → `CoreStartPreService` → record `AppManager.Instance.RunningCoreType`.
* `RunProcessNormal` (`CoreManager.cs:334-363`) builds a `ProcessService` with:
  * `arguments: string.Format(coreInfo.Arguments, configPath)` where `configPath` is `binConfigs/config.json` (relative, working dir is `binConfigs/`),
  * `workingDirectory: Utils.GetBinConfigPath()`,
  * environment variables from `CoreInfo.Environment` with `{0}` formatted to the config path,
  * redirected stdout/stderr only when `displayLog` is true.
* `ProcessService` (`ServiceLib/Services/ProcessService.cs`): `UseShellExecute=false`, `CreateNoWindow=true`, UTF-8 output encoding, `BeginOutputReadLine`/`BeginErrorReadLine`, one handler for both streams that forwards each line to the UI via `_updateFunc` (`:119-143`). Started with a 100 ms delay and then `HasExited` check to detect immediate failure (`CoreManager.cs:352-359`), which throws `ResUI.FailedToRunCore`.
* **Windows lifetime guard**: the child is assigned to a Job Object with `LimitFlags = 0x2000` (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) so Xray dies with the GUI (`ServiceLib/Services/WindowsJobService.cs:15-18`, `CoreManager.cs:365-376`). No equivalent guard on Linux/macOS — an orphaned root Xray is possible if the GUI is SIGKILLed (mitigated only by the sudo kill script, see below).
* stdout/stderr are **not parsed** for state. There is no readiness handshake except the optional SOCKS5 handshake probe `WaitForProxyPort` (5 s timeout, `CoreManager.cs:219-286`), which is only used for the "pre-service" (pre-socks) case, not for the main core.
* `CoreStop` (`CoreManager.cs:147-175`) kills the sudo-launched process first if needed, then `StopAsync` (cancel async reads → `Kill(true)` on non-Windows → `Kill()`), `Dispose`, and nulls the fields. `ProcessService.StopAsync:73-117` and `Dispose:145-179` swallow most exceptions.

**Restart behaviour — there is none.**

* Exhaustive grep for `HasExited|RestartCore|ReStart|coreRestart` outside `ProcessService.cs` returns only three `HasExited` checks used for *initial start* validation (`CoreManager.cs:196`, `:356`, `CoreAdminManager.cs:63`). The `Exited` event handler in `ProcessService.RegisterEventHandlers:132-142` **only unsubscribes handlers**; it does not notify, not restart, not surface an error.
* Consequence: if Xray crashes, the GUI keeps showing the old server and the only signal is the last log line in the message panel. `ErrorCodes.XrayStoppedUnexpectedly` already exists in MyVpn's Core (`src/MyVpn.Core/Results/ErrorCodes.cs:25`) precisely because this is a gap worth closing.

**Privileges — Linux/macOS TUN via `sudo` + password on stdin**

* `CoreManager.ShouldRunAsSudo` (`CoreManager.cs:298-303`): elevate only when a TUN launch is requested, core is Xray/sing-box/mihomo, and the OS is not Windows.
* `CoreAdminManager.RunProcessAsLinuxSudo` (`ServiceLib/Manager/CoreAdminManager.cs:32-70`) **writes a shell script** `run_as_sudo.sh` into `binConfigs/` whose body is `exec sudo -S -- env XRAY_LOCATION_ASSET='...' '.../xray' run -c '.../config.json'`, then starts it and writes the sudo password to the script's stdin (`ProcessService.StartAsync(pwd)`, `ProcessService.cs:56-71`).
* Shutdown uses a second embedded script (`Sample/kill_as_sudo_linux_sh`, `Sample/kill_as_sudo_osx_sh`) executed as `sudo -S kill_as_sudo.sh <pid>` (`CoreAdminManager.cs:72-103`), with the password piped again, then a hard-coded `Task.Delay(1000)`.
* The password is held in the process-wide mutable `AppManager.Instance.LinuxSudoPwd` (`AppManager.cs:33`) and is collected by `v2rayN.Desktop/Views/SudoPasswordInputView.axaml.cs` (`SavePasswordAsync`, verified password by running a sudo probe). This is a design MyVpn should not reproduce (see §1.10 and §3.2).
* Windows elevation is a process-level restart with `Verb="runas"` and a `rebootas` argument (`ServiceLib/Common/ProcUtils.cs:47-64`, `Global.cs:88`).

**Working directory / asset resolution details worth keeping**

* Config is written to `binConfigs/config.json` (`Global.cs:13`, `CoreManager.cs:74`) and the core is started with `-c binConfigs/config.json` relative to `binConfigs/` as CWD (`CoreManager.cs:344-345`) — i.e. **CWD ≠ asset dir**. Asset resolution is therefore delegated to `XRAY_LOCATION_ASSET=bin/` (verified against Xray docs, §1.4).
* A separate pre-service config `binConfigs/configPre.json` (`Global.cs:14`) is used for proxy-chaining / TUN pre-socks (`CoreManager.cs:194-212`).
* Speed-test configs are per-run files `binConfigs/configTest<guid>.json` (`Global.cs:15`, `CoreManager.cs:106-145`), cleaned up hourly by age (`TaskManager.cs:58-65` deletes files older than 1 h matching `Test`).

### 1.4 Geo data (geoip / geosite) handling

* Expected location: **`bin/` next to the core binaries** — `Utils.GetBinPath("geoip.dat")` (`ServiceLib/Services/UpdateService.cs:370-390`, `GetGeoFilesRequest`). Xray is told the same directory via `XRAY_LOCATION_ASSET` (`CoreInfoManager.cs:168`). The packaged app additionally normalises a `bin/xray/*.dat` layout up into `bin/` (`package-debian.sh`, `unify_geo_layout`, verified by reading the script).
* Default source: `Global.GeoUrl = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/{0}.dat"` (`Global.cs:8`), overridable per install through `ConstItem.GeoSourceUrl`, with two alternate regional sources in `Global.GeoFilesSources` (`Global.cs:179-184`).
* Update: `UpdateService.UpdateGeoFileAll` (`UpdateService.cs:140-150`) builds a request list (geo .dat + "other" geo files + sing-box `.srs` rule sets), **reverses** the list (comment: small files first), and downloads them with `DownloadSmallFilesAsync`.
* Extra files when the default (China-mainland) source is used (`GetOtherFilesRequest`, `:392-414`): `geoip-only-cn-private.dat`, `Country.mmdb`, `geoip.metadb` from `Loyalsoldier/geoip` and `MetaCubeX/meta-rules-dat` (`Global.cs:662-667`).
* Download mechanics (`DownloadGeoFiles`, `:534-590`): every file is first written to a temp path from `Utils.GetTempPath`, and **all files are copied over the live paths only when the batch reports success**; failures are reported through `args.Msg`. There is **no checksum, no content-type check, no proto validation, and no atomic per-file rename** — a captive portal HTML page or a truncated `.dat` will be installed as-is if the batch reports success (see §3.2, and note that MyVpn's `GeoAssetValidator` in `src/MyVpn.Core/Geo/GeoAssetValidator.cs` already exists to close exactly this gap).
* Scheduling: `TaskManager.UpdateTaskRunGeo` (`TaskManager.cs:124-135`) runs on a 1-minute tick and triggers when `hours % GuiItem.AutoUpdateInterval == 0` with `AutoUpdateInterval > 0` (hours); `GuiItem.AutoUpdateInterval` at `Models/Configs/ConfigItems.cs:73`.
* Path/asset failure modes observed in code (not runtime-verified) — the same failure class is analysed in depth by a sibling agent in `docs/research/02-issue-9765-geodata.md`:
  * If `bin/*.dat` is missing, Xray fails to load `geoip:`/`geosite:` rules and refuses to start; v2rayN surfaces only Xray's stdout text in the message panel — no dedicated repair UI. **UNVERIFIED (runtime)**: exact Xray error text.
  * Geo download is attempted through the local SOCKS proxy first when "update via proxy" is on (`blProxy`), falling back to direct (`SubscriptionHandler.DownloadSubscriptionContent:102-113` shows the same pattern for subscriptions; geo uses `DownloadService.DownloadSmallFilesAsync(..., blProxy, ...)` at `:589`) — a proxy that is up but broken yields HTML/errors that are then installed unvalidated.

### 1.5 Config generation (Xray)

* Entry point: `CoreConfigHandler.GenerateClientConfig` (`ServiceLib/Handler/CoreConfigHandler.cs:10-42`) dispatches on `node.ConfigType == Custom` (mihomo/custom file copy) → `sing_box` → **else Xray** (`CoreConfigV2rayService`), then `File.WriteAllTextAsync(fileName, result.Data.ToString())`.
* Input is an immutable-ish snapshot: `CoreConfigContext` (`ServiceLib/Models/CoreConfigs/CoreConfigContext.cs:3-34`: `Node`, `RunCoreType`, `RoutingItem`, `RawDnsItem`, `SimpleDnsItem`, `AllProxiesMap`, `AppConfig`, `FullConfigTemplate`, `IsTunEnabled`, `IsWindows`, `IsMacOS`, `HasGlobalIPv6Address`, …). Built by `CoreConfigContextBuilder.Build` (`ServiceLib/Handler/Builder/CoreConfigContextBuilder.cs:34-…`) together with `NodeValidator` warnings/errors.
* Generation is template-first: the base config is **an embedded JSON sample** `ServiceLib/Sample/SampleClientConfig`, deserialized into `V2rayConfig` (`ServiceLib/Models/CoreConfigs/V2rayConfig.cs`, 530 lines), then mutated by partial-class services: `GenLog`, `GenInbounds`, `GenOutbounds`, `GenRouting`, `GenDns`, `GenStatistic` (`CoreConfigV2rayService.cs:47-72`). Same pattern for TUN inbound (`Sample/SampleTunInbound`) and routing (`Sample/SampleTunRules`).
* **TUN inbound** (`ServiceLib/Services/CoreConfig/V2ray/V2rayInboundService.cs:56-135`): inbound `protocol: "tun"`, name `xray_tun` (or `utun<random>` on macOS), `MTU` from settings (default `Global.TunMtus.First()` = 1280), `gateway` = one IPv4 (+ optional IPv6) prefix from `Global.TunIPv4Address`/`TunIPv6Address` lists, `autoSystemRoutingTable` = `["0.0.0.0/0"]` or `["0.0.0.0/0","::/0"]` depending on `HasGlobalIPv6Address`, `autoOutboundsInterface` from `CoreBasicItem.BindInterface`, `sniffing.routeOnly = true`, and `RouteExcludeAddress` handled by CIDR subtraction with IPNetwork2 then `Supernet()` compression (`:93-132`). Sample template: `ServiceLib/Sample/SampleTunInbound`.
  * ⚠ **Case discrepancy found**: the sample uses `"MTU"` and `settings.MTU` (`Sample/SampleTunInbound`), while the official Xray documentation specifies a lowercase `mtu` key (https://xtls.github.io/en/config/inbounds/tun.html). It works only because Go's `encoding/json` matches field names case-insensitively. MyVpn should emit the documented lowercase keys and treat casing as part of the schema contract.
  * ⚠ The docs also expose fields v2rayN does not use here: `desc` (Windows adapter description, default `Wintun`), and they document that on **Android/iOS (and optionally Linux)** the TUN FD is passed in via the `XRAY_TUN_FD` environment variable instead of Xray creating the device — relevant to MyVpn's privilege design (§2.6).
* **DNS** (`V2rayDnsService.cs`, 555 lines) and **routing** (`V2rayRoutingService.cs`) translate `geosite:`/`geoip:` prefixes into Xray routing/DNS rule fields; the sing-box path additionally rewrites them to `.srs` rule-sets (`SingboxRoutingService.cs:519-570`).
* **Statistics / control plane**: Xray is configured with `stats: {}`, `policy.system.statsOutbound{Uplink,Downlink}` and a `metrics` listener on `127.0.0.1:<StatePort>` (`V2rayStatisticService.cs`); the GUI polls **`http://127.0.0.1:<port>/debug/vars`** once per second and parses outbound counters from JSON (`ServiceLib/Services/Statistics/StatisticsXrayService.cs`, `Url` property + `Run`/`ParseOutput`). This is the plaintext Xray metrics endpoint, not the gRPC stats API. For sing-box/mihomo the same UI data comes from the Clash API (`ClashApiManager.cs`).
* Note on the config being valid JSON: v2rayN writes standard JSON (`JsonUtils.Serialize`), which means MyVpn can set `XRAY_JSON_STRICT=true` on the child process — documented as making Xray use the strict RFC 8259 parser (https://xtls.github.io/en/config/env.html).
* **Xray's own validation mode is available and unused**: `xray run -c <file> -test` loads and builds the config without starting the server ("The `-test` flag tells Xray to test config files only, without launching the server"; on failure it prints `Failed to start:` and exits **23**, deliberately, "to prevent systemd from restarting" — https://github.com/XTLS/Xray-core/blob/main/main/run.go). v2rayN never calls it; a broken config therefore only surfaces as a failed launch. This is the single highest-value integration improvement available to MyVpn (§2.4).

### 1.6 Subscription import / update

Entry points and scheduling:

* UI/command handlers call `SubscriptionHandler.UpdateProcess(config, subId, blProxy, updateFunc)` (`ServiceLib/Handler/SubscriptionHandler.cs:5-58`), which iterates enabled `SubItem`s and counts successes.
* Automatic updates: `TaskManager.ScheduledTasks` ticks every 60 s; `UpdateTaskRunSubscription` (`TaskManager.cs:93-122`) selects `SubItem`s where `AutoUpdateInterval > 0` and `now - UpdateTime >= AutoUpdateInterval * 60`, then per item calls `UpdateProcess`, sets `item.UpdateTime = now`, re-saves the item, and sleeps 1 s. Config is additionally flushed every 20 min, logs/temp pruned and geo updated hourly (`TaskManager.cs:42-88`).
* Metadata stored per subscription — `ServiceLib/Models/Entities/SubItem.cs`: `Id`, `Remarks`, `Url`, `MoreUrl`, `Enabled`, `UserAgent`, `RequestHeaders` (JSON string), `Sort`, `Filter` (regex on remark), `AutoUpdateInterval` (minutes), `UpdateTime` (unix seconds), `ConvertTarget`, `PrevProfile`/`NextProfile` (proxy-chaining), `PreSocksPort`, `Memo`, `CustomCoreType`. Persisted in SQLite `guiNDB.db` (`ServiceLib/Helper/SqliteHelper.cs:12`), table created at startup (`AppManager.cs:85-94`).

Fetching:

* URL validation: must start with `http://` or `https://` (`SubscriptionHandler.IsValidSubscription:75-78`); punycode applied via `Utils.GetPunycode` (`:132`); `http://` outside private networks produces the `InsecureUrlProtocol` notice but is **not blocked** (`ConfigHandler.AddSubItem`, commented-out `return -1`).
* Custom request headers: `HttpRequestHeadersHelper.TryParse` validates a JSON object of header name→string, rejecting control characters and non-string values (`ServiceLib/Helper/HttpRequestHeadersHelper.cs:5-58`); invalid headers abort that subscription with `FormatException(ResUI.SubRequestHeadersInvalid)` (`SubscriptionHandler.cs:85-88`).
* Download: `DownloadService.TryDownloadString(url, blProxy, userAgent)` tries `HttpClient` first, then the third-party `Downloader` library, each with a 15 s timeout and 2–5 s connect timeout (`DownloadService.cs:187-315`). Proxy is the local SOCKS5 inbound, only if the port is actually accepting connections (`GetWebProxy:320-351`). When `blProxy` is set and the first attempt returns empty, the code **retries directly** (`SubscriptionHandler.DownloadSubscriptionContent:102-113`).
* User-Agent: per-subscription `SubItem.UserAgent`; when empty, `Utils.GetVersion(false)` → `"v2rayN/<version>"` (`DownloadService.cs:256-260`, `Utils.cs:866-880`). A dictionary of browser UAs exists for per-outbound/uTLS purposes (`Global.cs:207-216`), and `CoreBasicItem.DefUserAgent` is a separate setting used for outbound traffic, not for subscriptions.
* Subscription conversion services (external `subconverter` instances) are optional: `ConstItem.SubConvertUrl` or defaults `https://sub.xeton.dev/sub?url={0}`, `https://api.dler.io/sub?url={0}`, `http://127.0.0.1:25500/sub?url={0}` (`Global.cs:136-142`), with `target=` and `config=` appended (`SubscriptionHandler.DownloadMainSubscription:129-156`).
* Multiple URLs per subscription: `MoreUrl` comma-separated; main payload base64-decoded before concatenation if it looks like base64 (`DownloadAdditionalSubscriptions:158-195`).

Parsing pipeline (`ConfigHandler.AddBatchServers`, `ServiceLib/Handler/ConfigHandler.cs:2040-2138`):

1. If `isSub && subid` → delete existing servers of that subscription first, remember the active profile and old traffic stats.
2. Try, in order: base64-decode → parse as newline-separated share links; then raw text; then base64 again (classic v2rayN heuristic `if (Utils.IsBase64String(strData)) ...; if (counter < 1) raw; if (counter < 1) base64`).
3. Fallbacks: Shadowsocks SIP008 JSON (`AddBatchServers4SsSIP008`), WireGuard `.conf` (`AddBatchServers4Wireguard`), internal `v2rayn://` URIs (`AddBatchServers4InnerUri`), then custom configs (v2ray JSON / sing-box JSON / outbound-only JSON) (`AddBatchServers4Custom`, `:1718-1757`).
4. Per line: `FmtHandler.ResolveConfig` (scheme dispatch at `ServiceLib/Handler/Fmt/FmtHandler.cs:35-110`) → per-protocol typed parser (`VmessFmt`, `VLESSFmt`, `TrojanFmt`, `ShadowsocksFmt`, `SocksFmt`, `Hysteria2Fmt`, `TuicFmt`, `WireguardFmt`, `AnytlsFmt`, `NaiveFmt`) → regex `SubItem.Filter` against the remark (`:1667-1674`) → `AddVMessServer`/`AddVlessServer`/… (per-protocol insert/merge with dedupe) → batch insert.
5. After import, re-select the previously active node if it still exists and clone traffic stats (`:2112-2135`).

Parsing details worth knowing:

* VMess: `vmess://` payload is base64 of a JSON `VmessQRCode` (`v`, `ps`, `add`, `port`, `id`, `aid`, `scy`, `net`, `type`, `host`, `path`, `tls`, `sni`, `alpn`, `fp`, `insecure`, `vcn`, `pcs`) — `VmessFmt.ResolveVmess:81-150`; also supports the "standard" `vmess://userinfo@host:port?...` form (`ResolveStdVmess:152-179`).
* VLESS/Trojan/etc.: URI with query string mapped in the shared `BaseFmt.ResolveUriQuery` (`ServiceLib/Handler/Fmt/BaseFmt.cs:197-…`): `security`, `sni`, `alpn`, `fp`, `pbk`, `sid`, `spx`, `pqv`, `ech`, `vcn`, `pcs`, `fm` (FinalMask JSON), and `type` mapped into an `ETransport` enum with the legacy alias `tcp`→`raw` (`:231-237`).
* Transport-specific fields are stored as **JSON strings inside SQLite columns** (`ProfileItem.ProtoExtra`, `ProfileItem.TransportExtra`, `Models/Entities/ProfileItem.cs:202-203`, accessed through `GetProtocolExtra()`/`SetProtocolExtra()`).
* Error handling: per-line failures are silently skipped (`if (profileItem is null) continue;`, `ConfigHandler.cs:1661-1665`); only an aggregate count is reported. If `AddBatchServers` returns ≤ 0, the raw payload is dumped into the log file (`SubscriptionHandler.cs:216-221`) and the UI shows "failed to import subscription". There is no per-line error list.

### 1.7 Cross-platform abstractions

| Concern | Windows | Linux | macOS |
|---|---|---|---|
| Core elevation for TUN | restart app elevated (`runas`, `Global.RebootAs`) — `ProcUtils.RebootAsAdmin:47-64` | `sudo -S` shell script with password on stdin — `CoreAdminManager.cs:32-70` | same as Linux, different kill script (`:81`) |
| TUN device cleanup | `pnputil /remove-device SWD\Wintun\{guid(md5(name))}` for `wintunsingbox_tun` and `xray_tun` (`ServiceLib/Common/WindowsUtils.cs:49-72`) | none (Xray removes its own interface) | none |
| System proxy | WinINet/registry P/Invoke, ~14 KB implementation with PAC support (`ServiceLib/Handler/SysProxy/ProxySettingWindows.cs`); PAC server `PacManager` | **embedded shell script** `proxy_set_linux_sh` invoked as a file, detects GNOME/KDE/XFCE/…, uses `gsettings`/`kwriteconfig` (`ProxySettingLinux.cs`, `Sample/proxy_set_linux_sh`) | embedded `proxy_set_osx_sh` (`ProxySettingOSX.cs`) |
| Auto-start | registry Run key (`Global.cs:78-79`, `Handler/AutoStartupHandler.cs`) | embedded `linux_autostart_config` | launch agent (`AutoStartupHandler.cs`) |
| Global hotkeys | submodule `GlobalHotKeys` (Windows-only) | — | — |
| Core lifetime | Win32 Job Object kill-on-close | process kill only | process kill only |
| Paths | `%LOCALAPPDATA%\v2rayN` fallback when not writable | same mechanism | same |
| Updates | `AmazTool` unzip-and-restart | same | same |

The abstractions are **runtime `if (Utils.IsWindows())` branches over static helper classes**, not interfaces; platform code is compiled into `ServiceLib` on all platforms (e.g. `[SupportedOSPlatform("windows")]` methods in shared files). There is no OS-conditional project.

### 1.8 Avalonia implementation

* **MVVM framework**: ReactiveUI 24.2.0 with `ReactiveUI.SourceGenerators` (3.2.0) — `[Reactive] public partial ...` properties (`Directory.Packages.props`, `v2rayN.Desktop/ViewModels/ThemeSettingViewModel.cs:10-14`). Base class `MyReactiveObject : ReactiveObject, IActivatableViewModel` with a **`protected static Config? _config`** (`ServiceLib/Base/MyReactiveObject.cs:3-7`) — i.e. every ViewModel reads a static mutable global.
* **DI container: none.** Composition is `AppManager.Instance.InitApp()` / `InitComponents()` called from `Program.OnStartup`/`App.OnFrameworkInitializationCompleted` (`v2rayN.Desktop/Program.cs:48-54`, `v2rayN.Desktop/App.axaml.cs:23-32`). Everything else is `Lazy<T>` singletons: `AppManager`, `CoreManager`, `CoreInfoManager`, `CoreAdminManager`, `StatisticsManager`, `TaskManager`, `NoticeManager`, `SQLiteHelper`, plus static `ConfigHandler`, `Utils`.
* **View/ViewModel layout**: ViewModels live in `ServiceLib/ViewModels` (21 files, shared with WPF); Avalonia Views in `v2rayN.Desktop/Views` (26 `.axaml`, each with a code-behind). Mapping is a hand-written registry `SimpleViewLocator : IDataTemplate` (`v2rayN.Desktop/Common/SimpleViewLocator.cs:15-39`), which caches views for four VM types in a `ConditionalWeakTable` and returns a red `TextBlock` for unregistered VMs.
* **Theming**: Semi.Avalonia 12.1.0.1 + DialogHost.Avalonia; theme selected in `ThemeSettingViewModel.ModifyTheme` (`:75-91`) mapping `ETheme` (`ServiceLib/Enums/ETheme.cs`) to `ThemeVariant` / `SemiTheme.Aquatic|Desert|Dusk|NightSky`. Font size/family are applied by **appending a new `Style` to `Application.Current.Styles` on every change** (`ModifyFontSize:93-121`, `ModifyFontFamily:132-166`) — styles accumulate and are never removed.
* **Localization**: `.resx` in `ServiceLib/Resx` (`ResUI.resx` + `az/fa/fr/hu/id/ru/zh-Hans/zh-Hant`), 5403-line generated designer; consumed in XAML via `{x:Static resx:ResUI.Key}`. Language is applied by setting `Thread.CurrentThread.CurrentUICulture` once at startup (`AppManager.cs:77`) and on change (`ThemeSettingViewModel.cs:68`) with a "restart required" notice (`:70`) — because `x:Static` values are resolved once at load. 9 languages (`Global.cs:492-503`).
* **Settings persistence**: two stores. `guiConfigs/guiNConfig.json` via `ConfigHandler.LoadConfig`/`SaveConfig` (`ConfigHandler.cs:18-…`, `:208-233` — write temp then `File.Move(..., overwrite: true)`); everything list-like (servers, subscriptions, routing, DNS, traffic stats, groups) in `guiConfigs/guiNDB.db` via `sqlite-net-e`. The JSON `Config` is a mutable POCO aggregate of 20+ sub-items (`Models/Configs/Config.cs`, `ConfigItems.cs:3-303`) and is saved from many places (grep `SaveConfig(` → five call sites inside `ConfigHandler.cs` alone, 20 across `ServiceLib` + `v2rayN.Desktop`) with no single writer.
* Startup single-instance: named `EventWaitHandle` on Windows, `Mutex("v2rayN")` elsewhere (`Program.cs:26-46`).
* The Windows WPF shell duplicates every View (`v2rayN/Views/*.xaml` + `xaml.cs`) against the same shared ViewModels — i.e. **two XAML trees to maintain** and the reason the ViewModels contain UI-shaped state (window sizes, column widths, `IWindowDialog`) rather than being presentation-agnostic.

### 1.9 Configuration model quality (evidence for "do not copy")

`ServiceLib/Models/Entities/ProfileItem.cs` (219 lines) mixes current and dead fields in one type:

* `[Obsolete]` string fields kept for compatibility: `HeaderType`, `RequestHost`, `Path`, `Extra`, `Ports`, `Flow`, `Id`, `Security` (`:173-218`).
* Typed escapes: `ProtoExtra` and `TransportExtra` are **JSON blobs in string columns**, parsed lazily and cached (`:127-147`), and `GetProtocolExtra()` is called pervasively at generation time.
* Booleans encoded as strings: `AllowInsecure == Global.StringTrue` (`:149-152`, `Global.cs:96-97`).
* `ProfileItem` is `[Serializable]` and used directly as the SQLite row type, the IPC payload candidate, the config-generation input **and** the object bound into the server grid — one type, four responsibilities.
* Migration helper: `AppManager.MigrateProfileExtra` (`AppManager.cs:109-110`) exists precisely because the schema evolves in place.

### 1.10 Concrete UX problems and technical debt to avoid

1. **No core supervision / no crash surfacing.** A crashed Xray leaves the UI claiming the old state (`ProcessService.cs:132-142`); MyVpn already has `ErrorCodes.XrayStoppedUnexpectedly` and a `Reconnecting`/`Degraded` state (`src/MyVpn.Core/Domain/VpnConnectionState.cs`) — wire them up.
2. **Global mutable singleton state everywhere.** `AppManager.Instance.Config` is mutated from ViewModels, handlers and managers; `MyReactiveObject._config` is `static` (`ServiceLib/Base/MyReactiveObject.cs:5`); `StatisticsManager` and `AppManager` hold unbounded per-core caches (`StatisticsManager` holds `_lstServerStat` in memory; `AppManager.LastCheckUpdateResults` grows per core type). This makes deterministic tests impossible without deep stubbing.
3. **God classes.** `ConfigHandler.cs` = 3003 lines (~40 responsibilities incl. server CRUD, subscriptions, backup/restore, routing, DNS); `Utils.cs` = 1411 lines of path/string/QR/network/process helpers; `V2rayOutboundService.cs` = 881 lines; `ProfilesViewModel.cs` = 904.
4. **Stringly-typed everything.** Routing rules, DNS, `ProtocolExtra`, `TransportExtra`, ports, `AllowInsecure`, log levels, `EInboundProtocol` arithmetic (`GetLocalPort` adds the enum ordinal to a base port — `AppManager.cs:165-169`), and `ConstItem` URLs. A typo becomes a runtime Xray error instead of a compile error.
5. **Almost no validation before launch.** `ProfileItem.IsValid()` (`:67-125`) is a partial check; `NodeValidator` exists (`Handler/Builder/NodeValidator.cs`) but produces warnings/errors that are only enqueued as toasts. The generated config is never validated with `xray run -test` before swapping the running core.
6. **Dense, technical UI.** The main window is a server grid with 15 column kinds (`Enums/EServerColName.cs`) and 29 column definitions in one XAML file (`v2rayN.Desktop/Views/ProfilesView.axaml`, 322 lines); a menu bar with 45 `MenuItem` entries, 20 of which are per-protocol "Add …" variants (`MainWindow.axaml:25-89`); the server context menu has 33 items including 7 export variants and 5 test variants (`ProfilesView.axaml:37-204`); the bottom tab strip duplicates "message log / Clash proxies / Clash connections" across three layout variants (`MainWindow.axaml:123-153`); and there are 26 top-level Views/windows for routing, DNS, full-config template, global hotkeys, theme, sub-edit, sub-setting, QR code, JSON editor and more. Nothing guides a first-time user; even "add a server" requires a protocol mental model.
7. **Errors surface as log text, not as structured states.** Many catches are `catch { }` or `Logging.SaveLog(...); return null;` (e.g. `CoreManager.cs:171-174`, `ProcessService.cs:103-109`, `CoreConfigV2rayService.cs:79-84`). Failures are pushed onto the message panel as unlocalized/technical strings or via `NoticeManager.Enqueue` toast with no action.
8. **Logging cannot be re-enabled at runtime.** `Logging.LoggingEnabled(false)` calls `LogManager.SuspendLogging()` and there is no resume (`ServiceLib/Common/Logging.cs:23-28`).
9. **Update path has no integrity check and no path-traversal guard.** `AmazTool.UpgradeApp.Upgrade` unzips entries into `Path.Combine(startupPath, relativeName)` after dropping the first path component, with no `Path.GetFullPath` containment check and no hash/signature verification anywhere in the update code path (grep for `sha256|gpg|signature|hash` in `AmazTool/*.cs`, `Services/UpdateService.cs`, `Services/DownloadService.cs` → no matches). A malicious update archive or a hijacked mirror can write outside the install directory. (The README advertises GPG-signed releases, but the in-app updater does not verify them — the GPG step is a manual user action.)
10. **Geo data is never validated; downloads are installed wholesale on batch success** (`UpdateService.DownloadGeoFiles:534-590`), and there is no repair path when a `.dat` is corrupt (MyVpn's `GeoAssetValidator` + `ErrorCodes.GeoAsset*` already exist as the fix).
11. **Privilege model is weak.** Root Xray launched from a user-writable script directory (`binConfigs/run_as_sudo.sh`) with the sudo password in memory, plus `Global.LinuxSudoPwd` in a singleton; the whole GUI runs unprivileged but the elevated child is spawned by the GUI. MyVpn's `MyVpn.Service` + IPC design (`src/MyVpn.Service/MyVpn.Service.csproj`) is a materially safer structure.
12. **Mobile-style hard-coded business defaults** inside `Global.cs` (speed-test URLs, DoH servers, tun address pools, regional keyword regexes, `Prefilter` regexes) — configuration masquerading as code.
13. **Hidden promotional artifact.** `Global.PromotionUrl = "aHR0cHM6Ly85LjIzNDQ1Ni54eXovYWJjLmh0bWw="` (`Global.cs:11`) decodes to `https://9.234456.xyz/abc.html`. A grep across the clone finds **no reference** to the constant, so its (intended) use is **UNVERIFIED**; nevertheless it is the kind of embedded promotional/telemetry-adjacent surface MyVpn should not reproduce.
14. **Two full XAML trees** (WPF + Avalonia) for one product, with ViewModels carrying window/column/layout state.

### 1.11 Licensing facts (summary; analysis in §3.1)

* Repository `LICENSE` (`/tmp/v2rayN/LICENSE`, 674 lines, 35 134 bytes) is the **verbatim GNU GPL version 3 text** (header: "GNU GENERAL PUBLIC LICENSE / Version 3, 29 June 2007"). There is **no "or any later version" statement** anywhere in the repo: the only GPL/SPDX token in the entire solution is `Directory.Build.props:14` (`grep -rn -i 'spdx\|gpl-3\|gplv3' --include='*.cs' --include='*.csproj' --include='*.props' --include='*.axaml' --include='*.xaml'` returns exactly that one line), there is no license section in `README.md` (`grep -ci licen README.md` → `0`), and `Directory.Build.props:14` declares the SPDX expression **`GPL-3.0`** (the deprecated alias of `GPL-3.0-only`, not `GPL-3.0-or-later`).
* GitHub's repository metadata reports `"license": {"key":"gpl-3.0","spdx_id":"GPL-3.0"}` (`https://api.github.com/repos/2dust/v2rayN`, fetched during this study).
* Subprojects: the only other project with its own license file is the `GlobalHotKeys` submodule → **WTFPL v2** (`https://github.com/2dust/GlobalHotKeys`, `LICENSE` first 3 lines "DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE / Version 2, December 2004"). It is permissive and GPL-compatible, and it is Windows-only. The other projects (`ServiceLib`, `v2rayN`, `v2rayN.Desktop`, `AmazTool`, `ServiceLib.Tests`, `ServiceLib.UdpTest`) carry no separate license and inherit the root GPL-3.0. No `NOTICE`/additional-terms file exists in the repository (only `NoticeManager.cs`, which is an in-app toast helper, not a legal notice).
* **Bundled third-party artifacts in v2rayN release packages** (verified by reading `package-debian.sh:275-410`): the **Xray-core binary** (MPL-2.0, see §3.1) and **geo data downloaded from `Loyalsoldier/v2ray-rules-dat`** (GitHub reports GPL-3.0 — `https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/license`, fetched during this study), plus `Loyalsoldier/geoip` (`geoip-only-cn-private.dat`, `Country.mmdb`) and `MetaCubeX/meta-rules-dat` (`geoip.metadb`) and `2dust/sing-box-rules` `.srs` files. Licenses of the latter three were **not verified in this study** (UNVERIFIED; GitHub API rate-limited after the first two calls).
* Everything in the repo — code, embedded JSON templates in `ServiceLib/Sample/`, `.resx` strings, shell scripts, images — is part of the GPL-3.0 work unless separately licensed.

---

## 2. Architecture proposal for MyVpn

This proposal is written against the **scaffold already present in this workspace** (all projects target `net8.0`, `TreatWarningsAsErrors=true`, GPL-3.0-or-later, `CommunityToolkit.Mvvm`, xunit+Shouldly). It reuses the existing Core types: `Result`/`Result<T>`, `MyVpnError`, `ErrorCodes`, `ServerProfile`, `VpnStateMachine`/`VpnConnectionState`, `CidrBlock`, `GeoAssetValidator`/`GeoDataStatus`/`GeoRuleAvailability`. Nothing here requires touching `src/` now — it is a design to implement.

### 2.1 Dependency rule (already encoded in the existing `.csproj` comments)

```
MyVpn.Core                     (no deps; domain + pure logic)
  ↑
MyVpn.Application              (ports + use cases; Core only)
  ↑                                     ↑
MyVpn.Platform.Abstractions ────────────┘   (capability ports + pure plan renderers)
  ↑
MyVpn.Infrastructure           (Xray engine, geo, subscriptions, settings, diagnostics)
  ↑
MyVpn.Platform.{Linux,Windows,MacOS}   (plan executors only)
  ↑
MyVpn.Ipc  →  MyVpn.Service (privileged host)   MyVpn.Cli (headless)   MyVpn.UI (Avalonia)
```

The **one rule that must not bend**: `MyVpn.UI` never performs privileged or network-mutating work; it talks to `IMyVpnServiceFacade`, which is either the in-process facade (proxy-only) or the IPC-backed facade (TUN / kill switch). This is already stated in `src/MyVpn.UI/MyVpn.UI.csproj` and is the direct answer to v2rayN's `sudo`-script design.

### 2.2 Ports to add in `MyVpn.Application`

```csharp
// src/MyVpn.Application/Ports/Xray/IXrayBinaryLocator.cs
namespace MyVpn.Application.Ports.Xray;

/// <summary>Finds the Xray executable and reports what it can do.</summary>
public interface IXrayBinaryLocator
{
    /// <summary>
    /// Resolution order is explicit and user-visible:
    ///   1. explicit path from settings, 2. <c>myvpn</c> side-by-side dir,
    ///   3. OS package locations, 4. PATH. Never "first file that happens to exist".
    /// </summary>
    Task<Result<XrayBinary>> LocateAsync(CancellationToken ct);

    /// <summary>Runs <c>xray version</c> and caches the parsed semantic version.</summary>
    Task<Result<XrayVersionInfo>> ProbeAsync(XrayBinary binary, CancellationToken ct);
}

public sealed record XrayBinary(string AbsolutePath, string Sha256, bool IsExecutable);

public sealed record XrayVersionInfo(
    Version Version,
    bool SupportsTunInbound,        // probed, not assumed
    bool SupportsRunTestFlag,       // `xray run -c f -test`
    bool SupportsMetricsEndpoint,
    IReadOnlyDictionary<string, string> Capabilities);
```

```csharp
// src/MyVpn.Application/Ports/Xray/IXrayConfigGenerator.cs
public interface IXrayConfigGenerator
{
    /// <summary>
    /// Pure: profile + options -> JSON document + a structured map of what was emitted.
    /// The returned <see cref="XrayConfigArtifact.ReferencedGeoAssets"/> is what the
    /// geo gate consults: a geoip:/geosite: rule is only emitted if the asset is Valid.
    /// </summary>
    Result<XrayConfigArtifact> Generate(XrayConfigRequest request);
}

public sealed record XrayConfigRequest(
    ServerProfile Profile,
    TunnelMode Mode,                       // MyVpn.Core.Domain.TunnelMode
    TunOptions? Tun,
    InboundOptions Inbound,
    RoutingPlan Routing,                   // resolved, typed rules — not raw JSON
    DnsOptions Dns,
    GeoRuleAvailability Geo,
    LoggingOptions Logging,
    string AssetDirectory,                 // absolute; becomes XRAY_LOCATION_ASSET
    string ConfigPathAbsolute);            // absolute; no reliance on CWD

public sealed record XrayConfigArtifact(
    string Json,
    IReadOnlyList<GeoAssetKind> ReferencedGeoAssets,
    int InboundPort);
```

```csharp
// src/MyVpn.Application/Ports/Xray/IXrayProcessSupervisor.cs
public interface IXrayProcessSupervisor : IAsyncDisposable
{
    XrayProcessStatus Status { get; }
    event EventHandler<XrayProcessStatusChanged>? StatusChanged;

    /// <summary>
    /// Start = validate (`-test`) -> start -> wait for readiness -> attach log pump.
    /// Returns only when the core is either Ready or the start failed.
    /// </summary>
    Task<Result<XrayProcessHandle>> StartAsync(XrayLaunchSpec spec, CancellationToken ct);
    Task<Result> StopAsync(TimeSpan gracefulTimeout, CancellationToken ct);
    Task<Result> ReloadAsync(XrayLaunchSpec spec, CancellationToken ct); // atomic swap
}

public sealed record XrayLaunchSpec(
    string ExecutablePath,
    string ConfigPathAbsolute,
    string WorkingDirectory,                                   // explicit, defaults to state dir
    IReadOnlyDictionary<string, string> Environment,            // XRAY_LOCATION_ASSET, XRAY_JSON_STRICT, XJSON...
    TimeSpan ReadinessTimeout,
    LogLevel MinimumLogLevel);

public enum XrayProcessStatus { Stopped, Validating, Starting, Ready, Degraded, Stopping, Faulted }
```

Restart policy as a **pure, testable policy object** (no `Task.Delay` inside the policy):

```csharp
// src/MyVpn.Core/Domain/XrayRestartPolicy.cs  (pure -> unit-testable, no I/O)
public sealed record XrayRestartPolicy(
    int MaxConsecutiveFailures = 5,
    TimeSpan InitialBackoff = TimeSpan.FromSeconds(1),
    TimeSpan MaxBackoff = TimeSpan.FromSeconds(30),
    TimeSpan HealthyResetThreshold = TimeSpan.FromMinutes(2))
{
    /// <summary>
    /// Exit code 23 is Xray's "configuration error, do not restart" signal
    /// (see XTLS/Xray-core main/run.go). Exit 0 = requested stop. Everything else
    /// is a crash subject to backoff.
    /// </summary>
    public RestartDecision Decide(int exitCode, TimeSpan uptime, int consecutiveFailures) =>
        exitCode switch
        {
            0 => RestartDecision.Stop,
            23 => RestartDecision.Faulted,                  // fix the config, never loop
            _ when uptime >= HealthyResetThreshold => RestartDecision.Restart(new(1)),
            _ when consecutiveFailures >= MaxConsecutiveFailures => RestartDecision.Faulted,
            _ => RestartDecision.Restart(Next(consecutiveFailures)),
        };

    private TimeSpan Next(int failures) =>
        TimeSpan.FromMilliseconds(Math.Min(
            MaxBackoff.TotalMilliseconds,
            InitialBackoff.TotalMilliseconds * Math.Pow(2, failures)));
}
```

```csharp
// src/MyVpn.Application/Ports/Process/IProcessRunner.cs   (fake-able; no System.Diagnostics in use cases)
public interface IProcessRunner
{
    Task<Result<IProcessHandle>> StartAsync(ProcessStartSpec spec, CancellationToken ct);
}

public interface IProcessHandle : IAsyncDisposable
{
    int ProcessId { get; }
    bool HasExited { get; }
    int? ExitCode { get; }
    Task WaitForExitAsync(CancellationToken ct);
    IAsyncEnumerable<ProcessOutputLine> ReadOutputAsync(CancellationToken ct); // Channel-bounded
}

public sealed record ProcessStartSpec(
    string FileName, IReadOnlyList<string> Arguments, string WorkingDirectory,
    IReadOnlyDictionary<string, string> Environment, bool RedirectStdout, bool RedirectStderr);
```

### 2.3 Subscription pipeline

```csharp
// src/MyVpn.Application/Ports/Subscriptions/ISubscriptionService.cs
public interface ISubscriptionService
{
    Task<Result<SubscriptionFetchResult>> FetchAsync(SubscriptionSource source, CancellationToken ct);
    Task<Result<SubscriptionImportResult>> ImportAsync(SubscriptionSource source, CancellationToken ct);
    Task<Result<SubscriptionUpdateSummary>> UpdateAsync(SubscriptionUpdateRequest request, CancellationToken ct);
}

public sealed record SubscriptionSource(
    Guid Id,
    string DisplayName,
    Uri Url,
    IReadOnlyList<Uri> AdditionalUrls,
    string? UserAgent,                                        // default "MyVpn/<version>"
    IReadOnlyDictionary<string, string> RequestHeaders,       // validated at construction
    string? RemarkIncludeFilter,                              // compiled regex, not a string
    TimeSpan? AutoUpdateInterval,
    DateTimeOffset? LastUpdatedAt);

public sealed record SubscriptionImportResult(
    int Imported, int Skipped, int Duplicates,
    IReadOnlyList<ServerImportError> Errors);                  // per-line, structured, localized keys

public sealed record ServerImportError(int LineNumber, string ErrorCode, string MessageKey, string? RedactedLine);
```

Share-link parsing is split per protocol behind one port, so adding a protocol is additive and the parser is a pure function:

```csharp
// src/MyVpn.Application/Ports/Subscriptions/IShareLinkParser.cs
public interface IShareLinkParser
{
    bool CanParse(ReadOnlySpan<char> line);
    Result<ServerProfile> Parse(ReadOnlySpan<char> line);
    Result<string> Write(ServerProfile profile);   // export path uses the same model -> round-trip tests
}
```

Payload decoding stays in Infrastructure but as explicit, ordered strategies instead of v2rayN's "try raw/base64/raw/base64" guess loop:

```csharp
public interface ISubscriptionPayloadReader
{
    /// <summary>Ordered, each strategy reports why it declined; first success wins.</summary>
    IReadOnlyList<IPayloadStrategy> Strategies { get; }
}
// Strategies: Base64ShareLinkList, PlainShareLinkList, Sip008Json, WireGuardConf,
//             ClashYaml(optional, sing-box-free: parse proxies only, no core involved), MyVpnInnerUri
```

Fetching rules (derived from §1.6, but stricter):

* Ordered transports: `HttpClient` (SocketsHttpHandler, explicit connect timeout) → optional second transport; each attempt yields a structured error.
* **No silent direct fallback that leaks the real IP** when the user explicitly enabled "update via proxy": fallback is a setting, off by default, and is reported in the UI when it happens.
* Enforce `https://` unless the host is loopback/private or the user explicitly allowed insecure once (v2rayN only warns — `ConfigHandler.AddSubItem` commented-out return).
* Enforce a maximum payload size (e.g. 8 MiB) and a per-line maximum length.

### 2.4 Xray integration design (the core of MyVpn)

1. **Locate & probe** the binary (`IXrayBinaryLocator`), record absolute path + SHA-256 + probed version/capabilities. Refuse to start on an unsupported version with `ErrorCodes.XrayVersionUnsupported`.
2. **Generate a typed config** (`IXrayConfigGenerator`) from a resolved `XrayConfigRequest`. No embedded third-party JSON templates: the generator builds `System.Text.Json` DTOs, all keys exactly as documented by Xray (lowercase `mtu`, `gateway`, `autoSystemRoutingTable`, `autoOutboundsInterface`, `dns`, `desc`). Golden-file tests pin the JSON.
3. **Pre-flight validate**: write to a per-attempt file `state/config/<profileId>/candidate.json`, then run `xray run -c candidate.json -test` with a short timeout; treat exit 23 / non-zero as `ErrorCodes.ConfigRejectedByCore` and surface Xray's stdout verbatim. Only then promote the file to the live path (atomic `File.Move` with a `.previous` copy retained).
4. **Start supervised**: spawn with explicit `WorkingDirectory` (state dir, never the asset dir), explicit `XRAY_LOCATION_ASSET` absolute path, `XRAY_JSON_STRICT=true` (our JSON is RFC 8259), and `XRAY_LOCATION_CERT` only if we ship certs. Capture stdout/stderr into a **bounded `Channel<ProcessOutputLine>`** (e.g. 5 000 lines, oldest dropped, overflow counter exposed) so a chatty core can never grow memory without bound — v2rayN forwards every line into a UI-bound `ObservableCollection` (`ProcessService.RegisterEventHandlers`).
5. **Readiness**: poll the local inbound (SOCKS5 greeting or TCP connect) for the proxy-only mode; for TUN mode additionally verify the interface exists and the default route/metric, then run a *health probe* (HTTP 204 through the tunnel) before declaring `Connected`. v2rayN only has the SOCKS handshake, and only for the pre-service (`CoreManager.WaitForProxyPort`).
6. **Reload semantics** (server switch / settings change): generate candidate → `-test` → start *new* process on a *new* local inbound port pair → health-check → then stop the old process and flip the system proxy/routes. v2rayN stops the core first and starts the new one (`CoreManager.LoadCore:85-96`), i.e. a guaranteed outage window and, in TUN mode, a window where the OS route points at a dead interface while the Kill Switch may already be re-arming.
7. **Crash handling**: `XrayRestartPolicy` above; exit 23 → `Faulted` with `XrayRestartLoopDetected`-style diagnostics; on repeated crashes set `Degraded` and **keep** the kill switch engaged (never tear down protection just because the core died — the state machine in `VpnConnectionState` already models this distinction).
8. **Shutdown**: send SIGTERM (or `CloseMainWindow`/`Kill(entireProcessTree: false)` per platform), wait `gracefulTimeout`, escalate; verify no orphan by PID+start-time fingerprint, and on Windows keep the Job Object kill-on-close equivalent (already proven correct in v2rayN), with a Linux/macOS equivalent (process group + `PR_SET_PDEATHSIG` on a tiny launcher, or a systemd unit `BindsTo`).

TUN data structures (mirroring the documented Xray inbound, not v2rayN's sample):

```csharp
// src/MyVpn.Core/Domain/TunOptions.cs
public sealed record TunOptions(
    string InterfaceName,                       // "myvpn0" (Linux), "utun" (macOS, Xray picks N), Wintun adapter on Windows
    string? Description,                        // Windows adapter description, default "Wintun"
    int Mtu = 1500,
    IReadOnlyList<CidrBlock> Gateways = default!,        // e.g. 172.18.0.1/30 (+ fc00::/126)
    IReadOnlyList<IPAddress> DnsServers = default!,      // Windows only per Xray docs
    bool AddDefaultRoutes = true,               // autoSystemRoutingTable = 0.0.0.0/0 (+ ::/0 when applicable)
    string OutboundInterface = "auto",          // autoOutboundsInterface — loop prevention
    Ipv6Mode Ipv6 = Ipv6Mode.DisableWhileConnected,
    IReadOnlyList<CidrBlock> RouteExclude = default!);
```

### 2.5 Geo asset management

Existing Core types already define the target state (`GeoAssetKind`, `GeoDataStatus`, `GeoAssetInfo`, `GeoAssetValidator`, `GeoRuleAvailability`). Infrastructure adds:

```csharp
// src/MyVpn.Application/Ports/Geo/IGeoAssetManager.cs
public interface IGeoAssetManager
{
    Task<GeoDataStatus> InspectAsync(CancellationToken ct);                    // absolute paths only
    Task<Result<GeoInstallResult>> InstallAsync(GeoAssetKind kind, Stream content, GeoAssetManifestEntry manifest, CancellationToken ct);
    Task<Result<GeoInstallResult>> RollbackAsync(GeoAssetKind kind, CancellationToken ct);
}

public sealed record GeoAssetManifestEntry(
    GeoAssetKind Kind, Uri Source, long SizeBytes, string Sha256, string LicenseSpdx, Uri LicenseUrl, string Attribution);
```

* Storage: `<state>/geodata/geoip.dat`, `<state>/geodata/geosite.dat`, previous generation in `<state>/geodata-backup/`; downloads land in `*.download` on the same filesystem and are promoted by atomic rename only after `GeoAssetValidator` passes **and** the SHA-256 matches the manifest.
* Never install a payload that does not validate — this closes v2rayN's `DownloadGeoFiles` hole (§1.4).
* Config generation consults `GeoRuleAvailability`: unavailable asset ⇒ emit an explicit fallback rule set and a UI repair prompt instead of a `geoip:`/`geosite:` reference that makes Xray refuse to start.
* Ship a **manifest** (URL, size, SHA-256, license, attribution) rather than hard-coded `Global.GeoUrl` format strings.

### 2.6 Platform capabilities (ports + pure renderers)

Already specified by `src/MyVpn.Platform.Abstractions/MyVpn.Platform.Abstractions.csproj`: capability interfaces (`IKillSwitch`, `IRouteManager`, `IDnsConfigurator`, `IProcessRouter`, `ISystemProxy`, `IPrivilegedHost`, `ITunDeviceManager`) plus *plan* value objects and **pure renderers** (nftables text, WFP descriptors, PF anchor text) that unit-test without root.

Two additions worth making explicit from this study:

```csharp
// src/MyVpn.Application/Ports/Platform/ISystemProxy.cs
public interface ISystemProxy
{
    Task<Result<SystemProxySnapshot>> CaptureAsync(CancellationToken ct);          // to restore exactly
    Task<Result> ApplyAsync(SystemProxyPlan plan, CancellationToken ct);
    Task<Result> RestoreAsync(SystemProxySnapshot snapshot, CancellationToken ct);
    bool SupportsPac { get; }
}

// src/MyVpn.Application/Ports/Platform/ITunDeviceManager.cs
public interface ITunDeviceManager
{
    bool CanCreateWithoutRoot { get; }        // true when a privileged helper owns creation
    /// <summary>
    /// Creates the interface, returns its native handle/FD so the core can adopt it via
    /// XRAY_TUN_FD (documented by Xray for mobile and *optionally Linux*), or null when
    /// the core must create the device itself.
    /// </summary>
    Task<Result<TunDeviceLease>> AcquireAsync(TunOptions options, CancellationToken ct);
    Task<Result> ReleaseAsync(TunDeviceLease lease, CancellationToken ct);
}
```

Privilege model (explicitly different from v2rayN):

* GUI is always unprivileged; the privileged work happens in `MyVpn.Service` (systemd unit / Windows service / launchd daemon) reached over authenticated IPC (Unix socket with `SO_PEERCRED`/`LOCAL_PEERCRED`, or a named pipe with an explicit ACL — as the `MyVpn.Ipc` project comment already specifies).
* The IPC surface is a **narrow, typed command set** ("connect profile X with plan Y", "disconnect", "status"), never "run this command" or "apply this raw config" — the service re-derives the plan from the typed request, so a compromised GUI cannot inject a root shell or an arbitrary nftables payload.
* **No sudo password handling**: prefer (a) a root helper that creates the TUN device and passes the FD via `XRAY_TUN_FD`, or (b) capabilities on the core binary (`setcap cap_net_admin,cap_net_raw+ep`) as a documented alternative, or (c) running Xray inside the service's own cgroup/unit. Remove the "password on stdin to a script in a user-writable directory" pattern entirely.
* Windows: TUN driver lifecycle delegated to Xray (Wintun) as v2rayN does; keep the adapter-removal logic as a *recovery* step only, and use the documented `desc` field to name the adapter deterministically.

### 2.7 UI / MVVM / DI / i18n / settings (Avalonia)

* **MVVM**: `CommunityToolkit.Mvvm` (already pinned, MIT) with `[ObservableProperty]`/`[RelayCommand]` source generators; `ObservableValidator` for form VMs; community toolkit's `IMessenger` for cross-VM events instead of static events. ViewModels live in `MyVpn.UI/ViewModels` and are **constructed by DI** (constructor injection), never singletons with static state.
* **DI**: `Microsoft.Extensions.Hosting` generic host in `MyVpn.UI/Program.cs` and `MyVpn.Service`; `IServiceCollection` modules per layer (`AddMyVpnCore`, `AddMyVpnApplication`, `AddMyVpnInfrastructure`, `AddMyVpnPlatform`); options bound from settings (`IOptions<XrayOptions>` etc.). No `AppManager.Instance`.
* **Views**: one View per ViewModel with `AvaloniaUseCompiledBindingsByDefault` (already enabled in `MyVpn.UI.csproj`), registered in an `IDataTemplate` view locator; Views contain **no logic** beyond visual wiring. No duplicated XAML tree for a second UI framework.
* **Theming**: Fluent + `ThemeVariant` for Light/Dark/System; a single `IThemeService` that swaps a `ResourceDictionary` (never appends `Style` objects to `Application.Styles` — v2rayN's font-size/family handling leaks styles, §1.8).
* **Localization**: JSON locale files (the `MyVpn.UI.csproj` already embeds `Localization/locales/*.json`) behind `ILocalizer` with a `{loc:Translate Key}` markup extension **and** runtime culture switch that re-reads strings (no "restart required"). Error text is always resolved from `ErrorCodes` → message key, so a code is never localized (matching the contract stated in `src/MyVpn.Core/Results/ErrorCodes.cs:5-10`).
* **Settings**: one `IAppSettingsStore` with a **single writer** (an actor/queue) writing atomically (temp + `File.Move`), schema-versioned with explicit migrations, and **secrets separated** (credentials in an OS keystore — DPAPI/libsecret/Keychain — not in the plaintext JSON next to the profiles). Profile lists get their own store (`IProfileRepository`) — v2rayN conflates the JSON config and the SQLite DB and has 6+ `SaveConfig` call sites.
* **UX direction** (direct response to §1.10): a small number of task-oriented surfaces — *Home* (one big connect control + current server + live state from `VpnStateMachine`), *Servers* (searchable list with progressive detail; advanced fields in a drawer, not 15 always-visible columns), *Subscriptions* (add/update with per-line error report), *Routing/DNS* (presets first, advanced second), *Diagnostics* (structured health checks + export bundle). Every failure is a typed state with a suggested action, not a log line.

### 2.8 Concurrency and state

* All service/process state is owned by the domain (`VpnStateMachine`) and per-service supervisors; no `static` mutable state anywhere.
* `IProcessHandle.ReadOutputAsync` → bounded channel; UI consumes via a throttled batching collection.
* One writer per store; reads return immutable snapshots (`CoreConfigContext` in v2rayN is the right instinct — keep it, but as a request object owned by the Application layer, not a mutable bag).
* Every async port takes a `CancellationToken`; every `Task.Delay`/timeout lives in an injectable `TimeProvider` so tests do not sleep.

---

## 3. Risks

### 3.1 Licensing risks (critical)

**Finding: v2rayN is GPL-3.0-only, not "or later".**
Evidence: `/tmp/v2rayN/LICENSE` is the bare GPLv3 text with no version-election statement; `Directory.Build.props:14` = `GPL-3.0` (SPDX `GPL-3.0-only`); no SPDX/copyright headers in any `.cs` file; no license section in `README.md`; GitHub metadata `spdx_id: "GPL-3.0"`.

Consequences if MyVpn were to copy any v2rayN material (code, the embedded `ServiceLib/Sample/*` JSON templates, `.resx` strings, shell scripts, icons):

1. **MyVpn would become a derivative work of a GPL-3.0-only work.** The whole combined work must be distributed under GPLv3, with all copyright notices preserved, the full source of the corresponding work made available, and no additional restrictions (GPLv3 §§4-6, §10). MyVpn already intends to publish source under `GPL-3.0-or-later` (`Directory.Build.props:39`), so publishing source is compatible, **but** the combined distribution effectively becomes GPL-3.0(-only) for the copied portions: a bare `GPL-3.0-or-later` grant cannot add the "or later" option on top of a GPL-3.0-only component. Practically: keep copied files marked `GPL-3.0-only` with the original copyright line, and do not claim "or later" for them.
2. **Attribution/marking duties**: modified files must carry prominent notices of modification and date (GPLv3 §5a), and the work must carry notices that it is released under this licence (GPLv3 §5b). Saying "inspired by v2rayN" in `NOTICE` is **not** a substitute once code is copied.
3. **Non-code assets are covered too.** The embedded Xray config templates under `ServiceLib/Sample/` and the shell scripts (`proxy_set_linux_sh`, `kill_as_sudo_linux_sh`, `pac`, …) are part of the GPL-3.0 work. Copying a config template verbatim into `MyVpn.Infrastructure` would import GPL-3.0-only material into a file that would also be compiled into the same assembly.
4. **"Reading for behaviour" vs "copying"**: the *behaviour* and *protocol facts* in this report (e.g. "`XRAY_LOCATION_ASSET` selects the asset dir"; "`xray run -c f -test` exists"; "Wintun adapter names are `xray_tun`") are not themselves copyrightable and are independently documented upstream (Xray docs). MyVpn's current clean-room statement in `NOTICE` §3 is the right policy: **do not copy, record provenance.** I recommend making it auditable: keep a `docs/research/provenance/` log of each studied file/commit, and a CI check that fails if any file carries a v2rayN path/URL in a code comment or a copied identifier list (see §6).
5. **Recommendation**: MyVpn stays clean-room. Use v2rayN only for *what the ecosystem requires* and *what to avoid*. If, later, a specific utility would be much cheaper to copy (e.g. the SOCKS5 greeting readiness probe idea), reimplement it from the SOCKS5 RFC (RFC 1928) rather than copying code.

**Finding: the Xray-core binary is MPL-2.0.**
Evidence: `https://api.github.com/repos/XTLS/Xray-core/license` → `spdx_id: "MPL-2.0"` (fetched during this study).

* MPL-2.0 is file-level copyleft. Because MyVpn only **launches the unmodified executable as a separate process** and communicates via a JSON config file and stdio, MyVpn's own source is a "Larger Work" and is **not** placed under MPL-2.0. This matches `NOTICE` §1. However, if MyVpn **bundles** the binary in an installer/AppImage/zip:
  * §3.2 requires making the Covered Software available in Source Code Form and telling recipients how to obtain it (a URL to the exact upstream release is the normal, accepted approach) and permitting them to obtain it at no more than the cost of distribution;
  * §3.4 requires keeping upstream copyright/licence notices intact — ship the upstream `LICENSE` verbatim in the bundle's `licenses/` directory (as `NOTICE` §5 already requires);
  * if we ever patch/build Xray ourselves, the *modified files* must stay MPL-2.0 and be published; MyVpn currently has no reason to fork Xray, and this report recommends keeping it that way.
  * Also note Xray's `run.go` prints a version banner; do not remove notices from the binary.

**Finding: selected geo data sources carry incompatible-with-proprietary licences; pick deliberately.**
* `Loyalsoldier/v2ray-rules-dat` (v2rayN's default, `Global.cs:8`) is **GPL-3.0** (`https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/license`). Bundling its `geoip.dat`/`geosite.dat` inside a MyVpn installer imports GPL-3.0 material into the aggregate. Mere aggregation of an unmodified data file alongside an independent program is typically *not* derivative, but it still obliges licence text + source availability for the data, and it is a poor fit for a project that wants maximum flexibility.
* `v2fly/geoip` is **CC-BY-SA 4.0** (`https://raw.githubusercontent.com/v2fly/geoip/master/LICENSE`, first line "Attribution-ShareAlike 4.0 International"); `v2fly/domain-list-community` is **MIT** (`https://raw.githubusercontent.com/v2fly/domain-list-community/master/LICENSE`). `NOTICE` §2 already names these as MyVpn's sources — **good choice**, but the CC-BY-SA attribution and ShareAlike obligations must be honoured for any redistributed (or converted) copy: ship the licence text, the attribution line, and a link.
* **UNVERIFIED**: licences of `Loyalsoldier/geoip`, `MetaCubeX/meta-rules-dat` and `2dust/sing-box-rules` (GitHub API rate-limited during this study). If MyVpn ever considers them, verify before use, and record it in the manifest.
* Recommendation: **do not bundle geo data in the first releases**; download it post-install from the manifest with SHA-256 verification and explicit attribution in the UI ("Geo data © v2fly contributors, CC-BY-SA 4.0"), while allowing a user-supplied path so an offline/enterprise install never needs us to redistribute it. This also removes an updater attack surface from the installer.

**Finding: `GlobalHotKeys` is WTFPL v2** (`https://github.com/2dust/GlobalHotKeys` `LICENSE`: "DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE / Version 2"). Permissive and GPL-compatible, but: (a) WTFPL is not OSI-approved, which matters for some corporate policies and for `license-scan` tooling; (b) it is **Windows-only**, so it cannot serve a cross-platform requirement at all; a cross-platform client needs its own per-platform port (X11/Wayland portal on Linux, `RegisterEventHotKey` on macOS, the Win32 hotkey API on Windows). Do not import it.

**Finding: NuGet/dependency licences.** v2rayN's stack includes `sqlite-net-e`, `Repobot.SQLite.Unofficial`, `Downloader`, `WebDav.Client`, `ReactiveUI`, `Semi.Avalonia`, `MaterialDesignThemes`, `TaskScheduler`, `QRCoder`, `ZXing`. MyVpn's pinned set (`Directory.Packages.props`) is MIT/Apache-2.0 and much smaller — keep it that way and keep the `license-scan` CI job (referenced by `NOTICE` §4) as the gate. Note: `ReactiveUI` is MIT, so licence is not the reason to prefer `CommunityToolkit.Mvvm`; simplicity and testability are.

**Additional/other notices**: no `NOTICE`, `COPYING` or additional-terms file exists in the v2rayN repository (verified by `find . -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*'` → only `./LICENSE`). The `PromotionUrl` constant (§1.10.13) is not a licence notice, but it is embedded opaque content that MyVpn must not reproduce.

### 3.2 Technical risks

| # | Risk | Why it matters | Mitigation |
|---|---|---|---|
| T1 | **Xray TUN inbound is version-sensitive** (fields and even key casing evolve; docs list `mtu`, v2rayN emits `MTU`). | A MyVpn release pinned to a newer Xray can break at startup for every TUN user. | Probe version + capabilities at first run; golden-file tests per supported Xray version; pin a tested Xray range in the manifest; set `XRAY_JSON_STRICT=true` and emit documented keys only. |
| T2 | **TUN requires elevation on all three OSes**; Xray creates the interface itself. | Gui must not run as root; v2rayN's sudo-script approach is a security and UX liability. | Privileged service + narrow IPC; create the TUN device in the service and pass `XRAY_TUN_FD` where supported; capabilities on the core binary as an alternative. Never handle a sudo password. |
| T3 | **Traffic loops with TUN** (documented warning in Xray docs). | A loop wedges the machine's network. | Always set `autoOutboundsInterface`/`sockopt.interface`; add a post-connect loop detector (core→same-core inbound counters) and auto-disconnect to `Faulted`. |
| T4 | **Kill-switch/route ordering creates leak windows** on crash or server switch. | Silent IP leak is the worst failure mode for a VPN. | Immutable `NetworkPlan` with pure renderers; apply fail-closed rules before routing; verify after apply; only then declare `Connected`; keep rules engaged in `Degraded`/`Faulted`; atomic replacement (single nft transaction / single WFP transaction). |
| T5 | **Geo data corruption / missing assets** makes Xray refuse to start. | Total outage from a data problem. | `GeoAssetValidator` + SHA-256 + atomic install + rollback + fallback rule sets + repair UI (already modelled by `ErrorCodes.GeoAsset*`). |
| T6 | **Proxy-only mode on Linux** depends on GSettings/KDE CLI and desktop detection. | System-proxy mode silently does nothing on unsupported DEs (v2rayN prints "Unsupported desktop environment"). | Detect and report capability before promising it; capture and restore the exact previous settings; provide a documented env-var fallback and a "copy proxy command" affordance. |
| T7 | **Orphaned privileged core** if the GUI is force-killed (v2rayN guards only Windows). | Elevated process left running, traffic still proxied after the user thinks they disconnected. | Process-group + PDEATHSIG launcher, or run the core under the service's unit with `BindsTo`/`PartOf`; startup-time orphan sweep keyed by PID+start-time. |
| T8 | **Subscription format sprawl** (share links, base64 blobs, SIP008, WireGuard, Clash YAML, `v2rayn://`, sing-box JSON). | Unbounded compatibility work; parsing bugs; SSRF-ish fetching. | Explicit strategy list with an owner per format; scope guard: Xray-supported protocols only, no sing-box payloads accepted (requirement); SSRF guard (no `file://`, block private ranges unless explicitly allowed, cap size/redirects). |
| T9 | **Self-update integrity** (v2rayN verifies nothing and lacks a zip-slip guard). | Code execution via a hijacked mirror or a malicious subscription-supplied update URL. | Signed manifests + SHA-256 verification; absolute-path containment check on extraction; atomic install with rollback; no update from user-controlled URLs. |
| T10 | **Credentials at rest** (v2rayN keeps them in plaintext JSON/SQLite). | Profile theft on a shared machine. | OS keystore, or explicit "store secrets in plaintext" opt-in for portable mode; redaction in diagnostics export. |
| T11 | **Xray log volume and metrics endpoint exposure**. | Unbounded memory growth / local info disclosure (`/debug/vars` on loopback). | Bounded log channel; metrics on loopback with a random high port and no sensitive data; log rotation. |
| T12 | **sing-box exclusion is a hard requirement**, yet the ecosystem's subscription converters emit sing-box payloads. | Accidental inclusion / scope creep. | Parser rejects sing-box JSON explicitly with a clear error; CI check grepping for forbidden identifiers (`sing-box`, `sing_box`, `Singbox`, `srs`); ADR documenting the exclusion. |

### 3.3 Product/compliance risks

* **"VPN client" distribution sensitivity**: some store/package channels and jurisdictions restrict circumvention tooling. Not a code risk, but it affects release channels (`NOTICE`, packaging, and the fact that v2rayN itself ships GPG-signed releases — README "GPG Verification").
* **Reproducibility of the studied reference**: this report pins commit `cef40d3…`; v2rayN evolves quickly (release cadence is high). Any future re-check must re-clone and re-verify rather than trusting this document for new behaviour.
* **Trademark/naming**: do not use v2rayN's name, icons (`v2rayN.ico`, `NotifyIcon*.ico`) or the `v2rayn://` scheme in MyVpn's own UI, and do not imply endorsement.

---

## 4. Implementation plan

Sequenced so each phase is independently verifiable and ends with tests. "AC" = acceptance criteria.

**Phase 0 — provenance & licence guardrails (0.5 day)**
* Add `docs/research/provenance.md` recording this study (commit hash, files read, decisions taken).
* Add `scripts/check-no-derived-code.sh` + CI wiring: fails on forbidden identifiers (`sing-box`, `sing_box`, `Singbox`, `v2rayN`, `guerrilla`), on GPL-3.0-only headers in MyVpn files, and on geo/binary artifacts committed to the repo.
* Extend `NOTICE` §5 checklist with the geo-manifest and Xray-source-URL requirement. (Owner: whoever owns `NOTICE`; I only propose.)
* AC: `docs/research/01-v2rayn-architecture.md` exists and is referenced from `NOTICE` §3 (already the case); the check script exits 0 on the current tree.

**Phase 1 — Xray engine skeleton (3-4 days)**
* `IXrayBinaryLocator` + `XrayBinaryLocator` (explicit order, `chmod` awareness, `xray version` probe, SHA-256).
* `IProcessRunner` + `SystemProcessRunner` (bounded-channel output, process-group/Job-Object kill-on-close, `TimeProvider`-based timeouts).
* `IXrayConfigGenerator` with typed DTOs and **golden files** for: proxy-only, TUN IPv4, TUN dual-stack, VLESS+REALITY+vision, VMess+ws+tls.
* `xray run -test` pre-flight + atomic config promotion.
* AC: `myvpn --check-config <profile>` exits non-zero with `config.rejected_by_core` on a bad config and 0 on a good one; a real Xray launch passes a loopback SOCKS probe; no orphan after `SIGKILL` of the CLI.

**Phase 2 — supervision & state (2-3 days)**
* `IXrayProcessSupervisor` + `XrayRestartPolicy` (exit 23 → Faulted, backoff, restart-loop detection) wired to `VpnStateMachine`.
* Readiness + periodic health probe; `Degraded`/`Reconnecting` transitions.
* AC: killing the Xray process by PID produces `Reconnecting` → `Connected` (policy-compliant) or `Faulted` after N failures, with the kill switch concept kept engaged; unit tests cover the policy decision table without sleeping.

**Phase 3 — subscriptions (3 days)**
* `IShareLinkParser` for VLESS, VMess (both forms), Trojan, Shadowsocks, SOCKS/HTTP; `ISubscriptionPayloadReader` strategies: base64 list, plain list, SIP008; per-line structured errors; filters; dedupe; update-interval scheduling.
* SSRF/size guards; UA default `MyVpn/<version>`; header validation.
* AC: table-driven tests over a corpus of real share links (round-trip write→parse), plus a fake HTTP handler test for the fetch/update path; importing a 500-entry subscription reports exact per-line errors.

**Phase 4 — geo data (2 days)**
* `IGeoAssetManager` implementation: inspect (absolute-path enforcement), download with manifest SHA-256, `GeoAssetValidator` gate, atomic install, backup/rollback, and `GeoRuleAvailability` plumbing into the generator.
* AC: installing a truncated/HTML payload fails with `geodata.corrupt`/`geodata.checksum_mismatch` and leaves the previous file intact; a config that references `geoip:cn` is generated only while the asset is valid.

**Phase 5 — platform plans (4-5 days, parallelisable)**
* `NetworkPlan` value objects + pure renderers for nftables (Linux), WFP/PowerShell (Windows), PF anchor (macOS); executors behind `IPrivilegedHost`.
* `ISystemProxy` capture/apply/restore; `ITunDeviceManager` (+ `XRAY_TUN_FD` lease) ; route manager; DNS configurator.
* AC: renderer unit tests (golden text) + validation of nftables syntax with `nft -c -f` (as the existing `docs/research/_checks/validate.sh` already demonstrates for design snippets); applying and restoring leaves the system byte-identical in a VM test.

**Phase 6 — service + IPC (3 days)**
* `MyVpn.Service` host, `MyVpn.Ipc` contract (typed commands only), peer-credential verification, timeouts, message-size caps.
* AC: end-to-end test where a fake UI client connects over the socket and drives connect/disconnect/status with a fake privileged host; unauthorized peer is rejected with `ipc.unauthorized`.

**Phase 7 — Avalonia UI (5 days)**
* Generic host + DI, `MainViewModel` bound to `VpnStateMachine`, Servers/Subscriptions/Routing/DNS/Diagnostics surfaces, theming + localization JSON, single-writer settings store, OS-keystore secret storage.
* AC: UI never references a privileged or process API (enforced by an architecture test using `NetArchTest`-style reflection over referenced assemblies); language switch takes effect without restart; simulated Xray failure shows an actionable, localized state.

**Phase 8 — packaging & release (2-3 days)**
* Artifacts per OS; bundled Xray binary + `licenses/XRAY-LICENSE` (MPL-2.0); geo manifest + attribution; signed manifests; `artifacts/manifest.json` with versions and SHA-256.
* AC: a clean VM install connects via TUN; `licenses/` contains Xray + geo notices; the update path verifies the manifest signature and rejects a tampered archive.

Rough total: ~25-30 focused engineer-days, with Phases 1-2 being the critical path.

---

## 5. Files / modules affected (target layout `src/MyVpn.*`)

Only **new or extended** files are listed; the existing scaffold is respected. (I created none of these — this is the implementation map.)

**`src/MyVpn.Core/`** (extend)
* `Domain/XrayRestartPolicy.cs` (new) — pure decision table for crash handling.
* `Domain/TunOptions.cs` (new) — documented TUN inbound shape.
* `Domain/NetworkPlan.cs` (new) — platform-neutral desired network state (+ `RoutePlan`, `KillSwitchPlan`, `DnsPlan`, `SystemProxyPlan`).
* `Geo/*` — existing `GeoAssetValidator`/`GeoDataStatus`/`GeoRuleAvailability` are reused as-is (already implemented).
* `Results/ErrorCodes.cs` (extend) — already contains all `xray.*`, `geodata.*`, `subscription.*`, `ipc.*`, `platform.*` codes needed; add only if a new failure mode appears.

**`src/MyVpn.Application/`** (new content; currently empty)
* `Ports/Xray/IXrayBinaryLocator.cs`, `IXrayConfigGenerator.cs`, `IXrayProcessSupervisor.cs`, `XrayLaunchSpec.cs`, `XrayConfigRequest.cs`.
* `Ports/Process/IProcessRunner.cs`, `IProcessHandle.cs`, `ProcessStartSpec.cs`.
* `Ports/Subscriptions/ISubscriptionService.cs`, `IShareLinkParser.cs`, `ISubscriptionPayloadReader.cs`, `SubscriptionSource.cs`.
* `Ports/Geo/IGeoAssetManager.cs`, `GeoAssetManifestEntry.cs`.
* `Ports/Platform/ISystemProxy.cs`, `ITunDeviceManager.cs`, `IPrivilegedHost.cs`.
* `Ports/Settings/IAppSettingsStore.cs`, `IProfileRepository.cs`, `ISecretStore.cs`.
* `UseCases/ConnectProfile.cs`, `Disconnect.cs`, `SwitchProfile.cs`, `UpdateSubscriptions.cs`, `UpdateGeoData.cs`, `RunDiagnostics.cs` (each a small class orchestrating ports, returning `Result`/`Result<T>`).
* `Facade/IMyVpnServiceFacade.cs` (implemented in-process or over IPC — the UI's only dependency).

**`src/MyVpn.Infrastructure/`** (new content; currently empty)
* `Xray/XrayBinaryLocator.cs`, `XrayConfigGenerator.cs` (+ `XrayConfig/` DTOs and per-protocol builders), `XrayConfigPreflight.cs` (`run -test`), `XrayProcessSupervisor.cs`, `XrayLogPump.cs`, `SystemProcessRunner.cs`, `XrayHealthProbe.cs`.
* `Geo/GeoAssetManager.cs`, `GeoAssetDownloader.cs`, `GeoAssetManifest.cs`.
* `Subscriptions/SubscriptionService.cs`, `HttpSubscriptionFetcher.cs`, `Parsers/{Vless,Vmess,Trojan,Shadowsocks,Socks}ShareLinkParser.cs`, `Payload/{Base64ShareLinkList,PlainShareLinkList,Sip008,WireGuardConf}Strategy.cs`.
* `Settings/JsonSettingsStore.cs`, `SettingsMigrations.cs`, `SecretStores/{Dpapi,LibSecret,Keychain}SecretStore.cs`, `Profiles/SqliteProfileRepository.cs` (or JSON if a DB is not justified).
* `Diagnostics/DiagnosticsBundle.cs`, `SecretRedactor.cs`.

**`src/MyVpn.Platform.Abstractions/`** (new content; currently empty)
* `Plans/*` (value objects) and `Renderers/{NftablesRenderer, WfpRenderer, PfAnchorRenderer}.cs` — pure functions + golden tests.
* Capability interfaces exactly as the project comment enumerates: `IKillSwitch`, `IRouteManager`, `IDnsConfigurator`, `IProcessRouter`, `ISystemProxy`, `IPrivilegedHost`, `ITunDeviceManager`.

**`src/MyVpn.Platform.{Linux,Windows,MacOS}/`** (new content) — thin executors only: `Linux/NftablesExecutor.cs`, `Linux/SystemdUnitInstaller.cs`, `Linux/LinuxTunDeviceManager.cs`, `Linux/GnomeKdeSystemProxy.cs`; `Windows/WfpExecutor.cs`, `Windows/WinInetSystemProxy.cs`, `Windows/WindowsServiceInstaller.cs`, `Windows/WintunDeviceRecovery.cs`; `MacOS/PfAnchorExecutor.cs`, `MacOS/ScutilSystemProxy.cs`, `MacOS/LaunchdInstaller.cs`, `MacOS/UtunDeviceManager.cs`.

**`src/MyVpn.Ipc/`** — `Contracts/*.cs` (typed request/response records), `Transport/{UnixSocketServer, NamedPipeServer, PeerCredentials}.cs`, `Client/IpcServiceFacade.cs`.

**`src/MyVpn.Service/`** — `Program.cs`, `VpnWorker.cs`, `Handlers/{ConnectHandler, DisconnectHandler, StatusHandler}.cs`, `install/{myvpn.service, launchd plist, Windows service}.{tmpl}`.

**`src/MyVpn.UI/`** — `Program.cs`, `App.axaml(.cs)`, `Composition/ServiceCollectionExtensions.cs`, `ViewModels/{Main, Servers, Subscriptions, Routing, Dns, Diagnostics, Settings}ViewModel.cs`, `Views/*.axaml`, `Localization/{ILocalizer,JsonLocalizer,TranslateExtension}.cs`, `Locales/{en,ru,zh-Hans}.json`, `Theming/ThemeService.cs`, `Converters/*`.

**`src/MyVpn.Cli/`** — `Program.cs`, `Commands/{Connect,Diagnose,CheckConfig,ImportSub}Command.cs` (headless driver used by integration tests; the project comment already specifies this).

**Repo-level** — `docs/adr/` entries for: TUN-FD vs in-core TUN creation; exit-23 restart semantics; geo-data download-not-bundle; sing-box exclusion. `.github/workflows/ci.yml` (`build`, `test`, `license-scan`, `no-derived-code`). `artifacts/manifest.json` schema.

---

## 6. Tests

**Unit (no OS, no network, no timers)**
* `XrayRestartPolicy` decision table: exit 0 / 23 / crash after short uptime / crash after long uptime / failure-count boundary. No `Task.Delay`.
* Config generator golden files (approval-style) for: proxy-only; TUN IPv4; TUN dual-stack with `Ipv6Mode` variants; VLESS+REALITY+vision; VMess+ws+tls; SOCKS inbound with LAN enabled; fragment/packet-encoding options. Assert **documented key casing** (lowercase `mtu`) and that `XRAY_LOCATION_ASSET` is absolute.
* `GeoRuleAvailability` gating: no `geoip:`/`geosite:` may appear in generated JSON when the asset is not `Valid`; fallback rule set emitted instead.
* Share-link parsers: round-trip (`Parse(Write(p))` == `p`) and a corpus of malformed/hostile inputs (truncated base64, missing `pbk` for REALITY, `type=tcp` alias → `raw`, IPv6 literal hosts, percent-encoded remarks, CRLF endings, BOM).
* Payload strategies: base64 blob, plain list, SIP008, mixed base64/plain, oversized payload rejection, no-sing-box rejection.
* Subscription URL/header validation, filter regex, dedupe, per-line error aggregation.
* Settings store: atomic write (kill between temp write and rename), migration from a v1 JSON fixture, single-writer concurrency test, secret redaction.
* `GeoAssetValidator` (already exists) — extend with an HTML-error-page payload, a truncated protobuf, a wrong-magic file, and a valid minimal fixture; the code in `src/MyVpn.Core/Geo/` already anticipates these.
* Pure platform renderers: nftables text golden files; WFP descriptor shape; PF anchor text; `CidrBlock` subtraction for route exclusions (already covered by `CidrBlock` tests).
* Architecture tests: `MyVpn.UI` must not reference `MyVpn.Platform.*` or `System.Diagnostics.Process`; `MyVpn.Core`/`MyVpn.Application` must not reference Infrastructure; the IPC contract must contain no `string Command`/`string RawConfig` members.

**Integration (may spawn real processes; must work unprivileged in CI)**
* Real Xray, real config, loopback SOCKS inbound only (no TUN): fetch a known URL through the proxy against a local test HTTP server; assert traffic counters from the Xray metrics endpoint (`/debug/vars`).
* `xray run -c … -test` pre-flight: assert exit 0 for good config, non-zero + captured stderr for a deliberately broken config, and that no process is left behind.
* Crash/restart: start, `kill -9` the child, assert state transitions and no orphan; assert `Faulted` for an exit-23 scenario.
* Orphan sweep: start via the launcher, SIGKILL the parent, assert the child dies (PDEATHSIG/process-group/Job Object).
* Subscription end-to-end with a local HTTP server: base64 list, SIP008, per-line errors, update-interval scheduling with a fake `TimeProvider`.
* Geo end-to-end: serve a good `.dat` fixture and a corrupt one; assert install/rollback and that Xray starts with `geoip:cn` only in the good case.
* IPC end-to-end: unauthorized peer rejected, oversized message rejected, happy-path connect/status/disconnect against a fake privileged host.

**Platform / VM (privileged, nightly, matrix)**
* TUN connect on Linux (nftables), Windows (WFP/Wintun), macOS (PF/utun) in throwaway VMs: after connect, assert (a) default route via the tunnel, (b) no IPv6 leak with `Ipv6Mode.DisableWhileConnected`, (c) DNS goes through the tunnel, (d) on simulated core crash the kill switch stays engaged and no packet escapes.
* System-proxy capture/restore: assert exact restoration on GNOME, KDE, and an unsupported WM (must report `platform.unsupported`, not silently succeed).
* Updater: tampered archive rejected (`update.checksum_mismatch`), zip-slip entry (`../../x`) rejected, valid archive installs and rolls back on failure.

**Non-functional**
* Bounded log channel: 100 k lines from a chatty fake core must not exceed the configured memory ceiling.
* Startup budget: cold start to `Connected` (proxy mode) under a documented threshold; measure in CI and trend it.
* `license-scan` CI job + `no-derived-code` script (Phase 0) as release gates.

**Explicitly out of scope for tests**: any sing-box path (forbidden as a network core), and any test that requires the actual public internet.

---

## Appendix A — Evidence index

Local paths are relative to `/tmp/v2rayN/v2rayN/`; URLs are the upstream equivalents on `master`.

| Claim | Evidence |
|---|---|
| Project list, TFMs, versions | `v2rayN.sln`, `v2rayN.slnx`, `Directory.Build.props`, `Directory.Packages.props`, each `.csproj` |
| GPL-3.0-only + no additional terms | `/tmp/v2rayN/LICENSE`, `Directory.Build.props:14`; `find . -iname 'LICENSE*' -o -iname 'NOTICE*'`; `https://api.github.com/repos/2dust/v2rayN` |
| Xray binary discovery/args/env | `ServiceLib/Manager/CoreInfoManager.cs:32-51,149-171`; `ServiceLib/Global.cs:90-93` |
| Process start/capture/stop | `ServiceLib/Services/ProcessService.cs:24-54,56-71,73-117,119-143`; `ServiceLib/Manager/CoreManager.cs:305-363` |
| No restart on crash | `ProcessService.cs:132-142`; grep `HasExited|RestartCore` (only start-time checks in `CoreManager.cs:196,356`) |
| Windows Job Object kill-on-close | `ServiceLib/Services/WindowsJobService.cs:15-18`; `CoreManager.cs:365-376` |
| Linux sudo launch + kill | `ServiceLib/Manager/CoreAdminManager.cs:32-103`; `ServiceLib/Common/FileUtils.cs:237-252` |
| `XRAY_LOCATION_ASSET` semantics (upstream) | `https://xtls.github.io/en/config/env.html` |
| `xray run -c … -test`, exit 23 | `https://github.com/XTLS/Xray-core/blob/main/main/run.go` |
| TUN inbound fields (upstream, lowercase `mtu`) | `https://xtls.github.io/en/config/inbounds/tun.html`; contrast `ServiceLib/Sample/SampleTunInbound` |
| TUN generation logic | `ServiceLib/Services/CoreConfig/V2ray/V2rayInboundService.cs:56-135` |
| Xray stats via `/debug/vars` | `ServiceLib/Services/Statistics/StatisticsXrayService.cs`; `V2rayStatisticService.cs` |
| Geo paths/download/validation gap | `ServiceLib/Services/UpdateService.cs:140-150,370-414,534-590`; `ServiceLib/Global.cs:8,179-184`; `package-debian.sh` (`download_geo_assets`, `unify_geo_layout`) |
| Subscription download/UA/proxy fallback | `ServiceLib/Handler/SubscriptionHandler.cs:60-195`; `ServiceLib/Services/DownloadService.cs:178-315`; `ServiceLib/Common/Utils.cs:866-880` |
| Subscription metadata/interval | `ServiceLib/Models/Entities/SubItem.cs`; `ServiceLib/Manager/TaskManager.cs:93-135` |
| Subscription parsing pipeline | `ServiceLib/Handler/ConfigHandler.cs:1630-1707,2040-2138`; `ServiceLib/Handler/Fmt/{FmtHandler,BaseFmt,VmessFmt,VLESSFmt}.cs` |
| Stringly-typed profile model | `ServiceLib/Models/Entities/ProfileItem.cs:127-147,149-152,173-218` |
| Config snapshot / validation | `ServiceLib/Models/CoreConfigs/CoreConfigContext.cs`; `ServiceLib/Handler/Builder/{CoreConfigContextBuilder,NodeValidator}.cs` |
| MVC/DI/theming/i18n/settings | `v2rayN.Desktop/{Program.cs,App.axaml,App.axaml.cs,Common/SimpleViewLocator.cs,ViewModels/ThemeSettingViewModel.cs}`; `ServiceLib/Base/MyReactiveObject.cs`; `ServiceLib/Manager/AppManager.cs:63-96,165-169`; `ServiceLib/Handler/ConfigHandler.cs:18-233`; `ServiceLib/Helper/SqliteHelper.cs:12`; `ServiceLib/Resx/*` |
| Sysproxy per OS | `ServiceLib/Handler/SysProxy/{SysProxyHandler,ProxySettingLinux,ProxySettingOSX,ProxySettingWindows}.cs`; `ServiceLib/Sample/proxy_set_linux_sh` |
| Updater without verification / zip-slip-ish | `AmazTool/UpgradeApp.cs` (whole file), `AmazTool/Utils.cs:17-25`; grep `sha256|gpg|signature|hash` → no matches |
| Promotion constant | `ServiceLib/Global.cs:11` (decodes to `https://9.234456.xyz/abc.html`); no references found |
| Xray MPL-2.0 | `https://api.github.com/repos/XTLS/Xray-core/license` |
| Loyalsoldier geo GPL-3.0 | `https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/license` |
| v2fly geo CC-BY-SA 4.0 / MIT | `https://raw.githubusercontent.com/v2fly/geoip/master/LICENSE`, `https://raw.githubusercontent.com/v2fly/domain-list-community/master/LICENSE` |
| GlobalHotKeys WTFPL v2 | `https://github.com/2dust/GlobalHotKeys` `LICENSE` (cloned to `/tmp/ghk`) |

## Appendix B — UNVERIFIED items

1. **Runtime behaviour of anything in this report.** No `dotnet` SDK in this environment; no Xray binary was executed. All statements are static-reading or documentation-based.
2. **`Global.PromotionUrl` usage.** Defined at `Global.cs:11`; no reference found in the clone. Intended use unknown (no network call was made to that host).
3. **Licences of `Loyalsoldier/geoip`, `MetaCubeX/meta-rules-dat`, `2dust/sing-box-rules`.** GitHub API rate-limited after two calls; not verified.
4. **Exact Xray error text/exit behaviour when `geoip:`/`geosite:` assets are missing or corrupt.** Inferred from Xray's config-load path; not executed.
5. **Whether Xray accepts `MTU` vs `mtu` in all supported versions.** The sample's casing works because Go's `encoding/json` is case-insensitive; only the source is documented, the tolerance is an inference.
6. **GitHub's licence label vs. legal reading for v2rayN.** GitHub reports the family-level `GPL-3.0`; my "GPL-3.0-only" conclusion rests on the missing "or later" text and the `GPL-3.0` SPDX expression. This is an engineering reading, not legal advice; treat any actual code-reuse decision as requiring counsel.
7. **v2rayN's WPF-specific behaviour** (I read the project file and file list but did not study the WPF XAML in depth, since MyVpn is Avalonia-only).
8. **The `ServiceLib.Sample.*` embedded resources' provenance** beyond "authored in this repository" — i.e. I did not verify whether individual sample JSON files were themselves derived from upstream Xray sample configs.
