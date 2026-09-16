# 03 — Native Xray TUN Inbound: Capabilities, Limits and MyVpn Design

**Status:** research complete — primary sources pinned, no `src/` changes made.
**Author:** Xray TUN / Inbound Research Agent
**Scope:** can MyVpn use the *native* Xray-core TUN inbound as the sole network core (no sing-box)?

## Pinned sources

| Source | Revision | Used for |
|---|---|---|
| [XTLS/Xray-core](https://github.com/XTLS/Xray-core) `main` | `c412e77a9b712082ac9ebf27fa793951cb5a7d85` (2026-09-12) | config schema, per-OS code |
| Xray-core latest release | [`v26.9.9`](https://github.com/XTLS/Xray-core/releases/tag/v26.9.9) (2026-09-08) | shipped behaviour, version floors |
| [XTLS/Xray-docs-next](https://github.com/XTLS/Xray-docs-next) (source of <https://xtls.github.io>) `main` | `c6168022e118e3a65b4491edb7409063459f937f` (2026-09-16) | official config docs |
| Linux kernel | [`Documentation/networking/tuntap.txt`](https://www.kernel.org/doc/Documentation/networking/tuntap.txt) | Linux TUN device + `CAP_NET_ADMIN` |
| [wintun.net](https://www.wintun.net/) | Wintun 0.14.1 | Windows driver model |

Per-capability evidence (release tags, PR numbers, source files) is cited inline. Anything I could not confirm from a primary source is marked **UNVERIFIED**.

---

# 1. Findings

## 1.1 Which Xray-core versions introduced the native TUN inbound

**The native TUN inbound first shipped in Xray-core `v26.1.13` (published 2026-01-13).**

Evidence:

* Implementation PR: [`XTLS/Xray-core#5464`](https://github.com/XTLS/Xray-core/pull/5464) — *"Proxy: Add TUN inbound for Windows & Linux, including Android"*, merged **2026-01-07T22:05:09Z**, merge commit `39ba1f7952197ca99e8e99fb86cfa892fe2bc527`.
* File-existence proof across tags:
  * `https://raw.githubusercontent.com/XTLS/Xray-core/v25.12.8/proxy/tun/config.proto` → **HTTP 404** (feature absent)
  * `https://raw.githubusercontent.com/XTLS/Xray-core/v26.1.13/proxy/tun/config.proto` → **HTTP 200** (feature present)
* `v26.1.13` is the first release published after the merge; its release body is a one-line pointer to `v26.1.23` (Xray collapses some release notes), so the *tag content* is the authoritative evidence, not the release text.

The proto at `v26.1.13` was already this (see [`proxy/tun/config.proto`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/config.proto)):

```proto
message Config {
  string name = 1;
  uint32 MTU = 2;
  uint32 user_level = 3;
}
```

### Feature/field timeline (all verified by fetching the file at each tag)

| Release | Date | What landed there | Evidence |
|---|---|---|---|
| `v25.12.8` | 2025-12-08 | — no TUN | `proxy/tun/` = 404 |
| **`v26.1.13`** | **2026-01-13** | **TUN inbound: Windows, Linux, Android. Fields `name`, `mtu`, `userLevel` only.** | `proxy/tun/config.proto` @ `v26.1.13` |
| `v26.1.18` | 2026-01-18 | macOS/Darwin support (`tun_darwin.go` appears) | PR [#5559](https://github.com/XTLS/Xray-core/pull/5559); `tun_darwin.go` HTTP 404 @ `v26.1.13`, 200 @ `v26.1.18` |
| `v26.1.23` | 2026-01-23 | iOS support | PR [#5612](https://github.com/XTLS/Xray-core/pull/5612) |
| `v26.4.13` | 2026-04-13 | `gateway`, `dns`, `autoSystemRoutingTable`, `autoOutboundsInterface` added — **but `mtu` is `repeated uint32` in this tag (see risk R-1); do not ship this version.** | `proxy/tun/config.proto` @ `v26.4.13` = `repeated uint32 MTU = 2;`, `infra/conf/tun.go` = `MTU []uint32 \`json:"mtu"\``, `tun_linux.go` = `options.MTU[0]` |
| **`v26.4.15`** | **2026-04-15** | `mtu` back to scalar `uint32`; FreeBSD support (PR [#5891](https://github.com/XTLS/Xray-core/pull/5891)) | `config.proto` @ `v26.4.15` = `uint32 MTU = 2;`; `tun_freebsd.go` 404 @ `v26.4.13`, 200 @ `v26.4.15` |
| `v26.7.28` | 2026-07-28 | `desc` field (Windows Wintun adapter description), random `utunNN` default name | PR [#6486](https://github.com/XTLS/Xray-core/pull/6486) (2026-07-17); `desc = 8;` absent @ `v26.7.11`, present @ `v26.7.28` |
| `v26.9.8` | 2026-09-08 | `autoSystemRoutingTable` + `autoOutboundsInterface` on FreeBSD | commit `c1958dba04ba` *"TUN inbound: Support `autoSystemRoutingTable` and `autoOutboundsInterface` on FreeBSD"* (2026-08-27) — commit SHA from the GitHub commits-for-path API; PR number not recorded in the commit subject |
| **`v26.9.9`** | **2026-09-08** | Windows refinements (adapter-ready retry loop, default-route interface discovery) | PR [#6478](https://github.com/XTLS/Xray-core/pull/6478); `v26.9.9/proxy/tun/tun_windows.go` is byte-identical (md5 `74dd1cafe02c593dabbdbf7132838fe2`) to `main` |

**Minimum version recommendation for MyVpn: `v26.9.9`.** Rationale: it is the newest release, it is the first with the Windows retry fixes, and it is the only version line where every documented field exists *and* `mtu` is a scalar. Absolute floor if only basic TUN is needed is `v26.1.13`, but a client that generates one config shape for all platforms cannot target it.

## 1.2 Authoritative config schema

The TUN inbound is `"protocol": "tun"` and its fields live under `"settings"`. The single authoritative schema is [`proxy/tun/config.proto`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/config.proto) bound to JSON by [`infra/conf/tun.go`](https://github.com/XTLS/Xray-core/blob/main/infra/conf/tun.go) (`TunConfig`), documented in [`docs/en/config/inbounds/tun.md`](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/inbounds/tun.md).

### `settings` fields — the complete list

There are **exactly eight**. No more.

| JSON key | proto | Go type | Default (from `TunConfig.Build`) | Meaning | Effective platforms |
|---|---|---|---|---|---|
| `name` | `name = 1` | `string` | empty → auto-generated `utunN`, `N` random in `[10,1024]` (`GetAvailableTunName`, `infra/conf/tun.go:64-98`) | Interface name. Linux: any valid ifname (`xray0` in the docs' systemd example). macOS: must match `utunN`. FreeBSD: must match `tunN`. Windows: Wintun adapter name. | all |
| `desc` | `desc = 8` | `string` | `""` → `"Wintun"` | Windows Wintun adapter description; Wintun renders it as `"<desc> Tunnel"`. Ignored on every other platform (only referenced in `tun_windows.go`). | Windows only |
| `mtu` | `MTU = 2` | `uint32` | `0` → `1500` | Interface MTU, applied via `netlink.LinkSetMTU` (Linux), `winipcfg` `NLMTU` (Windows), `setMTU` (macOS/FreeBSD), and used as the gVisor link-endpoint `deviceMTU`. | all |
| `gateway` | `gateway = 3` (repeated) | `[]string` | `[]` | **Address prefixes assigned to the TUN interface** — *not* a next-hop. Windows: every entry added as an interface address (`SetIPAddressesForFamily`). Linux: every entry added as `netlink.AddrAdd`. macOS/FreeBSD: only the **first IPv4 prefix** is used, as the utun point-to-point *remote* address; the *local* address becomes the next address in that prefix. | Windows, Linux, macOS, FreeBSD |
| `dns` | `DNS = 4` (repeated) | `[]string` | `[]` | **Bare IP addresses** (not CIDR) set as the interface's DNS servers via `winipcfg.LUID.SetDNS`. **Windows only** — Linux and macOS do not touch system DNS. | Windows only |
| `userLevel` | `user_level = 5` | `uint32` | `0` | Policy level for connections accepted from the TUN. Drives `policy.levels[].timeouts.connectionIdle` and stats/user identity (`handler.go`: `IdleTimeout: policyManager.ForLevel(config.UserLevel)…`, `User: &protocol.MemoryUser{Level: config.UserLevel}`). | all |
| `autoSystemRoutingTable` | `auto_system_routing_table = 6` (repeated) | `[]string` | `[]` | CIDR destinations Xray **adds to the OS routing table on start and removes on shutdown**. Linux: `netlink.RouteAdd{Dst: <cidr>, LinkIndex: tun, Priority: 1}`, on-link (no gateway). Windows: `winipcfg.RouteData{Destination: <cidr>, NextHop: 0.0.0.0/::, Metric: 0}` + interface `UseAutomaticMetric=false, Metric=0`. macOS: route add via `AF_ROUTE`; **`0.0.0.0/0` is expanded into 8 more-specific routes** (see 1.7). FreeBSD: interface (on-link) routes. | Windows, Linux, macOS, FreeBSD |
| `autoOutboundsInterface` | `auto_outbounds_interface = 7` | `string` (Go `*string` in JSON, so *absent ≠ empty*) | absent → if `autoSystemRoutingTable` is non-empty, Xray forces `"auto"`; otherwise none. **`""` (explicit empty string) disables it even with routes present.** | Binds all Xray outbound sockets to a physical interface so Xray's own uplink traffic does not re-enter the TUN. `"auto"` = Xray picks the lowest-metric non-TUN default-route interface (and re-resolves it on route/interface change events). A literal interface name pins it. Implemented as a global dialer controller: Linux `unix.BindToDevice` (`SO_BINDTODEVICE`), Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF`, macOS `IP_BOUND_IF`/`IPV6_BOUND_IF`. Loopback destinations are skipped. | Windows, Linux, macOS, FreeBSD (`v26.9.8+`) |

### Inbound-level fields that also apply to `tun`

From [`infra/conf/xray.go`](https://github.com/XTLS/Xray-core/blob/main/infra/conf/xray.go) (`InboundDetourConfig`):

| JSON key | Type | Notes for `tun` |
|---|---|---|
| `protocol` | `"tun"` | Required. Registered in the **inbound** loader (`infra/conf/xray.go:35`). |
| `tag` | string | Required in practice: the tag is what routing rules and stats key off (`handler.go` reads `inbound.Tag`). |
| `settings` | object | The eight fields above. |
| `sniffing` | object | **Supported.** `InboundDetourConfig.SniffingConfig` → `ReceiverConfig.SniffingSettings`; `AlwaysOnInboundHandler` builds the sniffing request into the context and `Handler.Init` copies it onto every dispatched connection. |
| `port` / `listen` / `streamSettings` | — | **Ignored / skipped.** `InboundDetourConfig.Build` explicitly skips port validation when `protocol == "tun"` (`infra/conf/xray.go:141-145`), and `Handler.Network()` returns `[]net.Network{}`, so `AlwaysOnInboundHandler` starts the proxy directly with zero listen workers (`app/proxyman/inbound/inbound.go:181`, `app/proxyman/inbound/always.go:174-181`). The docs say the same: *"the configuration ignore required listen and port options, and never listen on any port."* |

### `sniffing` object (the real schema)

From `SniffingConfig` in `infra/conf/xray.go:56-63` and [`docs/en/config/inbound.md`](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/inbound.md):

| JSON key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Enable sniffing. |
| `destOverride` | `["http" \| "tls" \| "quic" \| "fakedns"]` | `[]` | Protocols whose sniffed domain may **replace the connection destination**. `"https"`/`"ssl"` are accepted aliases of `"tls"`; `"fakedns+others"` is accepted and maps to `"fakedns"`. |
| `domainsExcluded` | string[] | `[]` | Do not override destination for these domains. |
| `ipsExcluded` | string[] | `[]` | Do not override destination for these IPs. |
| `metadataOnly` | bool | `false` | Only metadata sniffers run (i.e. only `fakedns`). |
| `routeOnly` | bool | `false` | Use the sniffed domain **for routing only**; keep the real IP as the proxy destination. Requires `destOverride`. |

### Fields the task asked about that DO NOT EXIST — stated explicitly

I grepped the whole `main` tree. These names are **not present** anywhere in Xray-core and must not be emitted by MyVpn:

| Asked-about name | Verdict | Evidence |
|---|---|---|
| `address` (as a TUN setting) | **Does not exist.** The address field is called `gateway`. | `grep json:"address"` in `infra/conf/tun.go` — absent; only `gateway`. |
| `autoRoute` / `auto-route` | **Does not exist.** The auto-route field is `autoSystemRoutingTable`. | `infra/conf/tun.go:21`; no `autoRoute` anywhere in the tree. |
| `strictRoute` / `strict_route` | **Does not exist in Xray-core.** (This is a sing-box field.) | Case-insensitive grep for `strictroute`/`strict_route` over `*.go`, `*.proto`, `*.json` → **0 hits**. |
| `sniffingOverride` | **Does not exist.** Sniffing is configured only under the inbound's `sniffing` key. | Grep for `sniffingoverride`/`sniffing_override` over the whole tree → **0 hits**. |
| `routeOnly` as a TUN setting | **Does not exist at TUN level.** It exists only *inside* `sniffing`. | `infra/conf/xray.go:62` (`SniffingConfig.RouteOnly`); not in `TunConfig`. |
| `stack`, `autoRedirect`, `includeUid`/`excludeUid`, `endpointIndependentNat`, `udpTimeout`, `interfaceName` | **None exist.** There is no user-selectable IP stack (it is always gVisor) and no per-inbound redirect toggles. | `proxy/tun/config.proto` (8 fields, listed above). |

## 1.3 Per-OS requirements and limitations

### Windows

* **Driver:** Wintun, via the Go binding `golang.zx2c4.com/wintun` (`go.mod`: `v0.0.0-20230126152724-0fa3db229ce2`). Xray **does not embed the driver**: the official README states *"wintun.dll specific for your Windows/arch must be present next to Xray.exe binary"* ([`proxy/tun/README.md`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/README.md), "WINDOWS SUPPORT"). wintun.net distributes **signed** DLLs for AMD64/X86/ARM64/ARM32 and states the signed DLLs are *"the only supported way of distributing Wintun"*.
* **What Xray does:** `wintun.CreateAdapter(name, desc, md5-guid(name))`, `StartSession(8 MiB)`; sets interface addresses from `gateway`, routes from `autoSystemRoutingTable`, `NLMTU` from `mtu`, `UseAutomaticMetric=false`/`Metric=0` when routes exist, and DNS via `SetDNS`. On close it flushes routes/IPs/DNS, ends the session and closes the adapter.
* **Interface index is not stable** across restarts (README says so explicitly) — MyVpn must never persist the Wintun ifindex.
* **IPv6 caveat (official README):** the adapter gets an autoconfigured IPv6 address, but *"ipv6 is not possible until the interface has any routable ipv6 address"*; a link-local address will not accept external traffic. A static private prefix (e.g. `fc00::a:b:c:d/64`) must be assigned via `gateway`.
* **Admin rights:** Xray's README does **not** state a privilege requirement. **UNVERIFIED from Xray/wintun primary text.** In practice creating a Wintun adapter, reconfiguring interface addresses/routes and setting DNS require elevation on Windows; MyVpn should assume "elevated helper/service required" and fail with `ErrorCodes.PrivilegeNotElevated` rather than rely on the docs.
* **DNS blackhole PR is NOT in shipped code — important:** PR [#6478](https://github.com/XTLS/Xray-core/pull/6478)'s description claims it adds five WFP rules on Windows including *"blackhole 53 udp"* and *"blackhole 53 tcp"*. The **merged diff** (`https://github.com/XTLS/Xray-core/pull/6478.diff`) touches only `proxy/tun/tun_windows.go` and contains **no WFP code**; `grep -ri "wfp\|fwpm\|firewall"` over the entire `main` tree returns **0 hits**; none of the 37 commits that ever touched `proxy/tun/` mentions WFP. **Conclusion: there is no Xray-side DNS firewalling on Windows. MyVpn must implement DNS-leak prevention itself.** (UNVERIFIED whether a fork/PR carries it.)

### Linux

* **Xray creates the interface itself.** `tun_linux.go:open()` does `unix.Open("/dev/net/tun", O_RDWR)` + `ioctl(TUNSETIFF)` with `IFF_TUN|IFF_NO_PI`, then `netlink.LinkSetMTU`, and in `Start()` `LinkSetUp`, addresses, routes.
* **Privileges:** the kernel's own documentation states *"CAP_NET_ADMIN is required for creating network devices or for connecting to network devices which aren't owned by the user in question"* ([tuntap.txt](https://www.kernel.org/doc/Documentation/networking/tuntap.txt) §2). `/dev/net/tun` (char 10:200) must exist; the device disappears when the fd closes (*"When the program closes the file descriptor, the network device and all corresponding routes will disappear"* — same doc), which is exactly Xray's cleanup model.
* **Xray also sets `SO_BINDTODEVICE`** for `autoOutboundsInterface` (`setinterface` → `unix.BindToDevice`), which requires `CAP_NET_RAW` or root.
* **Pre-created fd path:** if `XRAY_TUN_FD` (`common/platform/platform.go:27` → `TunFdKey = "xray.tun.fd"`; env names accepted are `xray.tun.fd` and the normalised `XRAY_TUN_FD`) is set, `openFromEnv` validates fd ≥ 3, that `TUNGETIFF` shows `IFF_TUN`, that `IFF_NO_PI` is set, and that the device name equals the configured `name`. **When an fd is supplied, `ownsTun=false` and Xray does NOT set MTU, addresses or routes, and does not bring the link up** (`Start()` returns immediately) and does not tear it down. MyVpn must do all of that itself in that mode.
* **DNS:** Xray does **not** touch `/etc/resolv.conf`, `systemd-resolved` or NetworkManager. PR [#6398](https://github.com/XTLS/Xray-core/pull/6398) states this as an explicit design boundary: *"Linux 不接管系统 DNS，不修改 resolv.conf、systemd-resolved 或 NetworkManager；route 不设置 Gw，也不调整 metric"*.
* **Cleanup** removes only what Xray added (addresses + routes it recorded), sets the link down and closes the fd. `ip_forward`/NAT for LAN clients is **not** configured.

### macOS

* **Xray creates the utun itself**: `AF_SYSTEM`/`SOCK_DGRAM`/`SYSPROTO_CONTROL` + `CTLIOCGINFO` on `com.apple.net.utun_control`, then `connect(SockaddrCtl{Unit: N+1})`. The name **must** match `utunN`; `open()` returns an error otherwise.
* `gateway`: only the **first IPv4 prefix** is used. It becomes the point-to-point *remote* address; the *local* address is the next address in the prefix. Default when unset: `169.254.10.1/30`. IPv6 `gateway` entries are ignored for addressing; IPv6 routes are interface (link) routes.
* The prefix must contain a usable address **after** the gateway address, otherwise `selectDarwinGateway` errors out. For a `/32` there is no next address ⇒ rejected. A `/31` works.
* `dns` does **nothing** on macOS (README and `docs/en/config/inbounds/tun.md`: *"This option only takes effect on Windows"*).
* **Privileges:** creating a utun and adding routes requires root/`CAP_NET_ADMIN`-equivalent on macOS. Xray's docs do not spell this out. **UNVERIFIED from Xray primary text**; MyVpn should use a privileged helper.
* Cleanup: routes removed; the utun disappears when the fd is closed. In iOS/NetworkExtension fd mode (`ownsFd=false`) Xray deliberately does **not** close the fd and does not add routes/addressing.

### FreeBSD

* Implemented on `tun(4)`; required name scheme `tunN`. Gateway semantics follow macOS (first IPv4 prefix, point-to-point, next address local). Routes are **interface routes** because the tun(4) point-to-point peer address doubles as broadcast and a gateway route fails with `EACCES` (source comment in `tun_freebsd.go`).
* `autoSystemRoutingTable`/`autoOutboundsInterface` work from `v26.9.8`; the docs for the FreeBSD routing-table note are stricter than the code — the code does implement it. Prefer the code.

### Android / iOS

* **Xray does not create the interface.** The app (VpnService / NetworkExtension) creates the TUN and passes the fd via the `xray.tun.fd` / `XRAY_TUN_FD` environment variable before starting Xray. Xray then only reads/writes packets. Neither platform is a MyVpn target (desktop Avalonia client) but the mechanism matters as the *precedent* for "app owns the interface".

## 1.4 What Xray explicitly does NOT do (MyVpn must implement)

Derived from the code paths above plus [`proxy/tun/README.md`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/README.md):

| Concern | Xray TUN behaviour | MyVpn must do |
|---|---|---|
| Interface creation | Creates it on Win/Linux/macOS/FreeBSD; **does not** on Android/iOS/fd mode | Nothing extra in the normal path; everything in fd mode |
| Interface MTU | Sets it (only when it owns the tun) | Pass `mtu`; verify it actually applied |
| Interface address | From `gateway` (Win/Linux/macOS/FreeBSD) | Compute prefixes; supply them |
| **Route to the VPN server / uplink** | **Nothing. No host route, no exclusion, no loop detection.** README: *"You can't just route 0.0.0.0/0 through xray0 … resulting infinite network loop."* | Install a host route (or fwmark rule) for the server **before** the default route flip, and restore on teardown |
| Default route | Only if **you** put `0.0.0.0/0` in `autoSystemRoutingTable` | Decide full-tunnel vs split-tunnel; on Linux/Windows a `0.0.0.0/0` entry **replaces** the physical default |
| Loop prevention | Only `autoOutboundsInterface` (socket bind) — and only if configured | Always configure it, and additionally keep a server host route as a fallback |
| DNS interception | **Nothing on Linux/macOS.** Windows only assigns DNS servers to the adapter (`dns`) | Route DNS into the tun + hijack with a `dns` outbound, or run OS-level DNS redirection |
| DNS leak prevention | Nothing (the Windows WFP blackhole described in PR #6478 is **not** in shipped code) | Firewall rules / `killswitch`, and block port 53 outside the tunnel if required |
| Firewalling / kill switch | Nothing | MyVpn nftables/WFP/pf layer |
| Cleanup | Removes only the addresses/routes it added and closes its device | Restore DNS, original default route, firewall rules; remove the server host route |
| IPv6 disable | Nothing | Do not emit IPv6 `gateway`/routes **and** block IPv6 at the firewall (a v6 default route may still exist) |
| Process-level routing (per-app) | Nothing in the TUN inbound; only `routing.rules[].processName` for *routing decisions*, not for capture | OS-level per-app capture, or accept that TUN captures everything |
| ICMP beyond echo | Ignores it | Accept the limitation (see 1.7) |
| Reconnect/health | Nothing | Supervision, restart-loop detection (`ErrorCodes.XrayRestartLoopDetected`) |

## 1.5 IPv4 and IPv6

* **Supported:** both families. The gVisor stack is created with `ipv4.NewProtocol, ipv6.NewProtocol` and `tcp/udp/icmp4/icmp6` (`stack_gvisor.go:208-224`), routes `0.0.0.0/0` and `::/0` to the single NIC, and the NIC is set to spoofing + promiscuous mode.
* **Dual-stack config shape:** `gateway` and `autoSystemRoutingTable` are mixed lists; put one IPv4 CIDR and one IPv6 CIDR in each, e.g. `"gateway": ["172.19.0.1/30", "fc00::1/126"]`, `"autoSystemRoutingTable": ["0.0.0.0/0", "::/0"]`. `dns` is a mixed list of bare addresses. Windows derives `address4`/`address6` and `route4`/`route6` flags from the presence of each family and only touches the families present.
* **Disabling IPv6 (supported, but only "don't configure it"):** omit IPv6 entries from `gateway` and `autoSystemRoutingTable`, set `dns.queryStrategy` to `"UseIPv4"` (or per-server `queryStrategy`), and — critically — **block IPv6 at the OS firewall**, because Xray does not remove an existing IPv6 default route. On Windows, note that `SetDNS`/IP-interface tuning still runs for `AF_INET6` regardless of `route6`/`address6` presence (`tun_windows.go:162-192` always calls `IPInterface(family)` and `SetDNS`), so an IPv6 interface config is still written. **UNVERIFIED** whether that alone can attract traffic.
* **Selective IPv6:** put specific `::/`-prefixed CIDRs in `autoSystemRoutingTable` instead of `::/0`.
* On macOS/Solaris-style semantics the IPv6 route is an **interface route** (`RTF_GATEWAY` cleared, `RTAX_GATEWAY = LinkAddr`), not a gateway route.

## 1.6 DNS interception with Xray TUN — what is actually supported today

Official statement ([`docs/en/config/dns.md`](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/dns.md), "Built-in DNS Server"):

> **TUN/Transparent Proxy DNS Traffic Hijacking:** Combines routing with the DNS outbound to hijack DNS traffic into this module; or uses Tunnel to expose port 53 and act as a recursive DNS server.

| Option | Supported today? | Details |
|---|---|---|
| **(a) `dns` outbound + routing rule** (`"protocol": "dns"`, tag e.g. `dns-out`, rule `{"port": 53, "outboundTag": "dns-out"}`) | **YES — the recommended mechanism** | `DNSOutboundConfig` in [`infra/conf/dns_proxy.go`](https://github.com/XTLS/Xray-core/blob/main/infra/conf/dns_proxy.go); documented in [`docs/en/config/outbounds/dns.md`](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/outbounds/dns.md). Works for DNS packets arriving **through the TUN**, because the gVisor UDP/TCP handlers dispatch them into the router as normal flows. Plaintext UDP/TCP DNS only; the outbound can `rewriteNetwork`/`rewriteAddress`/`rewritePort`, and per-rule `action` ∈ `direct`/`hijack`/`drop`/`return`. Default fallback when no rule matches: **A and AAAA queries are imported into the built-in DNS module; all other query types get an empty response with RCODE 0.** |
| **(b) `fakedns` + `sniffing.destOverride: ["fakedns"]`** | **YES** | Top-level `"fakedns"` object (Go struct tag is `json:"fakeDns"`; Go's `encoding/json` matches case-insensitively, so the documented `"fakedns"` key works — use the documented spelling). The docs' canonical pattern is exactly the TUN pattern: `dns.servers = ["fakedns", …]`, an outbound `{"protocol":"dns","tag":"dns-out"}`, a routing rule `{"inboundTag":[…],"port":53,"outboundTag":"dns-out"}`, and `sniffing.destOverride:["fakedns"]` on the client-facing inbound. Warning from the docs: FakeDNS **pollutes the local DNS cache** and can cause "no network access" after Xray stops. |
| **(c) `tunnel` (dokodemo-door) inbound on port 53** as a recursive DNS front end | **YES, but it is a socket listener, not TUN capture** | [`docs/en/config/inbounds/tunnel.md`](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/inbounds/tunnel.md): `{"protocol":"tunnel","settings":{"allowedNetwork":"udp","rewriteAddress":"…","rewritePort":53}}`. It listens on a host socket; it does not capture packets sent to arbitrary DNS servers by other hosts/processes. Useful when MyVpn redirects OS DNS to `127.0.0.1:53`. |
| **(d) `dns` field in TUN `settings`** | **Partially — assignment only, Windows-only, NOT interception** | It calls `SetDNS` on the Wintun adapter. On Linux and macOS it is inert (README: *"Linux and macOS do not configure system DNS from the dns field"*; docs: *"This option only takes effect on Windows"*). It does not capture anything. |
| **(e) A dedicated DNS *inbound* protocol** | **NO — does not exist** | `"dns"` is registered only in `outboundConfigLoader` (`infra/conf/xray.go:51`). There is no `"protocol": "dns"` inbound. |
| **(f) DoH/DoT/DoQ server listener inside Xray** | **NO** | The built-in DNS is a client/resolver. The `dns` outbound is explicitly *"traditional plaintext DNS queries over UDP and TCP; non-plaintext DNS protocols such as DoH, DoT, and DoQ are not applicable to this outbound."* |
| **(g) `hijack-dns` routing rule keyword** | **NO such keyword.** The routing schema has no `hijack-dns` action. Hijacking is expressed as `"outboundTag": "<dns-outbound-tag>"` pointing at a `protocol: "dns"` outbound. | Routing rule fields are `inboundTag`, `outboundTag`/`balancerTag`, `domain`, `ip`, `port`, `network`, `protocol`, `processName`, etc. (`infra/conf/router.go:122-146`). |
| **(h) Non-A/AAAA DNS over the built-in module** | **Limited** | Only A and AAAA are handled; CNAMEs are followed until an A/AAAA appears; other query types do not enter the built-in DNS. |

**Design consequence for MyVpn:** the DNS path must be *route + hijack*: assign the adapter a synthetic resolver address (Windows `dns`), ensure it is routed into the tun via `autoSystemRoutingTable`, and add a priority-one routing rule `port 53 → dns-out`. On Linux/macOS MyVpn must additionally take over system DNS (resolv.conf / `systemd-resolved` / `scutil`) because Xray will not.

## 1.7 TCP, UDP, ICMP and the loop problem

**TCP** — the gVisor stack performs the three-way handshake **locally** (`tcp.NewForwarder` → `r.CreateEndpoint`, then `r.Complete(false)`), then hands a `gonet.TCPConn` to the dispatcher. Consequences, quoted from the official README "LIMITATION":

> * Connections are established to any host, as connection success is only a mark of successful accepting packet for proxying. Hosts that are not accepting connections or don't even exists, will look like they opened a connection (SYN-ACK), and never send back a single byte, closing connection (RST) after some time. This is the side effect of the whole process actually being a proxy, and not real network layer 3 vpn.

So **"TCP connect succeeded" must never be used as a health/reachability signal** by MyVpn. Tuning in `createStack`: cubic congestion control, SACK, moderate RX buffers, **RACK/TLP recovery disabled** (`TCPRecovery(0)`, PR [#5600](https://github.com/XTLS/Xray-core/pull/5600)) to avoid stalls.

**UDP** — not the stock gVisor forwarder. A custom `udpConnectionHandler` (`udp_fullcone.go`) keys connections by the **source address:port only** (`udpConns[src]`), giving **FullCone NAT** semantics (PR [#5509](https://github.com/XTLS/Xray-core/pull/5509), refined in [#5526](https://github.com/XTLS/Xray-core/pull/5526) and [#6747](https://github.com/XTLS/Xray-core/pull/6747)). Return packets are rebuilt and injected with `WriteRawPacket`. The egress queue is bounded at 1024 packets; overflow is **silently dropped** with a debug log (`udp_fullcone.go`). UDP checksums are computed; the Linux/macOS/android endpooints set `RXChecksumOffload: true`.

**ICMP** — Echo request/reply **only**, and *"ICMP Echo replies are generated locally by the TUN stack; they do not validate real remote ICMP reachability"* (README; PR [#6015](https://github.com/XTLS/Xray-core/pull/6015) "Reply fake pong to ICMP ping"). All other ICMP types are ignored. **`ping` succeeding is not evidence the tunnel works.**

**Performance** — GRO/GSO offload is intentionally not implemented (PR #5464 body). No fragmentation/PMTU discovery logic in the TUN inbound. **UNVERIFIED:** behaviour for fragmented UDP and for PMTU black holes.

### The routing-loop problem and `autoSystemRoutingTable` asymmetry (important)

Routing `0.0.0.0/0` into the tun without protection makes Xray's own uplink packets re-enter the tun. The three official approaches in `proxy/tun/README.md` are:

1. A **host route** for the uplink server via the physical gateway *before* the default route flip:
   ```
   ip route add 123.123.123.123/32 via <provider internet gateway ip>
   ip route add 0.0.0.0/0 dev xray0
   ```
   (README notes this becomes brittle: it re-encodes the gateway, the uplink IP, etc.)
2. Split-tunnel: only specific networks go through `xray0`, keeping the physical default route intact.
3. Two route tables plus `ip rule`s; either "xray0 is the default in table 1001, mark protected flows into it" or "move the real default to table 1000 and fw-mark the Xray process".

The new, preferred mechanism is `autoOutboundsInterface` (`v26.4.15+`), which binds **all** outbound sockets to the physical interface and thus removes the need for a host route. Per the docs it is *"equivalent to automatically setting sockopt.interface for all outbounds (it also additionally covers some requests that cannot have outbound settings configured, such as the various local modes of the built-in DNS)"* and it *"can be overridden by manually set sockopt."* Loopback destinations are skipped (`handler.go`), which was the subject of PR #6276.

**Critical platform asymmetry MyVpn must encode:**

* **macOS:** `0.0.0.0/0` in `autoSystemRoutingTable` is **not** installed as a default route. `buildDarwinSystemRoutes` expands it via `darwinProtectedDefaultRoutes` into **8 more-specific routes** — `1.0.0.0/8`, `2.0.0.0/7`, `4.0.0.0/6`, `8.0.0.0/5`, `16.0.0.0/4`, `32.0.0.0/3`, `64.0.0.0/2`, `128.0.0.0/1` — whose union is `1.0.0.0–255.255.255.255`, deliberately leaving `0.0.0.0/8` to the pre-existing default route. IPv6 does the analogue with `::/8` left out. **The physical default route is preserved.**
* **Linux:** `setSystemRoutes` installs the CIDR **as given**, `Priority: 1`, no gateway. `0.0.0.0/0` therefore *becomes* the default route (metric 1) and **replaces the physical default** for anything with a worse metric.
* **Windows:** routes are installed with `Metric = 0` and `UseAutomaticMetric = false`, i.e. maximum preference — again **replacing** the effective default.
* **FreeBSD:** interface routes, `0.0.0.0/0` as given.

So on Linux/Windows an unprotected `0.0.0.0/0` is genuinely loop-prone; on macOS it is defended by construction. MyVpn must therefore **require** `autoOutboundsInterface` (or explicit per-outbound `sockopt.interface`) whenever a default route is auto-installed, and should keep a server host route as a second line of defence on Linux/Windows.

### `sockopt` fields relevant to TUN loop avoidance

From `SocketConfig` in [`infra/conf/transport_sockopt.go`](https://github.com/XTLS/Xray-core/blob/main/infra/conf/transport_sockopt.go) (proto: [`transport/internet/config.proto`](https://github.com/XTLS/Xray-core/blob/main/transport/internet/config.proto)):

| Key | Type | Relevance to TUN |
|---|---|---|
| `interface` | string | **The primary loop-prevention knob** if you do not use `autoOutboundsInterface`. Linux `SO_BINDTODEVICE`, Windows `IP_UNICAST_IF`, macOS `IP_BOUND_IF`. |
| `mark` | int32 | `SO_MARK` (Linux). Use with `ip rule fwmark` to steer Xray's own traffic to a non-tunnel table. Requires `CAP_NET_ADMIN`. |
| `domainStrategy` | enum | If the **outbound server address is a domain**, set `UseIP`/`ForceIP` so the domain is resolved by the built-in DNS *before* connecting — avoids a DNS lookup that could itself be routed into the tun. |
| `tcpFastOpen` | bool \| int | Outbound TCP Fast Open. **Irrelevant to loop prevention**; leave unset (Xray's default is "do not call setsockopt"). |
| `tproxy` | `"tproxy"`/`"redirect"` | **Not applicable to TUN.** It configures the *transparent-proxy inbound* (dokodemo-door/`tunnel`) socket, not TUN. Do not set it. |
| `v6only`, `tcpCongestion`, `tcpMss`, `tcpWindowClamp`, `tcpUserTimeout`, `tcpMaxSeg`, `tcpMptcp`, `happyEyeballs`, `customSockopt` | various | Available; none required for TUN. `customSockopt` can inject arbitrary setsockopt calls if a platform needs one. |
| `dialerProxy` | string | Chains the outbound through another outbound (e.g. a `freedom` bound to the physical NIC). A viable alternative loop-breaker. |

Note: the `sockopt` object lives in the **inbound** `streamSettings` for listener sockets, but for TUN there is no listener — **outbound `streamSettings.sockopt` is the one that matters here.**

---

# 2. Architecture proposal

## 2.1 Division of responsibility

```
┌──────────────────────────── MyVpn (elevated helper / service) ────────────────────────────┐
│ • picks tun name, gateway prefixes, MTU, DNS synthetic resolver                            │
│ • pre-flights privileges (/dev/net/tun + CAP_NET_ADMIN, Wintun elevation, utun root)       │
│ • installs the uplink host route (Linux/Windows) and firewall/kill-switch rules             │
│ • takes over system DNS (Linux: resolv.conf/systemd-resolved; macOS: scutil; Win: adapter)  │
│ • writes xray config → `xray run -test` → spawns xray → watches                                │
│ • tears everything down in reverse order, even on crash                                     │
└───────────────────────────────────────────┬────────────────────────────────────────────────┘
                                            │ JSON config, stdin/argv
┌───────────────────────────────────────────▼────────────────────────────────────────────────┐
│ Xray-core ≥ v26.9.9                                                                        │
│ • creates/claims the TUN, sets MTU, addresses (gateway), routes (autoSystemRoutingTable)    │
│ • binds its own outbound sockets to the physical NIC (autoOutboundsInterface)               │
│ • gVisor L3 stack → TCP (local handshake) / UDP (full-cone) / ICMP echo                     │
│ • DNS hijack via `protocol:"dns"` outbound + routing rule                                    │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

Rule of thumb: **Xray owns the interface and the capture; MyVpn owns everything about not breaking the network.**

## 2.2 Loop prevention (the mechanism, spelled out)

Mandatory, in this order at startup:

1. Resolve the uplink server to IP(s) **before** touching routes (MyVpn, via the built-in DNS or the OS).
2. Install a host route for each uplink IP via the *current* physical default gateway (Linux `ip route add <ip>/32 via <gw> dev <iface>`; Windows `route add <ip> mask 255.255.255.255 <gw> if <idx>`), and record the original default route.
3. Emit `"autoOutboundsInterface": "auto"` (or a pinned interface name) **and** keep `sockopt.interface` on every outbound as belt-and-braces — including the `direct`/`freedom` outbound and the `dns-out` outbound's rewritten path.
4. Only then let Xray install `autoSystemRoutingTable` (which is what flips the default route on Linux/Windows).
5. On teardown: remove Xray's routes (Xray does this), then the host route, then restore DNS and firewall.

Because `autoOutboundsInterface` resolves "auto" by looking for the lowest-metric default route **excluding the TUN** (`findDefaultInterface`/`findOutboundInterface`), step 2 must have completed before Xray starts, otherwise "auto" may resolve to something wrong (or to nothing) and Xray logs `no usable outbound interface found` / `automatic outbound interface selection is not supported on this platform` and proceeds **without** loop protection. MyVpn must treat that log line as a hard failure.

## 2.3 Minimal viable JSON per OS

All snippets assume a VLESS/REALITY uplink named `proxy` and use **only fields that exist**. `streamSettings` of the proxy outbound is elided except where it matters.

### Linux (full tunnel, Xray creates `xray0`)

```json
{
  "log": { "loglevel": "warning" },
  "dns": {
    "tag": "dns-in",
    "queryStrategy": "UseIP",
    "servers": ["https://1.1.1.1/dns-query", "fakedns"]
  },
  "fakedns": { "ipPool": "198.18.0.0/15", "poolSize": 32768 },
  "inbounds": [
    {
      "tag": "tun-in",
      "protocol": "tun",
      "settings": {
        "name": "xray0",
        "mtu": 1500,
        "gateway": ["172.19.0.1/30", "fc00::1/126"],
        "userLevel": 0,
        "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
        "autoOutboundsInterface": "auto"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic", "fakedns"],
        "routeOnly": false
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": { "vnext": [{ "address": "203.0.113.5", "port": 443, "users": [{ "id": "…", "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": { "serverName": "…", "publicKey": "…", "shortId": "…", "fingerprint": "chrome" },
        "sockopt": { "interface": "eth0", "domainStrategy": "UseIP" }
      }
    },
    { "tag": "dns-out", "protocol": "dns", "settings": { "rewriteNetwork": "udp" } },
    { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "interface": "eth0", "domainStrategy": "UseIP" } } }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "port": 53, "outboundTag": "dns-out" },
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" },
      { "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }
    ]
  }
}
```

### Windows (full tunnel, Wintun)

```json
{
  "log": { "loglevel": "warning" },
  "dns": { "tag": "dns-in", "queryStrategy": "UseIP", "servers": ["1.1.1.1", "fakedns"] },
  "fakedns": { "ipPool": "198.18.0.0/15", "poolSize": 32768 },
  "inbounds": [
    {
      "tag": "tun-in",
      "protocol": "tun",
      "settings": {
        "name": "MyVpn",
        "desc": "MyVpn",
        "mtu": 1500,
        "gateway": ["172.19.0.1/30", "fc00::1/126"],
        "dns": ["172.19.0.2"],
        "userLevel": 0,
        "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
        "autoOutboundsInterface": "auto"
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic", "fakedns"] }
    }
  ],
  "outbounds": [
    { "tag": "proxy", "protocol": "vless", "settings": { "vnext": [ /* … */ ] },
      "streamSettings": { "security": "reality", "realitySettings": { /* … */ },
        "sockopt": { "interface": "Ethernet", "domainStrategy": "UseIP" } } },
    { "tag": "dns-out", "protocol": "dns" },
    { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "interface": "Ethernet" } } }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "port": 53, "outboundTag": "dns-out" },
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" },
      { "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }
    ]
  }
}
```

`172.19.0.2` is a **synthetic** resolver address: it is inside the tun's own `/30`, so the OS sends DNS to the adapter, the packet arrives through the TUN, and the `port 53 → dns-out` rule hijacks it. `wintun.dll` (matching arch) must sit next to `xray.exe`.

### macOS (full tunnel, `utun`)

```json
{
  "log": { "loglevel": "warning" },
  "dns": { "tag": "dns-in", "queryStrategy": "UseIP", "servers": ["https://1.1.1.1/dns-query"] },
  "inbounds": [
    {
      "tag": "tun-in",
      "protocol": "tun",
      "settings": {
        "name": "utun10",
        "mtu": 1500,
        "gateway": ["172.19.0.1/30"],
        "userLevel": 0,
        "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
        "autoOutboundsInterface": "auto"
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
    }
  ],
  "outbounds": [
    { "tag": "proxy", "protocol": "vless", "settings": { "vnext": [ /* … */ } },
      "streamSettings": { "sockopt": { "interface": "en0", "domainStrategy": "UseIP" } } },
    { "tag": "dns-out", "protocol": "dns" },
    { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "interface": "en0" } } }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "port": 53, "outboundTag": "dns-out" },
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" },
      { "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }
    ]
  }
}
```

Notes: `dns` inside `settings` is pointless on macOS (remove it). `gateway` may contain IPv6, but only the first **IPv4** entry is used for the utun point-to-point pair. `0.0.0.0/0` is split by Xray into protected routes, so macOS is the one platform where the default route is *not* replaced.

**Split-tunnel variant (all OSes):** drop `0.0.0.0/0`/`::/0` from `autoSystemRoutingTable`, list only the prefixes to capture, and keep the physical default route. This is approach 1-b in the README and is the lowest-risk configuration MyVpn can ship first.

## 2.4 C# model proposal

`MyVpn.Core` has **no NuGet dependencies** by design, and already owns "the configuration model" plus `MyVpn.Core.Net.CidrBlock`. So: **pure domain model in Core, JSON DTOs + writer in Infrastructure.**

### `src/MyVpn.Core/Config/Xray/TunInboundOptions.cs`

```csharp
using System.Net;
using MyVpn.Core.Net;

namespace MyVpn.Core.Config.Xray;

/// <summary>
/// Mirrors the <c>settings</c> object of the native Xray TUN inbound
/// (protocol "tun"). Field set and defaults are copied from Xray-core
/// v26.9.9 / infra/conf/tun.go — do not add fields Xray does not have.
/// </summary>
public sealed record TunInboundOptions
{
    /// <summary>Interface name. Always set explicitly: Xray's default changed
    /// between releases ("xray0" in 26.4.13, random "utunN" in 26.7.28+).</summary>
    public string? Name { get; init; }

    /// <summary>Windows Wintun adapter description ("&lt;desc&gt; Tunnel"). Ignored elsewhere.</summary>
    public string? Desc { get; init; }

    /// <summary>Interface MTU. Xray treats 0 as 1500; MyVpn always writes a value.</summary>
    public int Mtu { get; init; } = 1500;

    /// <summary>Address prefixes assigned to the TUN interface (NOT a next-hop).
    /// macOS/FreeBSD use only the first IPv4 entry, as the point-to-point remote address.</summary>
    public IReadOnlyList<CidrBlock> Gateway { get; init; } = [];

    /// <summary>Interface DNS servers. Bare IPs. Windows only; inert on Linux/macOS.</summary>
    public IReadOnlyList<IPAddress> Dns { get; init; } = [];

    /// <summary>Policy level for connections accepted from the tun. Default 0.</summary>
    public int UserLevel { get; init; }

    /// <summary>CIDRs Xray installs into the OS routing table while running.
    /// On Linux and Windows an entry of 0.0.0.0/0 REPLACES the physical default route.</summary>
    public IReadOnlyList<CidrBlock> AutoSystemRoutingTable { get; init; } = [];

    /// <summary>Binds all Xray outbound sockets to a physical interface so Xray's own
    /// traffic does not re-enter the tunnel. <see langword="null"/> = omit the key
    /// (Xray then implies "auto" when routes are present); "" = explicitly disabled;
    /// "auto" = Xray picks the lowest-metric non-tun default-route interface;
    /// anything else = that interface name.</summary>
    public string? AutoOutboundsInterface { get; init; }
}
```

Supporting type (Core), to keep the tri-state honest in validation without magic strings:

```csharp
namespace MyVpn.Core.Config.Xray;

public static class AutoOutboundsInterfaceValue
{
    public const string Auto = "auto";
    public const string Disabled = "";
}
```

### `src/MyVpn.Infrastructure/Xray/Serialization/XrayTunInboundDto.cs`

```csharp
using System.Text.Json.Serialization;

namespace MyVpn.Infrastructure.Xray.Serialization;

/// <summary>
/// Wire representation of the tun inbound. Key names and casing are exact:
/// Xray reads them with Go encoding/json (case-insensitive on read, but we
/// must emit the documented spelling). Omit-null is required so that
/// autoOutboundsInterface can be absent rather than "".
/// </summary>
internal sealed class XrayTunInboundSettingsDto
{
    [JsonPropertyName("name")] public string? Name { get; init; }
    [JsonPropertyName("desc")] public string? Desc { get; init; }
    [JsonPropertyName("mtu")] public uint Mtu { get; init; }
    [JsonPropertyName("gateway")] public IReadOnlyList<string>? Gateway { get; init; }
    [JsonPropertyName("dns")] public IReadOnlyList<string>? Dns { get; init; }
    [JsonPropertyName("userLevel")] public uint UserLevel { get; init; }
    [JsonPropertyName("autoSystemRoutingTable")] public IReadOnlyList<string>? AutoSystemRoutingTable { get; init; }
    [JsonPropertyName("autoOutboundsInterface")] public string? AutoOutboundsInterface { get; init; }
}
```

Serializer options (Infrastructure):

```csharp
private static readonly JsonSerializerOptions Options = new()
{
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
};
```

Mapping rules (must exactly mirror `TunConfig.Build`):

```csharp
static XrayTunInboundSettingsDto ToDto(TunInboundOptions o, TunPlatform platform) => new()
{
    Name = o.Name,
    // Xray ignores desc off-Windows; emit it only there to keep configs minimal.
    Desc = platform == TunPlatform.Windows ? (o.Desc ?? "Wintun") : null,
    Mtu = (uint)o.Mtu,                                 // validated > 0
    Gateway = o.Gateway.Count == 0 ? null : o.Gateway.Select(c => c.ToString()).ToArray(),
    Dns = platform == TunPlatform.Windows && o.Dns.Count > 0
            ? o.Dns.Select(a => a.ToString()).ToArray() : null,
    UserLevel = (uint)o.UserLevel,
    AutoSystemRoutingTable = o.AutoSystemRoutingTable.Count == 0
            ? null : o.AutoSystemRoutingTable.Select(c => c.ToString()).ToArray(),
    AutoOutboundsInterface = o.AutoOutboundsInterface,   // null stays absent
};
```

(`CidrBlock.ToString()` already renders `Network/PrefixLength` — verified in `src/MyVpn.Core/Net/CidrBlock.cs:180`.)

### Validation (`TunInboundOptionsValidator` in Core)

Returning `Result<TunInboundOptions>` with `ErrorCodes.ConfigInvalid`; every rule below is traceable to Xray behaviour:

1. **`mtu`**: reject `<= 0`; warn/clamp below `1280` when any IPv6 entry exists (v26.4.13's own default pair was `[1500, 1280]`, i.e. Xray once distinguished v4/v6 MTU).
2. **`name`**: non-empty always. `TunPlatform.MacOS` → must match `^utun\d+$` (`tun_darwin.go:open` errors otherwise). `FreeBSD` → `^tun\d+$` (README). Windows: non-empty, no path separators. Linux: non-empty, `<= 15` chars (kernel `IFNAMSIZ`).
3. **`desc`**: Windows only; strip elsewhere; non-empty string.
4. **`gateway`**: every entry must parse (`CidrBlock.TryParse`) — **Xray calls `netip.MustParsePrefix` on Windows and will panic the process on a malformed value**; on macOS require ≥1 IPv4 entry whose prefix has a usable address *after* the gateway address (⇒ `/32` rejected, `/31` accepted).
5. **`dns`**: every entry must be a **bare IP**, not CIDR — Xray calls `netip.MustParseAddr`. Reject CIDRs with a clear message; Windows-only, warn if set on Linux/macOS (it is silently inert there).
6. **`autoSystemRoutingTable`**: every entry must parse as CIDR. Additionally:
   * Linux/Windows + contains `0.0.0.0/0` or `::/0` ⇒ **require** `AutoOutboundsInterface` to be non-null and non-empty, else `ConfigInvalid` (loop).
   * macOS: `0.0.0.0/0` is allowed and is split by Xray.
7. **`autoOutboundsInterface`**: `null` is allowed only when `AutoSystemRoutingTable` is empty. A literal name must be non-empty and must not equal the TUN's own `name`.
8. **Cross-check**: reject `UserLevel` outside the configured `policy.levels` range.
9. **Version gate** (separate validator, `ErrorCodes.XrayVersionUnsupported`): require `>= 26.4.15`; **explicitly reject `26.4.13`** (its `mtu` is an array); recommend `>= 26.9.9`.

### How to validate the generated JSON

Two layers:

* **Schema/self-test:** `xray run -test -config <file>` (the `-test` flag is defined in [`main/run.go`](https://github.com/XTLS/Xray-core/blob/main/main/run.go): *"Test config file only, without launching Xray server"*). Non-zero exit + stderr ⇒ `ErrorCodes.ConfigRejectedByCore`. This exercises the real `TunConfig.Build`, i.e. the real schema.
* **Behavioural pre-flight (MyVpn-owned):** assert the tun name is free, the gateway prefix does not collide with the physical LAN subnet, and that after start the interface exists (`ip link show xray0`, `Get-NetAdapter`, `ifconfig utun10`).

---

# 3. Risks

| ID | Risk | Severity | Evidence | Mitigation |
|---|---|---|---|---|
| **R-1** | **`v26.4.13` has an incompatible `mtu` type** — `repeated uint32` on the wire, so `"mtu": 1500` is invalid there and omitting it yields `[1500,1280]`; code does `options.MTU[0]`. | High if that version is ever accepted | `proxy/tun/config.proto` @ `v26.4.13` = `repeated uint32 MTU = 2;`; `infra/conf/tun.go` @ `v26.4.13` = `MTU []uint32`; `tun_linux.go` = `int(options.MTU[0])` | Pin minimum `v26.4.15`, recommend `v26.9.9`; reject `26.4.13` in the version gate. Do not trust a bare `xray version` string — compare parsed semver. |
| **R-2** | **Invalid `gateway`/`dns`/`autoSystemRoutingTable` values panic Xray on Windows** (`netip.MustParsePrefix` / `MustParseAddr`). | Critical | `tun_windows.go:93,104,110` | Client-side CIDR/IP validation before writing config (rules 4–6 above). Never rely on Xray to reject bad input. |
| **R-3** | **`0.0.0.0/0` in `autoSystemRoutingTable` replaces the physical default on Linux/Windows**, and `autoOutboundsInterface` may fail to resolve ("auto" → no usable interface), silently leaving Xray unprotected → total network loop. | Critical | `tun_linux.go:266-290`; `tun_windows.go:107-128,195-208`; `handler.go` logging `no usable outbound interface found` | Require explicit `autoOutboundsInterface`; install an uplink host route *before* start; treat the Xray warning log as fatal; ship split-tunnel mode first. |
| **R-4** | **No DNS interception on Linux/macOS and no DNS leak protection anywhere.** The Windows WFP DNS blackhole described in PR #6478 is **not in the shipped code**. | High | PR #6478 diff contains only `proxy/tun/tun_windows.go` retry/lookup changes; `grep -ri "wfp\|fwpm\|firewall"` over `main` = 0 hits | MyVpn implements DNS takeover + firewall rules; add an active DNS-leak test. |
| **R-5** | **"Connected" is meaningless at L3.** TCP handshakes complete locally; ICMP echo replies are synthesized. | High | `proxy/tun/README.md` LIMITATION; `stack_gvisor.go:69-98`; `stack_gvisor.go` ICMP handlers | Never use `connect()`/`ping` as a health signal; health-check by fetching a known URL through the proxy. |
| **R-6** | **FakeDNS pollutes the OS/application DNS cache** and can leave "no network" after Xray exits. | Medium | `docs/en/config/fakedns.md` warning | Only enable FakeDNS when needed; on stop, flush DNS caches (`ipconfig /flushdns`, `resolvectl flush-caches`, `dscacheutil -flushcache`). |
| **R-7** | **`XRAY_TUN_FD` mode disables all Xray interface management** (no MTU, addresses, routes, up/down). MyVpn would own the whole lifecycle. | Medium | `tun_linux.go:44-49,167-170`; `tun_darwin.go` `ownsFd=false` | Decide deliberately: let Xray create the interface (recommended for desktop) rather than passing an fd. |
| **R-8** | **Insufficient privileges** — Linux needs `CAP_NET_ADMIN` (+ `CAP_NET_RAW` for `SO_BINDTODEVICE`); macOS needs root-equivalent; Windows almost certainly needs elevation though Xray does not document it. | High | [tuntap.txt](https://www.kernel.org/doc/Documentation/networking/tuntap.txt) §2; `tun_linux.go:122,232`; Windows requirement **UNVERIFIED** in Xray/wintun text | Ship a privileged helper/service (`ErrorCodes.PrivilegeNotElevated`, `PrivilegeHelperNotInstalled`); pre-flight before writing config. |
| **R-9** | **MTU/fragmentation/PMTU**: no PMTU discovery in the TUN inbound; GRO/GSO offload intentionally absent; UDP egress queue (1024) drops silently under load. | Medium | PR #5464 body; `udp_fullcone.go` drop paths | Default MTU 1500 but expose 1280–1420 presets; monitor UDP drops at debug log level; test with large UDP. |
| **R-10** | **Wintun `wintun.dll` must be redistributed per-arch and is the only supported distribution channel**; interface index changes every start. | Medium | README "WINDOWS SUPPORT"; wintun.net | Ship the signed DLLs for x64/arm64; never persist the ifindex; re-discover at start. |
| **R-11** | **macOS `dns` inertness** surprises users: a config that "works" on Windows leaks DNS on macOS. | Medium | README; `docs/en/config/inbounds/tun.md` | Platform-conditional config generation + UI copy that says so explicitly. |
| **R-12** | **Xray does not remove a pre-existing IPv6 default route.** Disabling IPv6 only by omitting config is not sufficient. | Medium | No IPv6 teardown/route code in `tun_*.go` | Firewall-level IPv6 block; assert no v6 default route to the physical NIC while the tunnel is up. |
| **R-13** | **`initialXrayVersionProbe` string parsing.** A version gate must be semver-aware; Xray tags are `vYY.M.D`. | Low | Release tags e.g. `v26.9.8` | Parse `v?(\d+)\.(\d+)\.(\d+)` and compare numerically. |

---

# 4. Implementation plan

**Phase 0 — decisions (0.5 d).** Confirm TUN inbound (not sing-box) as the core; confirm `v26.9.9` minimum; confirm helper/service privilege model; confirm split-tunnel-first rollout.

**Phase 1 — model + serialization (1–2 d).** Add `TunInboundOptions`, `TunPlatform`, `TunInboundOptionsValidator`, `AutoOutboundsInterfaceValue` to `MyVpn.Core`; add the DTO + writer to `MyVpn.Infrastructure`, wired into the existing Xray config builder. Golden-JSON unit tests per platform.

**Phase 2 — version gate (0.5 d).** Semver parser for `xray version`; enforce ≥ `26.4.15`, reject `26.4.13`, warn below `26.9.9`, using `ErrorCodes.XrayVersionUnsupported`.

**Phase 3 — per-OS interface discovery + privilege pre-flight (2–3 d).** `IReadOnlyList<NetworkInterface>` enumeration, `/dev/net/tun` presence + `CAP_NET_ADMIN` probe (Linux), Wintun DLL presence + elevation probe (Windows), utun root probe (macOS). Emit `TunCreateFailed` / `TunMissing` / `PrivilegeNotElevated`.

**Phase 4 — loop prevention (2 d).** Uplink IP resolution, host-route install/remove, `sockopt.interface` injection into every outbound, Xray-log watchdog that fails the start on `no usable outbound interface found`. Split-tunnel mode first.

**Phase 5 — DNS takeover (2 d).** `port 53 → dns-out` rule, `dns` module construction, OS DNS set/restore per platform, flush on stop, leak test.

**Phase 6 — validation + lifecycle (1–2 d).** `xray run -test -config` before spawn; teardown ordering; crash recovery (restore DNS/routes if Xray dies).

**Phase 7 — full-tunnel enablement + hardening (2–3 d).** Opt-in `0.0.0.0/0` + `::/0`, kill-switch rules, IPv6 block, MTU presets, UDP-drop diagnostics.

---

# 5. Files / modules affected (`src/MyVpn.*`)

All paths are **proposals**; nothing under `src/` was modified by this research.

| Project | New / changed | Purpose |
|---|---|---|
| `src/MyVpn.Core/Config/Xray/TunInboundOptions.cs` | new | The 8-field domain model (2.4 above). Zero dependencies. |
| `src/MyVpn.Core/Config/Xray/TunPlatform.cs` | new | `Windows`/`Linux`/`MacOS`/`FreeBSD` enum + name-pattern helpers. |
| `src/MyVpn.Core/Config/Xray/TunInboundOptionsValidator.cs` | new | Rules 1–8; returns `Result<TunInboundOptions>` with `ErrorCodes.ConfigInvalid`. |
| `src/MyVpn.Core/Config/Xray/XrayConfigOptions.cs` | new | Root options: inbounds, outbounds, routing, dns, fakeDns, policy. |
| `src/MyVpn.Core/Config/Xray/RoutingRuleOptions.cs`, `SockoptOptions.cs`, `SniffingOptions.cs` | new | Loop-prevention surface (`interface`, `domainStrategy`) and sniffing. |
| `src/MyVpn.Core/Net/CidrBlock.cs` | reuse | CIDR parsing/`ToString()` already sufficient. |
| `src/MyVpn.Core/Results/ErrorCodes.cs` | extend | Reuse `TunCreateFailed`, `TunMissing`, `RouteAddFailed`, `DnsConfigureFailed`, `DnsLeakDetected`, `PrivilegeNotElevated`, `XrayVersionUnsupported`; add `tun.loop_risk_unprotected` if a dedicated code is wanted. |
| `src/MyVpn.Infrastructure/Xray/Serialization/XrayTunInboundDto.cs` | new | Wire DTO with exact JSON keys. |
| `src/MyVpn.Infrastructure/Xray/Serialization/XrayConfigWriter.cs` | new | Full-document serializer, omit-null, indented. |
| `src/MyVpn.Infrastructure/Xray/XrayConfigValidator.cs` | new | `xray run -test -config` round-trip. |
| `src/MyVpn.Infrastructure/Xray/XrayVersionGate.cs` | new | Semver gate. |
| `src/MyVpn.Infrastructure/Xray/XrayProcessHost.cs` | new | Spawn, log-watch (fail on unprotected-interface warning), restart-loop detection. |
| `src/MyVpn.Platform.Abstractions/INetworkConfigurator.cs` | new | Interface discovery, host route, DNS set/restore, teardown. |
| `src/MyVpn.Platform.Linux/…` | new | `/dev/net/tun`, `CAP_NET_ADMIN`, `ip route`/netlink, resolv.conf/systemd-resolved. |
| `src/MyVpn.Platform.Windows/…` | new | Wintun DLL staging, elevation, adapter discovery, `route`/DNS, WFP/DNS-block. |
| `src/MyVpn.Platform.MacOS/…` | new | utun root check, `route`/`scutil` DNS. |
| `src/MyVpn.Service/…` | changed | Owns the elevated TUN lifecycle; IPC surface for start/stop. |
| `src/MyVpn.Application/…` | changed | Connect/disconnect orchestration + teardown ordering. |

---

# 6. Tests

**Unit — serialization (`tests/MyVpn.Infrastructure.Tests`)**
* Golden JSON per platform: Linux/macOS omit `desc` and `dns`; Windows emits both.
* `autoOutboundsInterface == null` ⇒ **key absent**; `== ""` ⇒ **key present with empty string**; `== "auto"` ⇒ `"auto"`. (This tri-state is the subtlest part of the schema.)
* Key names/casing asserted literally: `mtu`, `userLevel`, `autoSystemRoutingTable`, `autoOutboundsInterface`, `gateway`, `dns`, `desc`.
* Round-trip: serialize → deserialize → equal.
* No key outside the eight ever appears (guard against invented fields).

**Unit — validation (`tests/MyVpn.Core.Tests`)**
* Reject malformed CIDR in `gateway` and `autoSystemRoutingTable` (guard against the Windows `MustParsePrefix` panic, R-2).
* Reject a CIDR in `dns`; accept bare IPv4/IPv6.
* macOS: reject `gateway` with no IPv4 entry; reject `/32`; accept `/31` and `/30`.
* FreeBSD: reject a name not matching `tunN`; macOS: reject a name not matching `utunN`.
* Linux: reject an interface name > 15 chars.
* Require `autoOutboundsInterface` when a default route is auto-installed on Linux/Windows; allow omission when the routing table is empty.
* `mtu` bounds; warn below 1280 with IPv6 present.
* `UserLevel` outside the configured policy range.

**Unit — version gate**
* Accept `26.9.9`, `26.10.1`; reject `26.4.13` (array-`mtu` era); reject `26.1.13` when a `gateway`/`autoSystemRoutingTable` field is emitted; warn between `26.4.15` and `26.9.8`.

**Integration (`tests/MyVpn.Integration.Tests`, opt-in / CI matrix)**
* `xray run -test -config <generated>` returns 0 for each platform's golden config; non-zero for a deliberately malformed one.
* Start Xray with a real TUN in an isolated netns (Linux CI) and assert: interface exists with the requested name/MTU/addresses; the expected routes are present; teardown removes all of them.
* **Loop test:** with a stub uplink, assert no packet enters the tun from Xray's own outbound (counter check) — the single most important safety test.
* **DNS test:** query an arbitrary resolver from inside the namespace and assert it was answered by the built-in DNS path, not leaked (R-4).
* Crash-recovery test: `SIGKILL` Xray and assert MyVpn restores DNS, the original default route and the firewall state.

**Manual / platform acceptance**
* Windows: `route print` shows the Wintun adapter and no stale routes after stop; verify `wintun.dll` arch match; verify an unelevated start fails with `PrivilegeNotElevated` and does **not** half-apply routes.
* macOS: `ifconfig utunN` shows the point-to-point pair derived from `gateway`; `netstat -rn` shows the 8 protected routes and **still** a physical default route.
* Linux: `sysctl net.ipv4.conf.all.rp_filter` interaction — README notes martian-packet drops; test with `rp_filter=1` and document the required sysctl.

**Negative tests that encode the LIMITATION section**
* `ping` a nonexistent IP must **succeed** at the ICMP layer (fake pong) — assert MyVpn does not treat this as connectivity.
* TCP connect to a blackholed IP must appear to succeed — assert the health checker uses an application-level probe instead.

---

## Appendix — source index

Xray-core (pin `c412e77` / `v26.9.9`): [`proxy/tun/README.md`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/README.md) · [`proxy/tun/config.proto`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/config.proto) · [`proxy/tun/handler.go`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/handler.go) · [`proxy/tun/tun_linux.go`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_linux.go) · [`proxy/tun/tun_windows.go`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_windows.go) · [`proxy/tun/tun_darwin.go`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_darwin.go) · [`proxy/tun/tun_freebsd.go`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_freebsd.go) · [`proxy/tun/stack_gvisor.go`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/stack_gvisor.go) · [`proxy/tun/udp_fullcone.go`](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/udp_fullcone.go) · [`infra/conf/tun.go`](https://github.com/XTLS/Xray-core/blob/main/infra/conf/tun.go) · [`infra/conf/xray.go`](https://github.com/XTLS/Xray-core/blob/main/infra/conf/xray.go) · [`infra/conf/dns_proxy.go`](https://github.com/XTLS/Xray-core/blob/main/infra/conf/dns_proxy.go) · [`infra/conf/transport_sockopt.go`](https://github.com/XTLS/Xray-core/blob/main/infra/conf/transport_sockopt.go) · [`transport/internet/config.proto`](https://github.com/XTLS/Xray-core/blob/main/transport/internet/config.proto) · [`common/platform/platform.go`](https://github.com/XTLS/Xray-core/blob/main/common/platform/platform.go) · [`app/proxyman/inbound/always.go`](https://github.com/XTLS/Xray-core/blob/main/app/proxyman/inbound/always.go) · [`main/run.go`](https://github.com/XTLS/Xray-core/blob/main/main/run.go)

Official docs (pin `c6168022`, site <https://xtls.github.io>): [TUN inbound](https://xtls.github.io/config/inbounds/tun.html) · [tun.md source](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/inbounds/tun.md) · [Built-in DNS](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/dns.md) · [DNS outbound](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/outbounds/dns.md) · [FakeDNS](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/fakedns.md) · [InboundObject / SniffingObject](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/inbound.md) · [Routing](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/routing.md) · [Tunnel (dokodemo-door)](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/inbounds/tunnel.md) · [Sockopt](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/sockopt.md)

PRs: [#5464](https://github.com/XTLS/Xray-core/pull/5464) initial TUN · [#5559](https://github.com/XTLS/Xray-core/pull/5559) macOS · [#5612](https://github.com/XTLS/Xray-core/pull/5612) iOS · [#5509](https://github.com/XTLS/Xray-core/pull/5509)/[#5526](https://github.com/XTLS/Xray-core/pull/5526) UDP full-cone · [#5891](https://github.com/XTLS/Xray-core/pull/5891) FreeBSD · [#6015](https://github.com/XTLS/Xray-core/pull/6015) fake ICMP pong · [#6035](https://github.com/XTLS/Xray-core/pull/6035) `autoOutboundsInterface: "auto"` · [#6276](https://github.com/XTLS/Xray-core/pull/6276) loopback bypass · [#6398](https://github.com/XTLS/Xray-core/pull/6398) Linux gateway/routes · [#6434](https://github.com/XTLS/Xray-core/pull/6434) macOS gateway/routes · [#6478](https://github.com/XTLS/Xray-core/pull/6478) Windows refinements · [#6486](https://github.com/XTLS/Xray-core/pull/6486) `desc`

Platform: [Linux tuntap.txt](https://www.kernel.org/doc/Documentation/networking/tuntap.txt) · [wintun.net](https://www.wintun.net/)

### Explicit UNVERIFIED list

1. **Windows elevation requirement** — not stated in Xray's README, the Wintun site, the Wintun Go package docs, or `wintun.h`. Assumed required in practice.
2. **Whether the PR #6478 WFP/DNS-blackhole rules exist anywhere** — absent from the merged diff, from `v26.9.9` (byte-identical to `main`), and from a repo-wide grep. Treated as **not shipped**.
3. **IPv4/IPv6 packet fragmentation and PMTU behaviour** through the TUN inbound — no code path or doc found.
4. **Whether an explicit `sockopt.interface` truly overrides** the `autoOutboundsInterface` dialer controller (docs claim it can; the two both call setsockopt on the same fd and no precedence code was found).
5. **macOS utun creation privilege** — not documented in Xray primary sources; assumed root-equivalent.
6. **Whether Windows' unconditional `AF_INET6` `SetDNS`/`IPInterface` writes can attract IPv6 traffic** when no IPv6 gateway/route is configured.
