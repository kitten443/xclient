# NAT / UDP Transport Compatibility Matrix — MyVpn (Xray-core only)

- **Scope:** how Xray-core's UDP mechanisms behave across NAT environments, what MyVpn can detect, and which transport strategy it should select.
- **Evidence base:** Xray-core `main` cloned and inspected at commit [`c412e77a9b712082ac9ebf27fa793951cb5a7d85`](https://github.com/XTLS/Xray-core/commit/c412e77a9b712082ac9ebf27fa793951cb5a7d85) (`core/core.go` reports version `26.9.9`), plus the official docs at <https://xtls.github.io/en/> and the GitHub release/commit history.
- **Boundaries respected:** this document is the only artifact written. No file under `src/` was modified, `dotnet` was not run.
- **Confidence markers:** claims taken from the official docs or from source code I read are stated plainly with a link. Anything I could not confirm is marked **UNVERIFIED**. Claims that vendors commonly overstate are marked **⚠ OVERSTATED**.

---

## 1. Findings

### 1.1 The distinction everything else depends on: *local* NAT vs *server-side* cone

Two completely unrelated things are both called "NAT type" in Xray discussions:

| Concept | Where it lives | What it determines | Can Xray change it? |
| --- | --- | --- | --- |
| **Local NAT type** | The network the MyVpn client sits behind (home router, carrier CGNAT, hotel, corporate) | Whether *this machine* can receive unsolicited inbound UDP directly, and whether a UDP-based connection *from this machine to an arbitrary destination* survives | **No.** |
| **Xray "cone" / "UDP FullCone"** | The proxy server's UDP egress mapping, plus how the inbound keys UDP sessions | What NAT type a *remote peer on the Internet* observes for traffic that exits the server on behalf of this client | **Yes** — it is Xray's own implementation, controlled by one environment variable. |

Consequences that must drive the design:

1. **For proxied traffic the local NAT type is almost irrelevant.** With VLESS/VMess/Trojan the client's only flow is "client → server" over the configured transport. NAT type of the local network does not affect whether a proxied app's UDP payload is delivered; the payload is carried *inside* the tunnel (see §1.3, §1.5).
2. **Local NAT type matters only for:** UDP-based tunnel transports (mKCP, Hysteria), Shadowsocks' native UDP path where the client really does send UDP to the server, split-tunnel/direct (`freedom`) traffic, and any future direct/P2P feature.
3. **Server-side cone cannot fix a local symmetric NAT for direct P2P** — there is no direct P2P, everything is relayed through the server. Conversely, a local symmetric NAT does not prevent the *proxied* end-to-end path from looking full-cone to a remote peer.
4. **⚠ OVERSTATED:** "enabling UDP FullCone gives you full-cone NAT" is true only in the sense of *"remote peers see an endpoint-independent mapping on the server's egress"*. It does not grant the client's machine inbound reachability outside the tunnel, and it does nothing at all for a client-side symmetric NAT.

Xray's own [v1.3.0 release notes](https://github.com/XTLS/Xray-core/releases/tag/v1.3.0) state this outright (Chinese original; independent translation): FullCone is achieved entirely by the VPS's public IP and **has nothing to do with the local NAT environment**; and if the client is Xray-core v1.3.0+ while the server is v2fly-core, a **"false FullCone"** will be measured. Any MyVpn UI text that implies the user's own NAT became full-cone is therefore wrong twice over — once about *which side* changed, and once about the requirement that **both** sides support it.

⚠ **"False FullCone" is a measured, reproducible artefact, not a theoretical concern.** A NAT-type tester run *through* a full-cone-capable proxy reports FullCone even when the local NAT is symmetric, because it is measuring the proxy's egress mapping. This is why the report insists on two separately labelled measurements.

### 1.2 Mechanism catalogue (verified)

| Mechanism | What it mechanically is | Config surface | Verified source / doc |
| --- | --- | --- | --- |
| **Proxied UDP (per-destination)** | VLESS/VMess/Trojan have no native UDP: each proxied UDP destination becomes its own request with `Command=UDP`, datagrams framed with a 2-byte length prefix over the existing stream (this is "UoT"). Shadowsocks is different: it dials the server with `dest.Network = Network_UDP`, i.e. a genuine UDP socket to the server. | implicit | [`proxy/shadowsocks/client.go:59-65`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/shadowsocks/client.go), [`common/buf/io.go` `NewPacketReader`](https://raw.githubusercontent.com/XTLS/Xray-core/main/common/buf/io.go) |
| **cone / "UDP FullCone"** | Global, process-wide, **on by default**. Server-side inbound UDP workers key their session by *client source address only* (`id = {src}`) instead of `{src, dest}`, and the outbound uses a single UDP socket for all destinations. VLESS/VMess additionally rewrite `Command=UDP` (except ports 53 and 443) into Mux.Cool `v1.mux.cool` so one session carries datagrams to many destinations. | **Environment variable `XRAY_CONE_DISABLED=true`** disables it. There is **no JSON `fullcone` key** — see §1.6. | [`core/xray.go:189-194`](https://raw.githubusercontent.com/XTLS/Xray-core/main/core/xray.go), [`common/platform/platform.go:19`](https://raw.githubusercontent.com/XTLS/Xray-core/main/common/platform/platform.go), [`app/proxyman/inbound/worker.go:314-322`](https://raw.githubusercontent.com/XTLS/Xray-core/main/app/proxyman/inbound/worker.go), [`proxy/socks/server.go:270-275`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/socks/server.go), [`proxy/vless/outbound/outbound.go:313-318`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/vless/outbound/outbound.go), [`proxy/vmess/outbound/outbound.go:146-150`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/vmess/outbound/outbound.go) |
| **XUDP** | UDP aggregation over Mux.Cool. One Mux sub-connection (ID `0`) carries many UDP datagrams; each *New* frame carries a destination **and an 8-byte Global ID**. The Global ID is a BLAKE3 hash of the inbound source, keyed by `XRAY_XUDP_BASEKEY`; the server uses it so that after a disconnect/reconnect the same egress port is reused for the same client source — this is the "UDP session migration". | `mux.enabled: true` **plus** `mux.xudpConcurrency` (1..1024). `-1` disables the Mux path for UDP (protocol-native UDP is used). `0`/omitted = old behaviour. `mux.xudpProxyUDP443` = `reject` (default) | [`common/xudp/xudp.go:65-79,95-136`](https://raw.githubusercontent.com/XTLS/Xray-core/main/common/xudp/xudp.go), [`app/proxyman/outbound/handler.go:120-164,215-232`](https://raw.githubusercontent.com/XTLS/Xray-core/main/app/proxyman/outbound/handler.go), [Mux.Cool protocol doc](https://xtls.github.io/en/development/protocols/muxcool.html), [Outbound doc](https://xtls.github.io/en/config/outbound.html) |
| **UoT (UDP over TCP)** | Not a separate feature in Xray: it is the normal encoding of UDP inside VLESS/VMess/Trojan streams. It is what makes proxied UDP survive a network that blocks UDP. It is selectable only indirectly (see `xudpConcurrency: -1`). | implicit / `mux.xudpConcurrency: -1` | [`proxy/vless/inbound/inbound.go:557-558`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/vless/inbound/inbound.go), [`proxy/trojan/server.go:231-232`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/trojan/server.go) |
| **TUN full-cone** | A separate, newer implementation for the TUN inbound: `udpConns` is keyed by the packet's source address only, so returning packets are matched by source, not by source+destination. | TUN inbound (implicit) | [`proxy/tun/udp_fullcone.go:40-50`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/tun/udp_fullcone.go), [`proxy/tun/stack_gvisor.go:101`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/tun/stack_gvisor.go) |
| **WireGuard UDP full-cone** | Same idea, implemented for the WireGuard outbound (2026-03, [#5833](https://github.com/XTLS/Xray-core/pull/5833), fixed on Linux in [#5858](https://github.com/XTLS/Xray-core/pull/5858)). | WireGuard outbound | GitHub PR search, commits `WireGuard: Implement UDP FullCone NAT (#5833)`, `WireGuard outbound: Fix UDP FullCone NAT on Linux (#5858)` |
| **UDP-based transports** | mKCP (`streamSettings.method: "mkcp"`), Hysteria transport and Hysteria outbound all put the tunnel itself on UDP. | `streamSettings.method` | [mKCP doc](https://xtls.github.io/en/config/transports/mkcp.html), `transport/internet/hysteria/`, `transport/internet/kcp/` |
| **QUIC / UDP-443 policy** | With `xtls-rprx-vision`, UDP/443 is **rejected** by the core (`"XTLS rejected UDP/443 traffic"`) unless the flow is `xtls-rprx-vision-udp443`. With Mux enabled, `xudpProxyUDP443: reject` (default) drops it (`"XUDP rejected UDP/443 traffic"`). | `flow`, `mux.xudpProxyUDP443` | [`proxy/vless/outbound/outbound.go:248-259`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/vless/outbound/outbound.go), [`app/proxyman/outbound/handler.go:217-231`](https://raw.githubusercontent.com/XTLS/Xray-core/main/app/proxyman/outbound/handler.go), [`infra/conf/xray.go:110-117`](https://raw.githubusercontent.com/XTLS/Xray-core/main/infra/conf/xray.go), [VLESS outbound doc](https://xtls.github.io/en/config/outbounds/vless.html) |

### 1.3 What each mechanism actually solves — and does not

| Mechanism | Solves | Does **not** solve |
| --- | --- | --- |
| Proxied UDP over a TCP-shaped transport | UDP apps work even when the local network blocks UDP entirely; local NAT type becomes irrelevant | Latency: HOL blocking, TCP retransmit stalls; QUIC (UDP/443) is rejected by default with Vision |
| Proxied UDP over a UDP transport (mKCP / Hysteria) | Loss tolerance and latency on bad links; better throughput than TCP-over-lossy | Nothing at all if UDP is blocked or throttled; *adds* a dependency on local UDP + local NAT mapping lifetime |
| Shadowsocks native UDP to server | Lowest overhead for UDP; no framing | Fails when UDP to the server port is blocked; subject to local NAT mapping timeouts; leaks the server's UDP port to on-path observers |
| cone / FullCone | Remote peers see an endpoint-independent mapping on the server egress, so unsolicited inbound UDP to the server's egress port reaches the client (gaming, VoIP, seeding, some QUIC flows). XUDP session migration keeps the **same egress port across tunnel reconnects** | Client-side symmetric NAT for direct P2P; NAT64 inbound; any situation where the app bypasses the tunnel. **It cannot create local inbound reachability outside the tunnel.** |
| XUDP | Aggregation (fewer connections/handshakes), migration of the egress port across reconnects, isolation of UDP from TCP mux | Does not by itself create inbound reachability; server must support Mux.Cool; only active when `mux.enabled: true` |
| **TUN full-cone** | Apps behind MyVpn's TUN can receive UDP from sources they never sent to — but only as far as the server's egress allows | End-to-end reachability if the server side is not cone; anything about the local ISP NAT |

**Three non-obvious verified traps** worth recording:

1. **`mux.xudpConcurrency` is inert unless `mux.enabled` is `true`.** The whole mux/XUDP/`xudpProxyUDP443` block in the outbound handler is inside `if config.Enabled { ... }` ([`app/proxyman/outbound/handler.go:120-164`](https://raw.githubusercontent.com/XTLS/Xray-core/main/app/proxyman/outbound/handler.go)). A profile that sets `xudpConcurrency: 16` but leaves `enabled: false` silently gets no XUDP at all. To get XUDP *without* TCP mux you must set `enabled: true, concurrency: -1, xudpConcurrency: 16`.
2. **Cone is on by default and is a *process-wide* switch**, not a per-outbound one. There is no per-profile cone. Turning it off requires setting `XRAY_CONE_DISABLED=true` for the child process (or via the config `env` block; that ordering is verified in §1.6).
3. **Cone widens the UDP injection surface on the server.** Xray's freedom UDP reader takes datagrams from an *unconnected* packet socket and forwards every received datagram to the client without source filtering ([`proxy/freedom/freedom.go` `PacketReader.ReadMultiBuffer`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/freedom/freedom.go), [`transport/internet/system_dialer.go:70-92`](https://raw.githubusercontent.com/XTLS/Xray-core/main/transport/internet/system_dialer.go) — `lc.ListenPacket` on a wildcard source, then `PacketConnWrapper`). In cone mode **one** egress port is shared across all destinations for that client session, so any Internet host that sends a datagram to that port is forwarded into the client's session. Non-cone mode allocates a distinct port per destination and therefore narrows, but does not remove, that surface. This is inherent to full-cone semantics and must be an explicit, informed user choice.

### 1.4 `sockopt`: what actually reaches UDP

All from the official [Sockopt doc](https://xtls.github.io/en/config/transports/sockopt.html) and the per-OS implementations. `isTCPSocket()` gates TFO/congestion/window/user-timeout/MSS, so those never touch UDP.

| Option | Applies to UDP? | Linux | Windows | macOS / iOS | Android | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `mark` (`SO_MARK`) | **Yes** (set before the `isTCPSocket` branch) | ✅ needs `CAP_NET_ADMIN` | ❌ | ❌ | ❌ | `sockopt_linux.go:17-21`. Documented "Linux only". |
| `interface` | **Yes** | ✅ `SO_BINDTODEVICE` | ✅ `IP_UNICAST_IF` / `IPV6_UNICAST_IF` (also `IP_MULTICAST_IF` for UDP) | ✅ `IP_BOUND_IF` / `IPV6_BOUND_IF` | ⚠️ build-dependent | `sockopt_linux.go:23-27`, `sockopt_windows.go:35-67`, `sockopt_darwin.go:136-148`. Doc says Linux/iOS/macOS/Windows. |
| `bindAddress` | — | ❌ | ❌ | ❌ | ❌ | **Does not exist** in current `SocketConfig` (`transport/internet/config.pb.go`, fields 1–23). Do not plan around it. |
| `sendThrough` (OutboundObject) | **No** | ✅ TCP | ✅ TCP | ✅ TCP | ✅ TCP | The outbound doc states explicitly that because UDP is connectionless Xray cannot know the original destination, so this "cannot take effect for UDP" ([Outbound doc](https://xtls.github.io/en/config/outbound.html)). |
| `tcpFastOpen` | No (TCP only) | ✅ | ⚠️ docs say the Windows implementation is incorrect | ⚠️ "needs testing" | ⚠️ | `isTCPSocket` gate. |
| `domainStrategy` | Resolution only | ✅ | ✅ | ✅ | ✅ | Not a NAT mechanism. The doc warns explicitly about a DNS ↔ proxy **infinite loop** when the server address is a domain — relevant to loop prevention (use `hosts` or route DNS direct). |
| `customSockopt` with `"network": "udp"` | **Yes** | ✅ int/str | ⚠️ int only, `str` unsupported | ✅ | ✅ (linux) | Escape hatch for e.g. `IP_BOUND_IF`/`SO_BINDTODEVICE` not covered elsewhere. |
| `tproxy` | **Yes** in `"tproxy"` mode | ✅ root / `CAP_NET_ADMIN` | ❌ | ❌ | ❌ | Linux only; "tproxy" supports TCP **and UDP**. |
| `receiveOriginalDestAddress` | **UDP only**, inbound | ✅ | ❌ | ❌ | ❌ | Not exposed in the JSON docs; used by TProxy internals. |
| `autoOutboundsInterface` (TUN inbound) | n/a (binds all outbounds) | ✅ | ✅ | ✅ | ⚠️ **UNVERIFIED** | The purpose-built loop-prevention switch for a TUN-mode client; equivalent to setting `sockopt.interface` on every outbound and on the built-in DNS local modes. [TUN doc](https://xtls.github.io/en/config/inbounds/tun.html). |

### 1.5 Detection-relevant strings and signals in Xray

These are literal strings in current source and can be matched in MyVpn's log tailer without guessing:

- `XTLS rejected UDP/443 traffic` — [`proxy/vless/outbound/outbound.go:259`](https://raw.githubusercontent.com/XTLS/Xray-core/main/proxy/vless/outbound/outbound.go)
- `XUDP rejected UDP/443 traffic` — [`app/proxyman/outbound/handler.go:220`](https://raw.githubusercontent.com/XTLS/Xray-core/main/app/proxyman/outbound/handler.go)
- `XUDP hit <GlobalID>` / `XUDP new <GlobalID>` — session **migration succeeded / was created**; enable with `XRAY_XUDP_SHOW=true` — [`common/xudp/xudp.go:74-76,35`](https://raw.githubusercontent.com/XTLS/Xray-core/main/common/xudp/xudp.go), [`common/mux/server.go:209,227,237`](https://raw.githubusercontent.com/XTLS/Xray-core/main/common/mux/server.go)
- `establishing new connection for <dest>` — a new per-destination egress session is being created (on the server side, `XRAY_CONE_DISABLED=true` produces one per destination instead of one per client source) — [`transport/internet/udp/dispatcher.go:87`](https://raw.githubusercontent.com/XTLS/Xray-core/main/transport/internet/udp/dispatcher.go). Note the dispatcher reuses a live session, so this fires once per session lifetime rather than once per datagram — do not use its raw frequency as a direct cone indicator.
- `failed to set SO_MARK` / `failed to set Interface` — sockopt silently degraded (`sockopt_linux.go`) — **this is the signal that loop prevention did not apply**.
- Idle timeouts are governed by `policy.levels.<n>.connIdle` (default 300 s) and by a hard-coded 1-minute idle timer in the UDP dispatcher ([`transport/internet/udp/dispatcher.go:102`](https://raw.githubusercontent.com/XTLS/Xray-core/main/transport/internet/udp/dispatcher.go)).

### 1.6 Historical / version facts (for correct config generation)

- **Xray abandons semantic versioning from v1.8.24.** The [v1.8.24 release notes](https://github.com/XTLS/Xray-core/releases/tag/v1.8.24) state the next version would be date-based, e.g. `v24.8.30`. The first date-based tags are the `v25.x` series (tag list via GitHub API); current `main` is `26.9.9`. **MyVpn must gate features on the version, not on a `1.x` comparison.**
- **Cone/UDP-FullCone predates date versioning.** The environment switch was added in commit [`d1704162` "Add environment variable XRAY_CONE_DISABLED option"](https://github.com/XTLS/Xray-core/commit/d17041621942eef8789ab1d3748cf3718b8061fc) (2021-02-11), alongside `Refactor: VLESS & VMess & Mux UDP FullCone NAT`. The [v1.4.0 release notes](https://github.com/XTLS/Xray-core/releases/tag/v1.4.0) already describe single-XUDP handling for VLESS/VMess and the port-53/443 exclusion. v1.4.0 source confirms the same `XRAY_CONE_DISABLED` mechanism and the same `h.cone && port != 53 && port != 443` condition — **behaviour is unchanged from 2021 to 26.9.9**. The [v1.3.0 release notes](https://github.com/XTLS/Xray-core/releases/tag/v1.3.0) are the origin of the "FullCone has nothing to do with the local NAT environment" and "false FullCone" statements quoted in §1.1.
- **`proxy/freedom/fullcone.go` never existed.** The GitHub commits API for that exact path on `XTLS/Xray-core` returns an empty list, i.e. it has never existed on the default branch (which covers all tags). Any documentation that tells users to set a `"fullcone"` key in the freedom outbound settings is describing something other than Xray-core; MyVpn must **never** emit such a key. The only supported way to change cone behaviour is the `XRAY_CONE_DISABLED` environment variable. **⚠ OVERSTATED / WRONG** in the wild.
- **`env` block ordering (verified by code path, not just docs):** `infra/conf.Config.Build()` calls `os.Setenv` for every `env` entry ([`infra/conf/xray.go:529-535`](https://raw.githubusercontent.com/XTLS/Xray-core/main/infra/conf/xray.go)) and produces the `*core.Config` that `core.New()` later consumes; `initInstanceWithConfig` only then reads `XRAY_CONE_DISABLED` ([`core/xray.go:189-194`](https://raw.githubusercontent.com/XTLS/Xray-core/main/core/xray.go)). So `"env": {"XRAY_CONE_DISABLED": "true"}` in `config.json` **does** work. Setting the OS environment variable on the child process is still preferable, because it cannot be lost if config merging changes.
- **`TransportKind` gap:** `MyVpn.Core/Domain/Enums.cs` has `Quic = 6` but no `Hysteria`; `ProxyProtocol` has no `Hysteria`/`WireGuard`. If UDP-based transports are ever offered, those enums need new members.

### 1.7 External standards this matrix relies on

**Use RFC 4787's vocabulary, not the RFC 3489 cone names.** RFC 4787 §3 states that the cone terminology "has been the source of much confusion, as it has proven inadequate at describing real-life NAT behavior", and defines **two independent axes**: *mapping* (which external `ip:port` the NAT assigns) and *filtering* (which inbound packets it admits). They are independent: a NAT can be Endpoint-Independent Mapping with Address-and-Port-Dependent Filtering, which is common and is **not** "Symmetric". Legacy equivalence (community convention, not normative): Full Cone = EIM+EIF, Restricted Cone = EIM+ADF, Port-Restricted Cone = EIM+APDF, Symmetric = ADM or APDM.

- NAT behaviour vocabulary: **RFC 4787** <https://www.rfc-editor.org/rfc/rfc4787.txt> (EIM required by REQ-1; UDP mapping timer ≥ 2 min by REQ-5; determinism by REQ-11).
- STUN: **RFC 5389** <https://www.rfc-editor.org/rfc/rfc5389.txt>, obsoleted by **RFC 8489** <https://www.rfc-editor.org/rfc/rfc8489.html>; NAT behaviour discovery: **RFC 5780** (Experimental) <https://www.rfc-editor.org/rfc/rfc5780.txt>; legacy cone taxonomy: **RFC 3489** (obsolete) <https://www.rfc-editor.org/rfc/rfc3489.txt>.
- CGNAT: **RFC 6598** (`100.64.0.0/10`, <https://www.rfc-editor.org/rfc/rfc6598.txt>), **RFC 6888** (<https://www.rfc-editor.org/rfc/rfc6888.txt>) — REQ-1 (CGNs must satisfy RFC 4787 for UDP), REQ-2 ("paired" IP pooling so the subscriber's external address is stable), REQ-4 (configurable per-subscriber port limits — a real cause of new-flow failures), REQ-7 (EIF recommended), REQ-8 (deallocated ports not reused for ≥ 120 s), REQ-9 (a CGN **must** implement PCP).
- NAT64/DNS64: **RFC 6146**, **RFC 6147**, **RFC 6052** (`64:ff9b::/96` and the legal prefix lengths), **RFC 7050** (`ipv4only.arpa`, <https://www.rfc-editor.org/rfc/rfc7050.txt>), **RFC 8781** (RA `PREF64`, option type 38), **RFC 7225** (PCP-based prefix discovery), **RFC 6877** (464XLAT/CLAT).
- Port-mapping protocols: **RFC 6886** (NAT-PMP), **RFC 6887** (PCP).
- QUIC: **RFC 9000**. Address selection / Happy Eyeballs: **RFC 8305** — Xray implements this for **TCP only**, and only when `sockopt.domainStrategy` is **not** `AsIs` ([Sockopt doc](https://xtls.github.io/en/config/transports/sockopt.html)).

**RFC 8781 §5.1 precedence** for NAT64-prefix discovery, which MyVpn should follow: PCP-discovered (RFC 7225) **>** RA `PREF64` option **>** RFC 7050 `ipv4only.arpa`. A `Pref64::/n` is **interface / provisioning-domain scoped** and must be re-discovered on network change, never cached globally.

---

## 2. Architecture proposal

### 2.1 Detection logic (what MyVpn can actually implement)

Ordered by *value per unit of complexity*. Probes 1–4 are cheap and decide almost everything; 5–6 need standards work; 7–10 are for verification, reporting and tuning. Nothing here may be inferred from a single failed probe.

| # | Probe | How | Confidence | Why it matters |
| --- | --- | --- | --- | --- |
| 1 | **Can this machine send/receive UDP to the Xray server?** | Send N=5 small UDP datagrams to `server:port` from a socket bound to the physical interface and wait for a reply; when the server speaks only TCP, fall back to a *behavioural* probe: build a config with a UDP transport (mKCP) and see whether the handshake completes within ~3 s. | High for "blocked vs not"; medium for "degraded" | Decides whether mKCP/Hysteria/SS-native-UDP may ever be used. |
| 2 | **Five-point cross-check.** Probe (a) a STUN server on 3478, (b) a STUN server on 443, (c) a QUIC server on 443, (d) the Xray endpoint on its real UDP port, (e) the Xray endpoint over TCP. | The **pattern** of successes isolates the cause: all fail = UDP blocked; only (d) fails = endpoint IP/port blocked or APDF filtering; (a) works but (c) fails = UDP/443 specifically blocked; everything works but throughput collapses = rate limiting. | Medium–high | A single STUN failure must **never** be read as "UDP is blocked" — it may be that one STUN port is filtered. Also check whether the probe egressed the same interface as the tunnel socket. |
| 3 | **Is UDP/443 (QUIC) usable?** | A UDP probe to a known QUIC endpoint, with a TCP/443 control probe. Sending a real QUIC Initial (or anything that elicits a Version-Negotiation/Retry) is more informative than a bare datagram. A STUN binding to a server on 443 (e.g. `stun.nextcloud.com:443`) separates "UDP/443 dropped" from "QUIC payload filtered". | Medium | Decides `xudpProxyUDP443` and whether to warn about QUIC-only apps. QUIC/UDP-443 blocking is a documented real-world censorship technique (see the USENIX Security 2025 GFW QUIC study, [ACM DL](https://dl.acm.org/doi/10.5555/3766078.3766119)). |
| 4 | **Address-family availability** | Enumerate interfaces + routing table: is there a global IPv6 address and an IPv6 default route? Any global IPv4 and IPv4 default route? Is the only IPv4 address inside `100.64.0.0/10` or RFC 1918? | High for local facts | Chooses IPv6-first vs IPv4-first, and drives the IPv6-only and NAT64 branches. |
| 5 | **NAT64/DNS64** | Per **RFC 8781 §5.1 precedence**: PCP (RFC 7225) **>** RA `PREF64` option (type 38) **>** RFC 7050. For RFC 7050: query `AAAA ipv4only.arpa` **with CD=0** (a MUST — with CD=1 a DNS64 resolver will not synthesize and will reveal nothing), then locate the well-known IPv4 bytes (`192.0.0.170`/`.171`) at an RFC 6052 embedding position **on octet boundaries** and appearing exactly once; the preceding bytes give `Pref64::/n`. Confirm functionally (ICMPv6 echo or a real connection to a synthesized address). **MUST NOT** probe `ipv4only.arpa` itself for connectivity — no server is operated there. Cache per interface; do not cache globally. | High when positive | Without this, an IPv6-only client fails confusingly. Cross-check with A-vs-AAAA on a known IPv4-only name. |
| 6 | **NAT mapping/filtering behaviour** | RFC 5780 Test II (mapping) and Test III (filtering) against **two independent** servers that actually advertise `OTHER-ADDRESS`; require agreement, otherwise report `Unknown`. Mapping lifetime via a binding request, wait, re-request. | **Low–medium by nature** | Used for *reporting* ("your local NAT is Symmetric") and for the "FullCone via proxy" comparison — never as the sole input for transport choice. |
| 7 | **Tunnel-level verification** | Run the same NAT-type test *through the tunnel*; if local = Symmetric but through-tunnel = FullCone, cone is genuinely delivering. Cross-check the Xray log for `XUDP hit/new` (enable `XRAY_XUDP_SHOW=true`) and for `establishing new connection for`. | Medium–high | The only honest way to claim "UDP FullCone". |
| 8 | **Interception / DPI environment** | MyVpn's own TCP/443 probe to the server: capture the certificate chain; if the leaf is signed by an enterprise root CA the local machine trusts, TLS interception is happening. Also flag when only 443/80 egress works. | Medium | REALITY/TLS-pinning assumptions break under MITM; the strategy must switch to a plain-TLS-shaped transport and warn. |
| 9 | **CLAT / 464XLAT detection** | A **private** RFC 1918 IPv4 address *plus* a default IPv4 route on an otherwise IPv6-only access network is a 464XLAT CLAT, **not** real IPv4 connectivity (RFC 6877). Distinguish "native IPv4", "CLAT-provided private IPv4", "no IPv4". | Medium | Determines whether IPv4 literals are genuinely reachable or only appear to be. 464XLAT is explicitly client-server only and does not support inbound IPv4. |
| 10 | **UDP path quality** | 30–60 s of UDP echo: loss %, RTT p50/p95, jitter (RFC 3550 §6.4.1), reordering, and mapping-lifetime estimate. | Medium | Feeds the "UDP is degraded, prefer TCP-carried UDP" decision. |

**On STUN server choice (empirically verified during this research).** `stun.l.google.com:19302` **does not support RFC 5780**: a plain Binding Request returns only `XOR-MAPPED-ADDRESS` (no `OTHER-ADDRESS`, no `RESPONSE-ORIGIN`), and a `CHANGE-REQUEST` is silently ignored rather than answered with 420. It therefore cannot be used for mapping Test II/III or filtering Test II/III at all. Servers that did advertise the RFC 5780 usage in testing: `stun.voipgate.com:3478`, `stun.sipgate.net:3478`, `stun.nextcloud.com:443`. `pion/stun`'s documented default prober is `stun.voipgate.com:3478`.

**On the validity of NAT-type results at all.** RFC 5780 is Experimental and says so plainly: it "does not allow an application behind a NAT to make an absolute determination of the NAT's characteristics … NAT devices do not behave consistently enough to predict future behavior with any guarantee", and "under load NATs may transition to the most restrictive filtering and mapping behavior and shorten the lifetime of new and existing bindings. In short, applications can discover how bad things currently are, but not how bad things will get." Results are per source port and per destination; tests should use a fresh, long-unused source port. This is the direct justification for `Unknown` being a first-class result and for caching with a TTL rather than storing a permanent "NAT type".

**Explicit anti-goal:** MyVpn must not present a NAT type as authoritative. Report it as `{mapping, filtering, confidence}` with `Unknown` as a first-class value, and always distinguish **Local NAT** from **NAT observed through the proxy**. Probes must run on the **physical** interface, never through the TUN — otherwise they measure the proxy or the NAT64, not the local access network.

### 2.2 Decision table

Inputs: `environment` (from §2.1), `profile` (protocol/transport/flow), `preferences` (user policy).

| Condition | Chosen plan | Rationale |
| --- | --- | --- |
| Default, nothing special detected | TCP-shaped transport (RAW/TLS/REALITY or WS/gRPC/XHTTP over TLS) **+ cone on** (do not set `XRAY_CONE_DISABLED`) **+** `mux.enabled: true, concurrency: -1, xudpConcurrency: 16, xudpProxyUDP443: "reject"` | Survives UDP blocking, gives cone/return-traffic and session migration, keeps TCP HOL away from UDP by disabling TCP mux |
| UDP to server **verified working**, transport is mKCP/Hysteria, or user asked for low latency | same, but `xudpProxyUDP443: "skip"` and consider native paths | Let QUIC/UDP-443 use the protocol-native UDP path |
| UDP to server **blocked** (corporate, some carriers) | Force TCP-only: `xudpProxyUDP443: "reject"`, no mKCP/Hysteria, no SS-native-UDP, warn that QUIC-only apps will fall back to TCP | Proxied UDP still works because it is inside the TCP tunnel |
| UDP to server **degraded** (loss > 5 % or mapping lifetime < 60 s) | Prefer UoT/XUDP over a TCP transport; raise `connIdle`; add app-level keepalives for long-lived UDP sessions | Short CGNAT timers kill native UDP sockets silently |
| IPv6 available and server has AAAA | Prefer IPv6 for the tunnel; `domainStrategy: "UseIPv6v4"` (or `UseIP` + `happyEyeballs` with `prioritizeIPv6`) | Bypasses IPv4 CGNAT entirely; often no NAT66 |
| IPv6-only client, server AAAA present, no NAT64 needed | Force IPv6; fail fast with an explicit error if the profile has only an IPv4 literal | Otherwise the failure is an opaque connect timeout |
| IPv6-only client, NAT64/DNS64 present, server IPv4-only | Allow synthesized connect; `domainStrategy: "UseIPv6"`; disable IPv4 literals; never rely on inbound UDP | NAT64 translates outbound UDP but creates no inbound mapping |
| Client has a private IPv4 address + IPv4 default route on an IPv6-only access network (464XLAT CLAT) | Treat as CLAT-backed, not native IPv4; prefer IPv6; never advertise inbound IPv4 features | RFC 6877: 464XLAT is client-server only and does not support inbound IPv4 |
| Profile address is an IPv4 literal and the network is IPv6-only without NAT64 synthesis for literals | Fail fast with a specific error; do not silently attempt and time out | Hardcoded literals bypass DNS64 entirely (the #1 practical NAT64 breakage) |
| Tunnel mode = TUN | Set `autoOutboundsInterface` on the TUN inbound (or `sockopt.interface` on every outbound) | Loop prevention; see §2.4 |
| TLS interception detected | Prefer a standard-TLS-shaped transport; do not claim REALITY works; surface a warning | REALITY's security model assumes no local MITM |
| Local NAT Symmetric **and** user wants P2P/full-cone semantics | Keep cone on, then verify through-tunnel; explain that only the *proxied* mapping becomes full-cone | Honest framing of what cone can and cannot do |

### 2.3 C# interface

Aligned with the conventions already in the repo (`MyVpn.Core.Domain` records + enums, `MyVpn.Core.Results.Result`/`MyVpnError`/`ErrorCodes`, platform code behind `MyVpn.Platform.Abstractions`).

```csharp
namespace MyVpn.Core.Domain;

/// <summary>How the local NAT maps an internal (ip:port) to an external (ip:port). RFC 4787 §4.</summary>
public enum NatMappingBehavior { Unknown, EndpointIndependent, AddressDependent, AddressAndPortDependent }

/// <summary>Which external senders may reach an internal (ip:port). RFC 4787 §5.</summary>
public enum NatFilteringBehavior { Unknown, EndpointIndependent, AddressDependent, AddressAndPortDependent }

/// <summary>Usability of UDP from this host to the configured server endpoint.</summary>
public enum UdpEgressHealth { Unknown, Allowed, Blocked, RateLimited, Degraded }

public enum AddressFamilyAvailability { None, Ipv4Only, Ipv6Only, DualStack }

public enum ProbeConfidence { Unknown, Low, Medium, High }

/// <summary>
/// Everything the strategy selector is allowed to know about the network.
/// Every field is optional-by-design: Unknown must never be treated as a negative result.
/// </summary>
public sealed record NetworkEnvironment
{
    public NatMappingBehavior LocalMapping { get; init; } = NatMappingBehavior.Unknown;
    public NatFilteringBehavior LocalFiltering { get; init; } = NatFilteringBehavior.Unknown;
    public NatMappingBehavior ThroughProxyMapping { get; init; } = NatMappingBehavior.Unknown;

    public AddressFamilyAvailability Families { get; init; } = AddressFamilyAvailability.None;
    public bool BehindCarrierGradeNat { get; init; }
    public bool BehindDoubleNat { get; init; }

    public bool Nat64Available { get; init; }
    /// <summary>RFC 6052 prefix, e.g. "64:ff9b::/96". Null when unknown.</summary>
    public string? Nat64Prefix { get; init; }
    public bool Dns64Available { get; init; }

    public UdpEgressHealth UdpToServer { get; init; } = UdpEgressHealth.Unknown;
    public bool Udp443Reachable { get; init; }
    public TimeSpan? UdpMappingLifetime { get; init; }
    public double UdpLossPercent { get; init; }
    public TimeSpan? UdpRttP95 { get; init; }

    public bool TlsInterceptionDetected { get; init; }
    public bool OnlyPort443Egress { get; init; }

    /// <summary>Physical interface the tunnel must leave through. Null when not determined.</summary>
    public string? PhysicalInterface { get; init; }

    public ProbeConfidence Confidence { get; init; } = ProbeConfidence.Unknown;
}

/// <summary>A concrete, serialisable Xray configuration choice for one outbound.</summary>
public sealed record TransportPlan
{
    public required TransportKind Transport { get; init; }
    public required SecurityKind Security { get; init; }

    /// <summary>false disables Xray's cone handling (process env XRAY_CONE_DISABLED=true).</summary>
    public bool ConeEnabled { get; init; } = true;

    /// <summary>Xray mux.enabled. Required for XudpConcurrency to have any effect at all.</summary>
    public bool MuxEnabled { get; init; }

    /// <summary>Xray mux.concurrency. -1 disables TCP mux while keeping XUDP available.</summary>
    public int MuxConcurrency { get; init; } = -1;

    /// <summary>Xray mux.xudpConcurrency. -1 = protocol-native UDP (UoT for VLESS), 0 = default, &gt;0 = XUDP.</summary>
    public int XudpConcurrency { get; init; }

    /// <summary>"reject" | "allow" | "skip". Only honoured when MuxEnabled is true.</summary>
    public string XudpProxyUdp443 { get; init; } = "reject";

    /// <summary>sockopt.interface — the only portable loop-prevention knob that reaches UDP.</summary>
    public string? Interface { get; init; }

    /// <summary>SO_MARK (Linux only).</summary>
    public int? Mark { get; init; }

    public string? SendThrough { get; init; }
    public string? DomainStrategy { get; init; }
    public bool HappyEyeballs { get; init; }
    public bool TcpFastOpen { get; init; }

    /// <summary>Environment variables to set on the Xray child process (e.g. XRAY_CONE_DISABLED).</summary>
    public IReadOnlyDictionary<string, string> XrayEnvironment { get; init; }
        = new Dictionary<string, string>();

    /// <summary>Localized reason keys explaining this choice; surfaced in diagnostics.</summary>
    public IReadOnlyList<string> ReasonKeys { get; init; } = Array.Empty<string>();

    /// <summary>Next plan to try if this one fails its health check.</summary>
    public TransportPlan? Fallback { get; init; }
}

public sealed record TransportPreferences
{
    public bool AllowUdpTransports { get; init; }
    public bool PreferLowLatency { get; init; }
    public bool RequireFullCone { get; init; }
    public bool IsTunnelMode { get; init; }
}
```

```csharp
namespace MyVpn.Platform.Abstractions;

using MyVpn.Core.Domain; // ServerEndpoint lives here

/// <summary>Collects a NetworkEnvironment snapshot. Never throws; failures degrade to Unknown.</summary>
public interface INetworkEnvironmentProbe
{
    Task<NetworkEnvironment> ProbeAsync(ServerEndpoint server, CancellationToken ct);
}

/// <summary>Binds a socket to the physical interface so it cannot re-enter the tunnel.</summary>
public interface IPhysicalSocketBinder
{
    /// <summary>Returns false when the platform cannot bind here; the caller must then refuse TUN mode.</summary>
    bool TryBindToInterface(System.Net.Sockets.Socket socket, string interfaceName);
    IReadOnlyList<string> EnumeratePhysicalInterfaces();
    string? GuessPhysicalInterface();
}
```

```csharp
namespace MyVpn.Application.Transport;

public interface ITransportStrategySelector
{
    /// <summary>Pure, deterministic, side-effect free.</summary>
    Result<TransportPlan> Select(
        NetworkEnvironment environment,
        ServerProfile profile,
        TransportPreferences preferences);
}

public interface ITransportPlanVerifier
{
    /// <summary>Applies a plan, runs the health probe, returns the plan to keep or the fallback to try.</summary>
    Task<Result<TransportPlan>> VerifyAsync(
        TransportPlan plan, ServerEndpoint server, CancellationToken ct);
}
```

### 2.4 Fallback ordering

Strict, bounded, no cycles. Each step is verified by a probe before the next is attempted; a step is skipped rather than retried when its precondition is known-bad.

```
0. Honour explicit user choice (manual override always wins; never silently "improve" it)
1. XUDP + cone over TLS-shaped TCP           (mux.enabled=true, concurrency=-1, xudpConcurrency=16, udp443=reject)
2. Plain UoT                                  (xudpConcurrency=-1)         — if step 1 stalls/HOL or the server rejects Mux
3. TCP-only / QUIC-suppressed                 (udp443=reject, no UDP transports) — if UDP is blocked
4. UDP transport (mKCP/Hysteria)              ONLY if UDP-to-server verified Allowed AND user opted in
5. Address-family overlay                     IPv6-first, then NAT64-synthesized IPv6 — applied on top of 1..4
6. Different ServerProfile (score-ordered)    last resort; the failure is the endpoint, not the transport
```

Loop prevention: the chain is a `TransportPlan.Fallback` linked list built once, with a depth cap (≤ 4) and a per-step budget. `TransportPlanVerifier` must not re-enter step *n* after moving to step *n+1* within one connection attempt.

### 2.5 Loop prevention and physical-interface binding

| Layer | Linux | Windows | macOS/iOS | Android | Reaches UDP? |
| --- | --- | --- | --- | --- | --- |
| Xray `sockopt.interface` | `SO_BINDTODEVICE` (needs `CAP_NET_ADMIN`, and `CAP_NET_RAW` on newer kernels) | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` (ifindex as a `DWORD` in **network byte order**) | `IP_BOUND_IF` (25) / `IPV6_BOUND_IF` (125) | build-dependent | **Yes** |
| Xray `sockopt.mark` | `SO_MARK` + `ip rule fwmark` (needs `CAP_NET_ADMIN`) | ❌ | ❌ | ❌ | Yes |
| Xray `sendThrough` | ✅ | ✅ | ✅ | ✅ | **No** — doc says it cannot take effect for UDP |
| Xray TUN `autoOutboundsInterface` | ✅ | ✅ | ✅ | ⚠️ UNVERIFIED | n/a (applies the binding for you) |
| MyVpn probe sockets | P/Invoke `setsockopt(SO_BINDTODEVICE)`, or bind the source IP; `IP_PKTINFO` for per-datagram source selection | Bind to the physical interface's IP (works for UDP), or P/Invoke `IP_UNICAST_IF` / `IP_PKTINFO` | P/Invoke `IP_BOUND_IF` / `IPV6_BOUND_IF` | `VpnService.protect(fd)` | Yes |

Platform notes that matter for a real implementation:

- **Windows has no `SO_BINDTODEVICE`.** `IP_UNICAST_IF` requires the interface index in network byte order and, per Microsoft's docs, "does not change the default interface for receiving" — it is an egress selector only. `GetAdaptersAddresses` supplies the index.
- **Android's canonical mechanism is `VpnService.protect(...)`** (or `Network.bindSocket`), applied to every socket the tunnel uses *before* connecting. Xray's `sockopt.interface` may be insufficient there — **UNVERIFIED**.
- **Apple's `IP_BOUND_IF`/`IPV6_BOUND_IF` are the established path.** Apple's private `socket_private.h` also exposes `SO_NOWAKEFROMSLEEP` (`0x10000`) and `SO_RESTRICTIONS`/`SO_RESTRICT_DENY_*` (`DENY_CELLULAR`, `DENY_EXPENSIVE`, `DENY_CONSTRAINED`), which are attractive for path selection but are **private API** — using them risks App Store rejection; verify per target before adopting.
- **FreeBSD** has no `SO_BINDTODEVICE`/`IP_BOUND_IF` equivalent (Xray's own TUN code comments on this), so treat interface binding there as **UNVERIFIED / likely unsupported**.

**Loop prevention must combine at least two independent mechanisms:**

1. **Host-route exception:** add a `/32` (IPv4) or `/128` (IPv6) route to the server via the **physical** gateway before installing `0.0.0.0/0` / `::/0` into the TUN. This is the universal approach and is what MyVpn's route code must do first.
2. **Bind the tunnel's sockets to the physical interface** so the outer packets leave the physical NIC even if the routing table is wrong (per the table above; in Xray this is `sockopt.interface`, or `autoOutboundsInterface` for TUN mode).
3. **Policy routing / fwmark** so DNS, probe traffic and the transport bypass the TUN table (Linux: `ip rule fwmark`; the Xray `mark` option exists for exactly this).
4. **Keep probe sockets off the tunnel** (see §2.1) and **re-run interface-scoped discovery** (NAT64 prefix, address families) on every network change.

**Hard requirement:** in TUN mode, if neither `autoOutboundsInterface` nor an equivalent interface binding can be established, MyVpn must refuse to start the tunnel rather than risk a routing loop. The Xray docs call this out directly ("Be aware of potential traffic loop issues … requests initiated by Xray might be sent back to Xray, causing a loop").

**Also required:** the DNS loop. If the server address is a domain and DNS is answered through the tunnel, Xray's own doc describes a deadlock. MyVpn should pin the server's address via `hosts` in the generated config, or guarantee by routing that resolution of the server domain is direct.

---

## 3. Risks

| # | Risk | Impact | Mitigation |
| --- | --- | --- | --- |
| R1 | **Cone is not actually delivering full-cone**, because a profile enables XUDP-looking options but `mux.enabled` is false, or `XRAY_CONE_DISABLED` is set | User pays for "full cone" and gaming/VoIP still fails; hard to diagnose | The selector must always emit `mux.enabled` explicitly; add a startup assertion that reads back the effective plan; verify through-tunnel with §2.1 probe 7 |
| R2 | **Vendor-marketing trap:** UI says "Full Cone NAT" and users conclude their *local* NAT is now full-cone | Support burden; wrong mental model; misdiagnosed P2P failures | UI must label it "FullCone **for proxied traffic**" and display Local NAT and Through-Proxy NAT side by side |
| R3 | **UDP injection surface** in cone mode (unconnected egress socket, no source filtering, one port shared per client session) | Malicious/spoofed UDP injected into a client's session | Make cone a documented, user-visible trade-off; default the *transport* to TCP-carried UDP; offer a "strict UDP isolation" profile that sets `XRAY_CONE_DISABLED=true`; never claim cone is free |
| R4 | **NAT64 breaks inbound and is endpoint-dependent** | "FullCone" cannot hold end-to-end; hardcoded IPv4 literals fail; DNSSEC validation may fail with DNS64 | Detect via RFC 7050; force DNS-based destinations; disable inbound-dependent features and say so |
| R5 | **Silent sockopt failure** (`failed to set SO_MARK` / `failed to set Interface` is only a log line; the core continues) | TUN mode loop or leak while the UI shows "connected" | Tail Xray logs for these exact strings; if the interface binding was required and the log line appears, tear the tunnel down |
| R6 | **CGNAT mapping expiry** kills long-idle UDP sessions with no ICMP | Apps silently stop receiving (VoIP, push, game sessions) | Detect mapping lifetime; prefer TCP-carried UDP; raise `connIdle`; app-level keepalives |
| R7 | **Version-gating mistakes** (treating `26.9.9` as older than `1.8.24`, or requiring `fullcone` JSON key) | Config rejected or silently ignoring options | Feature-detect via `xray version` + a parse rule that understands date-based versions; never reference a `fullcone` JSON key |
| R8 | **NAT-type detection presented as fact** when it is inherently non-deterministic | Wrong automatic decisions; user distrust | `Unknown` is a first-class result; require two independent STUN servers to agree; never let `Unknown` force a UDP-based transport |
| R9 | **Hysteria/mKCP chosen on a network where UDP works only to port 443 or only intermittently** | Tunnel flaps | Only enable UDP transports after §2.1 step 1 passes with margin (≥ 4/5 replies, loss < 5 %) |
| R10 | **TLS interception under REALITY** | Handshake fails cryptically, or security assumptions silently broken | Detect enterprise CA in the chain; switch to a plain-TLS transport and warn; do not attempt REALITY |
| R11 | Polling/`observatory` traffic itself being fingerprinted | Censorship detection of MyVpn clients | Use `burstObservatory` (randomized probe times) rather than fixed-interval `observatory`; the Xray doc explicitly notes the fixed-interval fingerprint risk |
| R12 | **"False FullCone" measurement** — a NAT-type test run through the proxy reports FullCone while the local NAT is symmetric, and MyVpn repeats that claim to the user | Trust damage; wrong diagnosis when a game/WebRTC app still cannot be reached locally | Run behaviour discovery on the **physical** interface (never through the TUN/proxy); label the two results separately; Xray itself warns about this exact artefact in its v1.3.0 notes |
| R13 | **Hardcoded IPv4 literals on an IPv6-only / NAT64 network** — update endpoints, STUN IPs, DNS IPs, or an IP-literal server profile | Connections fail with no useful error; the tunnel never comes up | Never store IP literals where a hostname works; synthesize via a discovered `Pref64::/n` when a literal is unavoidable; detect and surface the condition explicitly (RFC 7050 / RFC 8781) |
| R14 | **464XLAT CLAT mistaken for real IPv4** — a private RFC 1918 address plus an IPv4 default route on an IPv6-only access network | MyVpn concludes "IPv4 works", then IPv4 P2P/inbound and IPv4 literals fail unexpectedly; 464XLAT does not support inbound IPv4 | Detect the CLAT pattern (private v4 + IPv4 default route + a discovered NAT64 prefix) and record `AddressFamilyAvailability` as CLAT-backed, not native (RFC 6877) |
| R15 | **Trusting DHCP/DNS-provided "IPv4 works" on a captive portal or hijacking resolver** — RFC 7050 false positives are possible from NXDOMAIN hijacking | Wrong NAT64 decision | Validate the returned prefix position against RFC 6052 before accepting it; a hijack that does not place the well-known IPv4 bytes at a legal embedding position must be rejected |

---

## 4. Implementation plan

**Phase 0 — freeze the facts (0.5 day).** Add a generated table of the *effective* mux/sockopt/cone settings to the diagnostics bundle. Add the exact log-string matchers from §1.5. No behaviour change.

**Phase 1 — domain model (1 day).** Add `NatMappingBehavior`, `NatFilteringBehavior`, `UdpEgressHealth`, `AddressFamilyAvailability`, `ProbeConfidence`, `NetworkEnvironment`, `TransportPlan`, `TransportPreferences`, and new `TransportStrategySelectionFailed` / `UdpUnavailable` / `Nat64NotUsable` error codes. Pure data + unit tests.

**Phase 2 — selector (1–2 days).** Implement `TransportStrategySelector` exactly as the §2.2 table, with `Fallback` construction per §2.4. 100 % unit-testable with synthetic `NetworkEnvironment` values; no network I/O.

**Phase 3 — probes (3–5 days).** `INetworkEnvironmentProbe` per platform behind `MyVpn.Platform.Abstractions`:
- shared: address-family/interface enumeration, UDP echo + loss/RTT, QUIC/443 probe, RFC 7050 NAT64 detection, mapping-lifetime test;
- platform: `IPhysicalSocketBinder` P/Invoke per OS, Windows/Android specifics.

**Phase 4 — wire into config generation (1–2 days).** Emit `mux`, `sockopt`, `domainStrategy`, and the `XRAY_CONE_DISABLED` child-process environment variable from `TransportPlan`. Add the startup assertion + log tailer for silent sockopt failure. Add `autoOutboundsInterface` for TUN mode.

**Phase 5 — verification loop (2 days).** `ITransportPlanVerifier` + fallback execution with the depth cap; `burstObservatory` config for per-outbound health.

**Phase 6 — hardening.** Cone-off "strict UDP isolation" profile; NAT64 explicit-fail path; interception detection.

---

## 5. Files / modules affected

**Existing (read, minimal edits):**

| Path | Change |
| --- | --- |
| `src/MyVpn.Core/Domain/Enums.cs` | Add `NatMappingBehavior`, `NatFilteringBehavior`, `UdpEgressHealth`, `AddressFamilyAvailability`, `ProbeConfidence`, `TransportStrategyKind`. Add `Hysteria` to `TransportKind` and `ProxyProtocol` if UDP transports are offered (currently absent). |
| `src/MyVpn.Core/Results/ErrorCodes.cs` | Add `transport.*` codes (`transport.strategy_failed`, `transport.udp_unavailable`, `transport.nat64_unusable`, `transport.sockopt_not_applied`) following the existing `xray.*` / `platform.*` naming style. |
| `src/MyVpn.Infrastructure/Xray/*` (config builder) | Emit `mux`, `sockopt`, `domainStrategy` from `TransportPlan`; set the `XRAY_CONE_DISABLED` child-process env var. |

**New:**

| Path | Purpose |
| --- | --- |
| `src/MyVpn.Core/Domain/NetworkEnvironment.cs` | Probe result record. |
| `src/MyVpn.Core/Domain/TransportPlan.cs` | Selected plan + fallback chain + reason keys. |
| `src/MyVpn.Core/Domain/TransportPreferences.cs` | User policy inputs. |
| `src/MyVpn.Application/Transport/ITransportStrategySelector.cs` | Pure selection interface. |
| `src/MyVpn.Application/Transport/TransportStrategySelector.cs` | The §2.2 decision table + §2.4 fallback construction. |
| `src/MyVpn.Application/Transport/ITransportPlanVerifier.cs` + `TransportPlanVerifier.cs` | Apply → probe → advance-to-fallback. |
| `src/MyVpn.Platform.Abstractions/INetworkEnvironmentProbe.cs` | Cross-platform probe contract. |
| `src/MyVpn.Platform.Abstractions/IPhysicalSocketBinder.cs` | Interface-binding contract. |
| `src/MyVpn.Platform.Linux/PhysicalSocketBinder.cs` | `SO_BINDTODEVICE`; `SO_MARK` plan values. |
| `src/MyVpn.Platform.Windows/PhysicalSocketBinder.cs` | Bind to interface IP / `IP_UNICAST_IF`. |
| `src/MyVpn.Platform.MacOS/PhysicalSocketBinder.cs` | `IP_BOUND_IF` / `IPV6_BOUND_IF`. |
| `src/MyVpn.Platform.*/NetworkEnvironmentProbe.cs` | Per-OS address-family/route inspection; shared UDP/STUN/NAT64 logic in `MyVpn.Infrastructure.Networking`. |
| `src/MyVpn.Infrastructure/Networking/{StunClient,UdpReachabilityProbe,Nat64Detector,InterfaceEnumerator}.cs` | Probe implementation shared across platforms. STUN behaviour discovery via the `Stun.Net` NuGet package; NAT64 prefix via RA `PREF64` / PCP / RFC 7050 in that precedence order. |
| `src/MyVpn.Infrastructure/Xray/XrayLogSignals.cs` | Matchers for the §1.5 strings. |

**Tests:**

`tests/MyVpn.Core.Tests/Transport/TransportStrategySelectorTests.cs`, `tests/MyVpn.Platform.Tests/PhysicalSocketBinderTests.cs`, `tests/MyVpn.Integration.Tests/NatMatrix/*`, plus the netns harness under `docs/research/_checks/` style (scripts only; no production code).

---

## 6. Tests

### 6.1 NAT compatibility test matrix

**Column key** (all cells assume an Xray server on a public IP and a VLESS/VMess/Trojan profile unless stated):

- **PU** — plain proxied UDP: per-destination session, no cone, no XUDP (VLESS/VMess/Trojan `Command=UDP` framing; Shadowsocks native UDP).
- **FC** — cone (FullCone) enabled: the default, i.e. `XRAY_CONE_DISABLED` unset.
- **XU** — XUDP: `mux.enabled: true`, `mux.xudpConcurrency > 0`.
- **UoT** — forced UDP-over-TCP: `mux.xudpConcurrency: -1` (protocol-native path is still TCP-carried for VLESS/VMess/Trojan).
- **TCP** — TCP-only fallback: identical tunnel, QUIC/UDP-443 suppressed by policy.
- **V6** — tunnel over native IPv6.
- **N64** — tunnel over IPv6 to a NAT64/DNS64-synthesized address.

**Cell format:** `outcome · failure mode · detect → react`. `n/a` = mechanism does not apply in this environment.

| NAT environment | PU | FC | XU | UoT | TCP | V6 | N64 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Full Cone (EIM+EIF)** | OK · none for proxied · no action | OK · fails only if server cone off · detect: through-proxy NAT test shows AddressAndPortDependent → unset `XRAY_CONE_DISABLED` and retest | OK · HOL under parallel TCP load · detect: UDP RTT p95 rises with TCP load → keep `concurrency: -1`, raise `xudpConcurrency` | OK · +RTT vs native · detect: p95 vs TCP RTT → reliability default, not for gaming | OK · none · no action | OK if server has AAAA · fails on IPv4-literal profile · detect: AAAA lookup → `domainStrategy: UseIPv6v4` | n/a |
| **Restricted Cone (EIM+ADF)** | OK · same as Full Cone for proxied traffic | OK · remote peers still reachable because the *server* egress is what counts · detect: same through-proxy test | OK · as above | OK · as above | OK · none | OK if AAAA · as above | n/a |
| **Port-Restricted Cone (EIM+APDF)** | OK · direct P2P inbound needs hole-punching, proxied unaffected | OK · proxied mapping remains full-cone | OK · as above | OK · as above | OK · none | OK if AAAA | n/a |
| **Symmetric (APDM)** | OK · **local symmetric NAT does not break proxied UDP**; breaks only direct P2P · detect RFC 5780 Test II = AddressAndPortDependent → do not advertise P2P, keep proxy | OK · the headline case: through-proxy test reports FullCone while local reports Symmetric · detect: compare the two tests → label "FullCone via proxy" | OK · session migration helps if the tunnel reconnects · detect: `XUDP hit` after reconnect → keep GlobalID behaviour | OK · as above | OK · none | OK if AAAA and often the best fix (no NAT66) · detect: dual-stack check → prefer IPv6 | OK via NAT64 but NAT64 mapping is typically APDM, so no inbound · detect RFC 7050 → set expectations, no inbound features |
| **CGNAT (RFC 6598 / RFC 6888)** | WARN · short UDP mapping (~30–120 s) drops long-idle sockets; SS native UDP most exposed; per-subscriber **port limits** (RFC 6888 REQ-4) cause new-flow failures under load · detect: XOR-MAPPED-ADDRESS in `100.64/10` (RFC 6598 space) + mapping-lifetime test + count of successful new flows under load → prefer TCP-carried UDP, raise `connIdle`, keepalives, and use **PCP (RFC 6887)** — which a conforming CGN must support (RFC 6888 REQ-9) — to request a stable mapping | OK · server cone unaffected by CGNAT · detect: mapping-lifetime test → as above | OK\* · XUDP over TCP survives CGNAT timers; fails if the transport itself is UDP · detect: transport type + UDP health → keep the tunnel on TCP | OK · best choice here · no action | OK · none | Preferred if carrier gives native IPv6 · detect: global IPv6 address → IPv6-first | Common on mobile · detect RFC 7050 → force DNS-based destinations, no inbound |
| **Double NAT (CGNAT + home router)** | WARN · as CGNAT plus MTU/PPPoE limits; hole punching impossible · detect: ≥2 private hops / STUN vs local address mismatch → cap MTU, keepalive, TCP-carried UDP | OK · as CGNAT | OK\* · as CGNAT | OK · as CGNAT | OK · none | OK if AAAA · detect: dual-stack check | WARN · as CGNAT/NAT64 |
| **IPv6-only (no IPv4 route)** | FAIL if the profile resolves to IPv4 only and no DNS64 · detect: no global IPv4 + A-only resolution → fail fast, tell the user the server needs AAAA. **Beware a CLAT: a private RFC 1918 IPv4 address plus an IPv4 default route on an otherwise IPv6-only access network is 464XLAT, not real IPv4 connectivity (RFC 6877).** | FAIL · cone is server-side and cannot create IPv6 · detect: same → same | FAIL · same · detect: same | FAIL · same · detect: same | FAIL · tunnel needs an IP family that works · detect: same | OK · tunnel over IPv6; local NAT irrelevant (normally no NAT66) · detect: global IPv6 + v6 default route → IPv6-first | OK only with DNS64 · detect RFC 7050 / RFC 8781 PREF64 → N64 plan |
| **NAT64 / DNS64** | OK via synthesis, TCP and UDP both translate · failure: **hardcoded IPv4 literals bypass DNS64 entirely** (the #1 real-world breakage); DNSSEC validation of synthesized AAAA fails unless the host does DNS64 in stub mode; fragmented UDP and the extra header (MTU) add failure modes; **no inbound UDP at all** · detect RFC 7050 with **CD=0** (and never probe `ipv4only.arpa` for connectivity — RFC 7050 MUST NOT) plus a functional connect → force all destinations through DNS, disable inbound-dependent features | OK\* · cone applies on the server egress, but the end-to-end path through NAT64 is endpoint-dependent, so remote peers see a NAT64 mapping, not full-cone · detect: through-proxy test from an IPv4 client → warn that full-cone claims do not hold across NAT64 | OK · works over TCP; NAT64 UDP mapping life is typically short · detect: mapping-lifetime test → keepalives | OK · TCP-carried, unaffected · no action | OK · simplest correct choice here | FAIL (there is no native IPv6 path to an IPv4-only server) · detect RFC 7050 present → do not attempt V6 | OK · the intended path · detect: `AAAA ipv4only.arpa` yields the well-known IPv4 bytes at an RFC 6052 position → enable N64 plan; prefer RA `PREF64`/PCP discovery when available |
| **Home router (typical UPnP/NAT-PMP)** | OK · mapping lease can expire silently · detect: STUN type + mapping lifetime → keepalive; optionally request a PCP/NAT-PMP mapping (RFC 6887/6886) for direct paths | OK · best-case combination when router is EIM/EIF and server cone is on · detect: local test = EIM/EIF AND through-proxy test = full cone → advertise it | OK · as Full Cone | OK · as Full Cone | OK · none | OK if AAAA | n/a |
| **Mobile carrier network** | WARN/FAIL · UDP frequently blocked or rate-limited, QUIC throttled, CGNAT timers short, DNS possibly hijacked · detect: UDP echo fails or loss > 5 % while TCP works, plus `100.64/10` STUN address → TCP-only: no mKCP/Hysteria, no SS-native-UDP, `xudpProxyUDP443: reject`, MTU 1280 for IPv6 | OK · server cone still works, delivered over the TCP tunnel · detect: log match `XUDP rejected UDP/443 traffic` when expected to pass → expected on carrier QUIC blocks, no action | OK · aggregation reduces handshakes on high-RTT links · detect: reconnect rate → raise `xudpConcurrency` | OK · the recommended path on carriers | OK · expected default | Preferred where native IPv6 exists · detect: global IPv6 → IPv6-first | Common; treat as NAT64 row |
| **Corporate network, strict firewall / DPI** | OK with a TCP transport, FAIL with a UDP transport · the common error is confusing "UDP on the wire" with "UDP through the tunnel": proxied UDP still works because it rides inside the TCP tunnel; what breaks is mKCP/Hysteria and Shadowsocks' native UDP · detect: the §2.1 five-point cross-check fails on (a)(b)(c)(d) but (e) succeeds → force the TCP transport, `xudpProxyUDP443: reject` | OK · cone operates on the server side, unaffected by the corporate policy | OK · as long as the TCP transport is allowed | OK · recommended here | OK · default | FAIL/UNVERIFIED · often no IPv6 or IPv6 blocked · detect: no v6 default route → stay on IPv4 | FAIL · detection fails without DNS64 → stay on IPv4/TCP |
| **Corporate network with TLS interception** | WARN · tunnel may start but REALITY will fail or the security model is void · detect: leaf certificate signed by a trusted enterprise root CA → switch to plain-TLS transport, warn | WARN · same, cone is orthogonal · detect: same | WARN · same | WARN · same | WARN · same | as above | as above |

Cells that must be validated against real hardware (not emulatable): **mobile carrier**, **corporate with TLS interception**, **NAT64 on a real carrier**, **router-specific UPnP/PCP behaviour**, and platform-specific `VpnService.protect()` / interface-binding behaviour on Android and iOS.

### 6.2 Test plan

**Harness (reproducible, Linux netns).**

| Cell dimension | Emulation | Tooling | Metrics |
| --- | --- | --- | --- |
| Full Cone | netns + conntrack with endpoint-independent mapping (`iptables -t nat -A POSTROUTING -j MASQUERADE`) | `ip netns`, `veth`, `iptables`/`nft` | NAT type per RFC 5780, egress-port reuse across 3 destinations |
| Restricted / Port-Restricted | `MASQUERADE` + `-m conntrack --ctstate` filtering rules emulating address-dependent vs address-and-port-dependent filtering | same | filtering classification, inbound success rate |
| Symmetric | `MASQUERADE --random-fully` (or `nft ... masquerade random,persistent` absent) | same | distinct source ports per destination, classification=APDM |
| CGNAT | symmetric setup + outer pool on `100.64.0.0/10` + short timers (`net.netfilter.nf_conntrack_udp_timeout`, `..._stream`) | `sysctl`, `nft` | mapping lifetime in seconds, loss after idle |
| Double NAT | chain two netns routers | same | MTU discovery, hole-punch failure |
| IPv6-only | netns with only IPv6 addresses, `disable_ipv6=0` / no IPv4 addr | `ip -6`, `sysctl` | fail-fast behaviour, IPv6-first selection |
| NAT64/DNS64 | Jool for stateful NAT64 + Unbound `dns64` module | `jool`, `unbound` | RFC 7050 detection result, TCP/UDP success through the translator |
| UDP blocked | `nft` drop all UDP except selected ports | `nft` | plan selection = TCP-only; no UDP transport starts |
| UDP/443 blocked | drop UDP dport 443 | `nft` | QUIC suppression path, log-string match |
| Lossy/jittery UDP | `tc qdisc netem loss 5% delay 50ms` | `tc` | loss/RTT thresholds trigger the "degraded" branch |
| TLS interception | terminate TLS with a test CA, re-sign | `openssl`/`mitmproxy` | interception detection fires; REALITY is not attempted |

**Functional probes per cell:** RFC 5780 Test I/II/III via `pystun3`/`stunclient`/`nattypetester`; QUIC reachability; `iperf3 -u -b` for UDP throughput/loss/jitter; `mtr --udp` for per-hop loss; `tcpdump`/Wireshark for on-wire confirmation that no UDP leaves the host when a TCP-only plan is active; `xray` access log matched for the §1.5 strings; the Xray metrics/stats API for per-outbound UDP counters; `burstObservatory` delays as the health signal.

**In-product implementation choice (for `NatTypeDetector`):** the .NET BCL has **no** STUN API. Use [`Stun.Net`](https://www.nuget.org/packages/Stun.Net/) (the library behind [NatTypeTester](https://github.com/HMBSbige/NatTypeTester); documents RFC 3489, RFC 5780, RFC 8489, UDP/TCP/TLS/DTLS, IPv4+IPv6) for the RFC 5780 behaviour probe, and hand-rolled UDP for the reachability/lifetime probes. [`SIPSorcery`](https://www.nuget.org/packages/SIPSorcery) is a heavier alternative that also brings TURN/ICE. Do **not** depend on `pion/stun` (Go) — it would mean shipping a sidecar. Default probe servers must be ones that actually advertise `OTHER-ADDRESS` (e.g. `stun.voipgate.com:3478`); `stun.l.google.com:19302` must not be used for behaviour discovery.

**Assertions that must hold in every cell:** (a) no traffic leaks outside the tunnel while the tunnel is up; (b) the selected plan's fallback chain terminates within the depth cap; (c) on `sockopt`-failure log lines the tunnel is torn down, not left running; (d) `Unknown` environment never selects a UDP-based transport.

**Emulation caveat (must be recorded in the test report):** netns + conntrack emulates RFC 4787 *behaviour classes*, not real vendor NATs. Real-world NATs are often non-deterministic, mix behaviours per destination, and change under load. Every matrix cell marked "manual" must be re-validated on real networks before any user-facing claim (especially any "Full Cone" claim) is made.

### 6.3 What is UNVERIFIED

- Whether Xray's `sockopt.interface` is effective on Android builds, and whether it is sufficient versus `VpnService.protect()`.
- FreeBSD `sockopt.interface` support (the TUN code comments that FreeBSD has no `SO_BINDTODEVICE`/`IP_BOUND_IF` equivalent, so binding is likely a no-op there).
- The exact Xray tag that introduced the TUN inbound's `autoOutboundsInterface`.
- Hysteria transport/outbound internals beyond their existence and UDP-based nature (not audited line by line here).
- The canonical USENIX presentation URL for the 2025 GFW QUIC-censorship paper (the ACM DL DOI and the paper PDF resolve; the conference-page slug did not).
- Precise official semantics of the `pystun3` and `jselbie/stunclient` CLI flags (used here only as external cross-check tooling, not as an in-product dependency).
- Quantitative, peer-reviewed measurements of ISP UDP *rate limiting* (as opposed to outright blocking): treat "carrier throttles UDP" as a hypothesis the probe must measure, not as an established fact.
- Any claim that Xray can improve the **local** NAT type or provide direct P2P inbound reachability.

**Now verified (was previously listed as unknown):** `stun.l.google.com:19302` does **not** implement RFC 5780 behaviour discovery. This was confirmed empirically during this research (plain Binding Request returns only `XOR-MAPPED-ADDRESS`; `CHANGE-REQUEST` is ignored, not answered with 420), and `stun.voipgate.com:3478`, `stun.sipgate.net:3478` and `stun.nextcloud.com:443` were confirmed to advertise `OTHER-ADDRESS` + `RESPONSE-ORIGIN`.

---

*Report generated as part of the MyVpn research series. Sources are cited inline; the Xray-core revision inspected is `c412e77a9b712082ac9ebf27fa793951cb5a7d85` (26.9.9).*
