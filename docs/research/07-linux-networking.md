# 07 — Linux Platform Networking Design (MyVpn)

**Scope:** Ubuntu, Debian, Fedora, Arch Linux; x86‑64 and arm64. .NET 8 client.
**Status:** authoritative design proposal. Every nftables snippet in this document was
machine‑validated read‑only on the research host (nftables **v1.0.2**, kernel **5.15**)
using `nft -c -f`, which parses and semantically evaluates a ruleset **without
committing it to the kernel**. See §2.10 for the validation method and its limits.

**Host recon (read‑only):** Ubuntu 22.04.5, kernel `5.15.0-127-generic`, `nft v1.0.2`,
`iptables v1.8.7 (nf_tables)`, `iproute2 5.15.0`, `/dev/net/tun` present
(`crw-rw-rw-`, major 10 minor 200), `cgroup2` mounted at `/sys/fs/cgroup` with
controllers `cpuset cpu io memory hugetlb pids rdma misc` and mount option
`nsdelegate`, `/etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf`,
`systemd-resolved` active, `pkcheck`/`pkexec` present, `libmnl`/`libnftnl`/`libnftables`
present. The research shell has **zero effective capabilities**
(`CapEff: 0000000000000000`), so all firewall/TUN/routing work below is marked with
its required privilege and was *not* executed.

---

## 1. Findings

### 1.1 TUN devices

| Fact | Source |
|---|---|
| A program opens `/dev/net/tun` and issues an `ioctl()` to register a network device; the device appears as `tunNN`/`tapNN`. | [kernel: tuntap](https://docs.kernel.org/networking/tuntap.html) |
| **"When the program closes the file descriptor, the network device and all corresponding routes will disappear."** → TUN interfaces are *ephemeral by default*. | [kernel: tuntap](https://docs.kernel.org/networking/tuntap.html) |
| `CAP_NET_ADMIN` is required to create network devices. `/dev/net/tun` being world‑accessible (`0666`) is harmless *because* the ioctl is capability‑checked. | [kernel: tuntap](https://docs.kernel.org/networking/tuntap.html) |
| Flags: `IFF_TUN` (IP frames, no Ethernet header) / `IFF_TAP` (Ethernet frames); `IFF_NO_PI` suppresses the 4‑byte packet‑info prefix. `TUNSETIFF` is the registering ioctl. | [kernel: tuntap](https://docs.kernel.org/networking/tuntap.html) |
| The `ifr_name` buffer is **overwritten** with the real device name by `TUNSETIFF`. | [kernel: tuntap](https://docs.kernel.org/networking/tuntap.html) |
| Multiqueue since Linux **3.8**: repeat `TUNSETIFF` with `IFF_MULTI_QUEUE`, one fd per queue; `TUNSETQUEUE` attaches/detaches a queue. | [kernel: tuntap](https://docs.kernel.org/networking/tuntap.html) |
| `IFF_BACKPRESSURE` (newer kernels) stops the queue instead of dropping so a qdisc can apply AQM/shaping; requires an attached qdisc and a single‑queue device to toggle. | [kernel: tuntap](https://docs.kernel.org/networking/tuntap.html) |
| Device node: `mknod /dev/net/tun c 10 200` is the traditional recipe; on modern distros `devtmpfs`/`systemd-tmpfiles` already provide it. | [kernel: tuntap](https://docs.kernel.org/networking/tuntap.html) |

**Key architectural consequence — now verified, not assumed.** Xray's native TUN inbound
(`"protocol": "tun"`) *does* create and own the device on Linux:
`tun_linux.go:open()` performs `unix.Open("/dev/net/tun", O_RDWR)` +
`ioctl(TUNSETIFF)` with `IFF_TUN|IFF_NO_PI`, then `netlink.LinkSetMTU`, and in `Start()`
brings the link up and adds addresses/routes. This is documented in detail, with exact
source references and version history, in the sibling report
[`03-xray-tun-inbound.md`](03-xray-tun-inbound.md) — treat that file as the authority on
the Xray config schema and this file as the authority on the kernel-side consequences.

**We should let Xray create the TUN device**, because whoever holds the fd owns the
interface lifetime and Xray is the process that reads and writes it. MyVpn must **not**
create a second TUN device for the same tunnel.

* **Minimum Xray version: `v26.9.9`** (floor `v26.4.15`; `v26.4.13` is broken because
  `mtu` is `repeated`). From [`03-xray-tun-inbound.md`](03-xray-tun-inbound.md), which
  verified each tag against `proxy/tun/config.proto`.
* The interface name is the TUN inbound's **`name`** field. Set it explicitly to
  `"name": "myvpn0"` so it matches the `oifname "myvpn0"` used throughout our firewall
  rules; the default is an auto-generated random `utunN`. **Never rely on the random
  default** — it would silently break every rule in this document.
* The interface **address** comes from the **`gateway`** field (a list of address
  prefixes). There is no `address` and no `autoRoute` key. On an IPv4-only profile,
  simply omit IPv6 prefixes.
* `TUNSETPERSIST` is **not** used by Xray and we should **not** use it for the tunnel:
  a persistent TUN that outlives Xray is a stale device with a route pointing at
  nothing — exactly the crash‑recovery hazard we are trying to avoid. Ephemeral +
  fail‑closed firewall is strictly safer. Because Xray's cleanup removes only the
  addresses/routes it recorded, our own `ExecStopPost=` cleanup (§2.1) is what guarantees
  the rest.
* **Alternative worth prototyping: the `XRAY_TUN_FD` handoff.** If the env var
  `XRAY_TUN_FD` (alias `xray.tun.fd`) is set to an open fd ≥ 3, Xray validates that it is
  an `IFF_TUN` device with `IFF_NO_PI` whose name matches `name`, sets `ownsTun=false`,
  and then **does not set MTU, addresses or routes, does not bring the link up, and does
  not tear it down**. In that mode MyVpn (via the helper) owns all interface
  configuration — a clean way to make the helper, not Xray, authoritative over addresses
  and routes. Trade‑off: we then own MTU/address/route cleanup ourselves, including on
  crash. Recommend keeping Xray‑owned TUN as the default and treating the fd handoff as a
  later optimisation if we need deterministic route ownership.
* **Do not configure `autoSystemRoutingTable` for process‑selected routing.** Xray
  installs those routes into the **main** routing table
  (`netlink.RouteAdd{…, Priority: 1}`, and on Linux a `0.0.0.0/0` entry replaces the
  physical default). Our design deliberately keeps the system default untouched and
  routes only marked traffic via table 100 (§2.6). Use `autoSystemRoutingTable` only for
  explicit, narrow destinations in split‑tunnel mode, never `0.0.0.0/0`, or the two
  routing mechanisms will fight.

### 1.2 nftables `socket cgroupv2` — the critical caveat

This was the highest‑risk unknown and it materially changes the design.

* Syntax (from the installed `nft(8)`, SOCKET EXPRESSION): `socket cgroupv2 level NUM`
  in the synopsis, but the working form is **`socket cgroupv2 level N "path"`** — the
  man page's own example is
  `socket cgroupv2 level 1 "user.slice" counter`. The bare `NUM` synopsis is a
  documentation defect; `level 1` **without** a path is a **syntax error** (verified
  with `nft -c`).
* Semantics, verbatim from `nft(8)`: *"if the socket belongs to cgroupv2 `a/b`,
  ancestor level 1 checks for a matching on cgroup `a` and ancestor level 2 checks for
  a matching on cgroup `b`."* Therefore `level 1 "myvpn.slice"` matches the whole
  `myvpn.slice` subtree, while `level 2 "myvpn.slice"` would match a *child* named
  `myvpn.slice` — my first draft was wrong and the validator caught it.
* **The match resolves a numeric cgroup ID, not a dynamic path.** Per the nftables
  maintainers' own guidance quoted by the `systemd-cgroup-nftables-policy-manager`
  project: rules for a not‑yet‑existing cgroup fail with
  `Error: cgroupv2 path fails: No such file or directory`, and *"if cgroup gets removed
  and re-created, none of the existing rules will apply to it"* because the new cgroup
  gets a new unique ID ([project README](https://github.com/mk-fg/systemd-cgroup-nftables-policy-manager)).
* Version floor: **Linux ≥ 5.13** (verified directly: `net/netfilter/nft_socket.c` at tag
  v5.12 contains no cgroupv2 support; at v5.13 it does —
  [commit e0bb96db96f8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e0bb96db96f8ca94349344a2ea7bebc6f8cefdae))
  and userspace nftables ≥ 0.99
  ([upstream patch](https://patchwork.ozlabs.org/project/netfilter-devel/patch/20210426171056.345271-3-pablo@netfilter.org/)).
  `level > 255` is rejected by the kernel with `-EOPNOTSUPP`. The **exact first userspace
  nftables release is UNVERIFIED** (likely 1.0.0, Aug 2021); we pin a minimum and
  feature‑detect rather than trusting a version string.

### 1.3 nftables atomicity and marks

* `nft -f file` reads the file, builds the new configuration **in memory alongside** the
  live one, then swaps in **one atomic operation** — *"there is no moment when the
  firewall is partially configured."* ([wiki: Atomic rule replacement](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement))
* **A single failing command aborts the entire batch.** This is the property that makes
  fail‑closed replacement safe, and it is confirmed in the kernel source, not just the
  wiki: in `nfnetlink_rcv_batch()` the final decision is
  `if (success && done) ss->commit(skb); else ss->abort(skb);` — a batch with no
  `NFNL_MSG_BATCH_END` or with any error invokes `abort`, applies nothing, and skips
  event notifications. All messages are still parsed so userspace receives every error.
  ([commit 0628b123c96d](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0628b123c96d126e617beb3b4fd63b874d0e4f17))
  **Design consequence:** because the whole `nft -f` load is commit‑or‑abort, an invalid
  replacement ruleset leaves the *previous* (armed, fail‑closed) ruleset in force. There
  is no half‑applied state — so it is safe to attempt a reload at any time.
* Recommended replacement pattern: a `flush table` at the top, or a
  `delete table` + table redefinition, both within the same file/transaction. Without
  a flush/delete you get **duplicate rules** on each reload. ([wiki](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement))
  **Attribution caveat:** the specific "create the new table, delete the old table, in one
  transaction" recipe is a *design inference* from the confirmed commit‑or‑abort
  semantics above — it is **not** an explicitly documented upstream recommendation.
  (The wiki page named `Ruleset_replace` **does not exist**; it returns HTTP 404.) The
  "flush at top of file" form *is* explicitly documented and is what this design uses.
* **Table flags `owner` and `persist`** are a cleaner lifecycle primitive than a
  `delete`+redefine for some cases: `owner` excludes other processes from manipulating
  the table and removes it when the creating process exits, while `persist` keeps it
  alive past process exit and lets a restarting daemon re‑adopt it. Relevant to the
  crash‑cleanup design in §2.1, though we deliberately do **not** use `persist` for the
  kill switch (a surviving drop policy after a reboot would strand the host offline).
  (`nft(8)`)
* Chain types: `route` is valid **only on the `output` hook** and *"if a packet has
  traversed a chain of this type and is about to be accepted, a new route lookup is
  performed if relevant parts of the IP header have changed"* — this is precisely what
  makes mark‑based policy routing work from nftables. ([wiki: Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains), `nft(8)`)
* An `accept` verdict is **not final** if a later base chain on the same hook exists; a
  `drop` **is** final. Consequence: a third‑party `table inet filter` chain with a drop
  policy at a *later* priority can still drop our traffic. Our namespaced tables cannot
  guarantee the last word — see Risk R‑2. ([wiki](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains))
* `iifname`/`oifname` match by name and are the correct choice for **dynamically created
  interfaces such as TUN**, unlike `iif`/`oif` which match a (possibly reused) ifindex.
  Wildcard suffix `*` is supported. (`nft(8)`)
* Table flags exist: `owner` (exclusive to creating process, auto‑removed on exit) and
  `persist`. Relevant to ownership/cleanup. (`nft(8)`)

### 1.4 cgroup v2

* **One single hierarchy**; mount with `mount -t cgroup2 none $MOUNTPOINT`. ([kernel: cgroup-v2](https://docs.kernel.org/admin-guide/cgroup-v2.html))
* **No Internal Process Constraint:** only domain cgroups containing **no processes**
  may enable domain controllers in their `cgroup.subtree_control`. ([kernel: cgroup-v2](https://docs.kernel.org/admin-guide/cgroup-v2.html))
* **Delegation**, verbatim: *"A cgroup can be delegated in two ways. First, to a less
  privileged user by granting write access of the directory and its `cgroup.procs`,
  `cgroup.threads` and `cgroup.subtree_control` files to the user. Second, if the
  `nsdelegate` mount option is set, automatically to a cgroup namespace on namespace
  creation."* ([kernel: cgroup-v2](https://docs.kernel.org/admin-guide/cgroup-v2.html))
* `/sys/fs/cgroup/cgroup.controllers` existing ⇒ cgroup v2 is in use.
* **cgroup v2 is the default on:** Fedora (since 31), Arch Linux (since April 2021),
  openSUSE Tumbleweed (since c. 2021), Debian (since 11), Ubuntu (since 21.10), RHEL
  and RHEL‑likes (since 9). Elsewhere, add `systemd.unified_cgroup_hierarchy=1`.
  ([runc docs](https://raw.githubusercontent.com/opencontainers/runc/main/docs/cgroup-v2.md))
* **Only `memory` and `pids` are typically delegated to non‑root users by default**
  (`/sys/fs/cgroup/user.slice/user-$UID.slice/user@$UID.service/cgroup.controllers` →
  `memory pids`). More requires a drop‑in setting `Delegate=` on `user@.service`.
  ([runc docs](https://raw.githubusercontent.com/opencontainers/runc/main/docs/cgroup-v2.md))

**Consequence for MyVpn:** we do **not** need any delegated *controller* — we need to
create a cgroup *directory* and move processes into it, which is far weaker than
controller delegation, but it still requires write access to a delegated directory. An
unprivileged client process cannot create `/sys/fs/cgroup/myvpn.slice` at the root. This
is the decisive argument for the privileged helper (§2.5).

### 1.5 DNS

* Four `/etc/resolv.conf` modes are supported by `systemd-resolved`: (a) symlink to
  `/run/systemd/resolve/stub-resolv.conf` — lists `127.0.0.53` plus live search
  domains, **"This mode of operation is recommended."**; (b) symlink to the static
  `/usr/lib/systemd/resolv.conf` (no search domains); (c) symlink to
  `/run/systemd/resolve/resolv.conf` — all known upstream servers, *"clients that
  bypass any local DNS API will also bypass systemd-resolved and will talk directly to
  the known DNS servers"*; (d) a foreign/other-package file, in which case
  `systemd-resolved` becomes a *consumer*. The mode is auto‑detected.
  ([systemd-resolved.service](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html))
* `systemd-resolved` reads `/etc/resolv.conf` for upstream discovery **only if it is not
  a symlink to one of the three managed files** — so a "foreign" `resolv.conf` is both
  an input and a bypass. ([systemd-resolved.service](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html))
* Routing domains / split DNS: `~.` is the catch‑all routing domain (all names not
  matched by a more specific domain). `resolvectl`'s `-i`/exclusive switch *"is mapped to
  an additional configured search domain of `~.` — i.e. ensures that DNS traffic is
  preferably routed to the DNS servers on this interface, unless there are other, more
  specific domains configured on other interfaces."* (`resolvectl(1)`, installed)
* Per‑link DNS is a property of the *link*, configured via `resolvectl dns <link> …` /
  `resolvectl domain <link> …` or the D‑Bus API — not by editing `resolv.conf`.

### 1.6 polkit / privileged helper

* `pkexec` runs a program as another user, default root, under authorization
  `org.freedesktop.policykit.exec` unless an action file maps the program path.
  ([pkexec(1)](https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html))
* `pkexec` sanitises the environment to *"a minimal known and safe environment"*,
  sets `PKEXEC_UID`, and **strips `$DISPLAY`/`$XAUTHORITY`** (so no X11/GUI children)
  unless the discouraged `org.freedesktop.policykit.exec.allow_gui` annotation is set.
  Exit codes: **127** = not authorized / auth error, **126** = user dismissed the dialog.
  ([pkexec(1)](https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html))
* Action definitions are XML dropped into **`/usr/share/polkit-1/actions`**, with
  `<defaults>` of `allow_any` / `allow_inactive` / `allow_active` (e.g.
  `auth_self_keep`), and an optional
  `<annotate key="org.freedesktop.policykit.exec.path">` to bind an action to a specific
  binary path. ([pkexec(1)](https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html))
* **`pkexec` is a one‑shot privilege launcher, not a service model.** It execs a program
  and waits for it to exit; the privileged program's lifetime is not supervised, it has
  no restart policy, and the GUI cannot re‑connect to it. This alone disqualifies
  `pkexec` as the *primary* mechanism for a long‑lived tunnel + firewall owner.
  **This is an inference from the one‑shot `exec` model, not a documented upstream
  claim.** The claim that `pkexec` is "unsuitable for long-running tasks" and the claim
  that its process is killed or must re-authenticate when the controlling terminal or
  agent goes away are **NOT present in `pkexec(1)`** — an independent verification pass
  against three copies of the man page (freedesktop current, upstream `docs/man/pkexec.xml`,
  Arch `polkit 127-3`) found no such language. Do not cite `pkexec(1)` for those claims.
  Two documented facts *do* support the decision: `pkexec` resets the environment to a
  minimal safe set (defeating `LD_LIBRARY_PATH`-style injection but also discarding
  anything the GUI needs), and it **"does no validation of the ARGUMENTS passed to
  PROGRAM"**, which the man page itself flags as a potential security hole when an
  authorization is retained. That argument-validation gap is the stronger technical
  argument against a `pkexec`-per-operation design.
* **CVE-2021-4034 ("PwnKit")** — the `setuid`-root nature of `pkexec` made it a
  high-impact LPE (`pkexec` is *"a SUID-root program that is installed by default on
  every major Linux distribution"*). Fixed in policykit-1 `0.105-31.1`; see
  [Qualys advisory](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) and the
  [Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2021-4034).
  This reinforces keeping the privileged surface inside a sandboxed systemd **service**
  rather than a setuid binary.
* Hardening directives available: `NoNewPrivileges=`, `ProtectSystem=`, `ProtectHome=`,
  `PrivateTmp=`, `CapabilityBoundingSet=`, `AmbientCapabilities=`,
  `RestrictAddressFamilies=`, `RestrictNamespaces=`, `SystemCallFilter=`,
  `DynamicUser=`, `RuntimeDirectory=`. Note `DynamicUser=` *implies*
  `NoNewPrivileges=`, `RestrictSUIDSGID=`, `ProtectSystem=strict`,
  `ProtectHome=read-only`, i.e. it cannot write arbitrary paths without
  `ReadWritePaths=`. ([systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html))

### 1.7 Packaging / FHS

* FHS 3.0 places architecture‑independent data in `/usr/share`, architecture‑dependent
  object code and internal binaries in `/usr/lib`, host‑specific configuration in
  `/etc`, runtime variable data in `/run`, and variable state in `/var/lib`.
  ([FHS 3.0](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html))
* AppImage payload is mounted from a **read‑only** squashfs image at a fresh mountpoint
  each run; `$APPDIR` (mountpoint), `$APPIMAGE` (the file), `$OWD` (original working dir)
  are exported. Nothing inside `$APPDIR` is writable, and the path changes between runs.
  ([AppImage docs](https://docs.appimage.org/))
  → A root helper and polkit action file **cannot** be installed from an AppImage at
  runtime; they must come from a system package.
* Consequence: a helper that a package installs at a stable absolute path **cannot be
  shipped inside an AppImage**. AppImage builds must therefore either (a) require a
  separately installed system package for privileged mode, or (b) fall back to
  `pkexec`‑on‑demand in "degraded" mode with no kill‑switch guarantee across restarts.

---

## 2. Architecture proposal

### 2.0 Component overview

```
┌──────────────────────────┐        D-Bus (system bus)         ┌────────────────────────────┐
│  MyVpn.Client (.NET 8)   │  org.mylvpn.Helper1  (polkit)     │  myvpn-helper  (root)      │
│  unprivileged GUI/tray   │ ────────────────────────────────► │  systemd system service    │
│                          │ ◄──── signals: StateChanged ───── │  owns: nft, ip, resolve,   │
│  IKillSwitch             │                                   │        TUN lifecycle       │
│  IRouteManager           │                                   │  spawns: xray (myvpn-xray) │
│  IDnsConfigurator        │                                   │  CAP_NET_ADMIN only        │
│  IProcessRouter          │                                   └────────────┬───────────────┘
└──────────────────────────┘                                                │
                            myvpn.slice  ◄── selected apps moved into cgroup│
                                          ┌─────────────────────────────────┘
                                          ▼
                              Xray-core creates "myvpn0" (TUN inbound)
```

Design rule: **the privileged helper is the only component that mutates kernel state.**
The client never calls `nft`, `ip`, `resolvectl`, or `/dev/net/tun` directly. This gives a
single auditable privilege boundary, and makes cleanup deterministic (one service =
one `ExecStopPost=`).

### 2.1 TUN lifecycle and crash cleanup

**Decision: Xray‑core creates and owns `myvpn0`. MyVpn never opens `/dev/net/tun`.**

Rationale: the interface lives exactly as long as the fd (§1.1). Letting the process
that pumps packets own the device removes all cleanup work — when Xray dies, the kernel
deletes the interface *and its routes*. We then only have to clean the firewall, DNS and
routing state, which the helper can do deterministically.

Ordered sequence performed by the helper (`CAP_NET_ADMIN` required for every step
touching the kernel):

1. **Resolve the VPN endpoint hostname first**, while the network is still unfiltered.
   Cache the resulting A/AAAA addresses. This is essential: if the endpoint were
   resolved *after* the kill switch was armed, and the kill switch blocked DNS, we could
   never reach the server. (See Risk R‑4.)
2. Create/refresh the `myvpn.slice` cgroup and move the target applications into it.
3. **Arm the kill switch in one transaction**, with the resolved endpoint IPs already in
   the `vpn_endpoint4`/`vpn_endpoint6` sets. `delete table` + redefinition is atomic, so
   there is **no leak window** and no fail‑open moment (§1.3).
4. Start Xray. It creates `myvpn0`, sets the address, and adds the tunnel route.
5. Install the process‑routing marks and `ip rule`s referencing `myvpn0`.
6. Apply DNS configuration to the `myvpn0` link only.
7. Publish `Connected` on D‑Bus.

Crash/recovery, guaranteed by `systemd` (`Restart=on-failure`) plus
`ExecStopPost=`:

* `ExecStopPost=` deletes `table inet myvpn_ks`, `table inet myvpn_route`,
  `table inet myvpn_dns`, removes the `ip rule`s, and reverts DNS — each in one
  transaction/operation, all idempotent (existence-check then `delete`; see §2.2 — do
  **not** rely on `destroy`, which nftables 1.0.2 rejects).
* Because the kill‑switch table is **fail‑closed by design**, a helper crash leaves the
  machine **without internet**, not leaking. That is the correct failure direction. The
  `ExecStopPost=` handler is what restores connectivity.
* **SIGKILL/`kill -9` of the helper** cannot run `ExecStopPost=`. Mitigation: a
  `myvpn-killswitch.service` oneshot whose `ExecStop=` clears the tables, ordered
  `PartOf=myvpn-helper.service`, so systemd tears both down. Additionally the client
  performs a "panic‑clear" on next launch if it finds a stale `inet myvpn_ks` table with
  our name and no live `myvpn0`.
* **Power loss / reboot:** nftables state is not persistent unless explicitly saved into
  `/etc/nftables.conf`. We must **never** write our kill switch into the system
  `nftables.conf`, because a boot with no VPN would then have no internet. Verified by
  design: our tables exist only in the live kernel ruleset.

### 2.2 Kill switch — nftables ruleset

**Why nftables over iptables.** (a) `iptables` on every target distro is already the
nf_tables shim (`iptables v1.8.7 (nf_tables)` on the research host) — writing iptables
rules just produces nftables underneath, while losing the nftables feature set.
(b) Atomic whole‑ruleset replacement via `nft -f` is impossible to do correctly with a
sequence of `iptables` invocations. (c) One `inet` table covers IPv4 **and** IPv6, versus
maintaining parallel `iptables` + `ip6tables` rules with the inevitable drift and leaks.
(d) `socket cgroupv2` matching is available. iptables' equivalent is
`-m cgroup --path …`, which has the same cgroup‑ID staleness problem but no atomic
replacement.

The complete, validated ruleset is shipped at
[`assets/10-myvpn-killswitch.nft`](assets/10-myvpn-killswitch.nft) and reproduced here:

```nftables
#!/usr/sbin/nft -f
# MyVpn kill switch — fail-closed, dual-stack, single atomic transaction.
define VPN_IF   = "myvpn0"
define VPN_PORT = 443

table inet myvpn_ks
delete table inet myvpn_ks

table inet myvpn_ks {
	set vpn_endpoint4 { type ipv4_addr; flags interval; }
	set vpn_endpoint6 { type ipv6_addr; flags interval; }

	chain out {
		type filter hook output priority filter; policy drop;
		oifname "lo" accept comment "loopback"
		oifname $VPN_IF accept comment "the tunnel itself"
		ip  daddr @vpn_endpoint4 accept
		ip6 daddr @vpn_endpoint6 accept
		ip  daddr @vpn_endpoint4 udp dport $VPN_PORT accept
		ip  daddr @vpn_endpoint4 tcp dport $VPN_PORT accept
		ip6 daddr @vpn_endpoint6 udp dport $VPN_PORT accept
		ip6 daddr @vpn_endpoint6 tcp dport $VPN_PORT accept
		udp sport 68 udp dport 67 accept
		udp sport 67 udp dport 68 accept
		meta l4proto { icmp, ipv6-icmp } accept
		ct state established,related accept
		counter drop comment "myvpn_ks: egress denied"
	}

	chain in {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname $VPN_IF accept
		ct state established,related accept
		udp sport 67 udp dport 68 accept
		meta l4proto { icmp, ipv6-icmp } accept
		counter drop comment "myvpn_ks: ingress denied"
	}

	chain forward_chain {
		type filter hook forward priority filter; policy drop;
	}
}
```

Design notes, each load‑bearing:

* **`inet` family, not `ip` + `ip6`.** One table, one transaction, and
  `meta l4proto { icmp, ipv6-icmp }` plus the `ip`/`ip6` qualified matches cover both
  stacks. This is the dual‑stack answer.
* **IPv6 leak prevention.** With an IPv4‑only tunnel, the `ip6 daddr @vpn_endpoint6`
  rule matches nothing, so **all** IPv6 egress is dropped by the policy other than
  link‑local/ICMPv6/loopback — IPv6 cannot silently escape. If the tunnel is dual‑stack,
  the helper simply populates `vpn_endpoint6` and the tunnel interface carries IPv6.
  A belt‑and‑braces variant is to add an explicit
  `meta nfproto ipv6 counter drop` — validated syntax.
* **DHCP.** `udp sport 68 udp dport 67` permits lease renewal on the physical uplink in
  the clear; the reverse pair permits the server's reply. Without this, a laptop
  cannot renew its lease while connected.
* **Kept out of the chain:** an unconditional `udp dport 53 accept`. Allowing plaintext
  :53 in the *kill switch* would create a DNS leak by construction. DNS is handled
  separately by the DNS guard (§2.4), which forces it through the tunnel.
* **`ct state established,related accept`** must sit **after** the explicit blocks for
  the tunnel/endpoint, and is what makes bidirectional UDP‑based VPN transport work.
* **`flags interval`** on the sets lets the helper insert ranges/CIDR blocks, not just
  single hosts — necessary because VPN endpoints commonly resolve to several IPs and
  providers rotate them.
* **Endpoint accepts are protocol/port‑independent on purpose.** The `ip daddr
  @vpn_endpoint4 accept` rule precedes the port‑specific rules. This is not sloppiness:
  when the helper atomically replaces the endpoint set, a *live* tunnel session to an
  address present in both the old and the new set must not be interrupted. Matching on
  the address alone keeps the session alive across a reload, while the
  `ct state established,related` rule is not sufficient on its own because a reload
  briefly re‑evaluates the flow. The narrower port rules are kept immediately after as
  executable documentation of the intended transport, and the helper must additionally
  re‑add existing endpoint addresses before removing stale ones so the intersection is
  never empty.
* `oifname` (name) rather than `oif` (ifindex) because the TUN device is created
  dynamically and ifindexes are recycled (`nft(8)`, §1.3).

**Why the chain is named `forward_chain`, not `fwd`:** `fwd` is a **reserved nftables
keyword** (the FWD statement). `nft -c` rejects `chain fwd {`. Likewise `drop`,
`accept`, and `mark` are not usable as chain names. Verified by direct test; this is a
real trap that the validator caught.

**Updating endpoints without ever failing open.** When the endpoint set changes, the
helper rewrites only the set atomically:

```bash
# Root, atomic set replacement — does NOT tear down the drop policy.
# `flush set` + `add element` in ONE transaction: the set is never observed empty
# by a concurrently-evaluated packet, and the default-drop policy stays installed.
nft -f - <<'EOF'
flush set inet myvpn_ks vpn_endpoint4
add element inet myvpn_ks vpn_endpoint4 { 203.0.113.7, 198.51.100.0/24 }
EOF
```

**Do not use `destroy` — it is newer than our minimum nftables.** The `nft(8)` on the
research host documents `destroy table`/`destroy set`, but nftables **v1.0.2** rejects
`destroy table inet myvpn_ks` and `destroy set …` with
`Error: syntax error, unexpected table, expecting string` (verified, both in command mode
and via `-f`). Only `delete` works. `delete` **fails if the object is absent**, so
idempotent cleanup must instead either check for existence first or tolerate the
"no such file or directory" error. The helper's cleanup routine therefore does:

```bash
# Idempotent cleanup that works on old and new nftables alike.
for t in myvpn_ks myvpn_route myvpn_dns; do
    nft list table inet "$t" >/dev/null 2>&1 && nft delete table inet "$t"
done
# `delete table` also deletes the sets and chains it contains, so no separate
# set cleanup is needed. Exit status is deliberately not fatal.
```

This is a concrete example of why the deliverable pins a minimum nftables version and
why every snippet must be validated against that minimum rather than against whatever
happens to be installed.

### 2.3 Process routing — comparison and recommendation

**Recommendation: (a) cgroups v2 + nftables `socket cgroupv2` match to set a packet
mark, combined with (c) `ip rule fwmark` policy routing.** (a) provides the *selection*
mechanism; (c) provides the *routing* mechanism. They are complements, not competitors.
**(b) `SO_MARK` is retained only as the internal loop‑prevention/cleanup device, and
(d) Xray's own process routing is not used.**

| Option | Selection power | Privilege | Failure mode | Verdict |
|---|---|---|---|---|
| **(a) cgroup v2 + `socket cgroupv2`** | Whole process **subtree**, inherited by children automatically, survives forks/exec | Root to create+own the cgroup and load rules | cgroup‑ID staleness (§1.2); rule silently stops matching after cgroup recreation | **Adopt** — best ergonomics for "route these apps" |
| **(b) `SO_MARK` in each app** | Per‑app, must be set by the app before `connect()` | App itself (needs `CAP_NET_RAW`/`CAP_NET_ADMIN`) | Any unmarked socket leaks; third‑party apps cannot be modified | Reject as primary; **use for the tunnel's own sockets** |
| **(c) `ip rule fwmark` + `ip route`** | Acts on marks/cgroups already set | `CAP_NET_ADMIN` | Rules are ordering‑sensitive; stale rules after crash | **Adopt** as the routing half |
| **(d) Xray `routing`/`sockopt mark` + `inboundTag`** | Only traffic that *reaches Xray* (i.e. via a proxy inbound or TUN); cannot intercept arbitrary app sockets | — | Does not solve "route app X's traffic into the tunnel" by itself | **Complement only**: used to choose outbounds *inside* Xray |

**How selected processes are captured.** The helper creates a dedicated slice and moves
the chosen PIDs into it:

```bash
# Root. Create a cgroup the firewall can reference, then put processes in it.
mkdir -p /sys/fs/cgroup/myvpn.slice
# Move an existing process (and, writing the tgid, all its threads) into the slice:
echo "$PID" > /sys/fs/cgroup/myvpn.slice/cgroup.procs
# Or launch it there in the first place, so it can never exist outside:
systemd-run --slice=myvpn.slice --scope --unit=myvpn-app-$$$ /usr/bin/app
```

Using `systemd-run --slice=myvpn.slice --scope` is strongly preferred over moving PIDs:
a process started *inside* the slice never has a single packet outside it, whereas a
process moved after the fact may already have open sockets in the old cgroup. This
matters because the nftables match is evaluated per **socket** against the cgroup the
socket was created in.

**How the tunnel's own traffic is kept out (loop prevention).** Three independent
mechanisms; configure all three, because the failure mode of any one of them is an
infinite routing loop that takes the machine offline:

1. **Xray's official mechanism: `autoOutboundsInterface`.** Xray binds **all** its
   outbound sockets to a nominated physical interface (`SO_BINDTODEVICE` on Linux, which
   requires `CAP_NET_RAW` or root), so Xray's own uplink packets physically cannot
   re-enter the TUN. Set it explicitly to the physical uplink name rather than `"auto"`
   for determinism. This is the mechanism Xray's own README relies on, and it exists
   from `v26.9.8`; below that, do not rely on it.
   ([`03-xray-tun-inbound.md`](03-xray-tun-inbound.md); `proxy/tun/README.md`)
2. **Structural / cgroup:** Xray runs as `myvpn-xray.service`, which is **not** in
   `myvpn.slice` — so `socket cgroupv2 level 1 "myvpn.slice"` never matches Xray's
   upstream sockets. This does not depend on marks or on Xray config.
3. **Mark hygiene in nftables:** `oifname "myvpn0" return` before any `meta mark set`, so
   traffic already on the tunnel is never re‑marked; plus a `postrouting` chain that
   clears the mark before packets hit the wire, so a stale mark can never be seen by the
   peer or cached in a route lookup.

Layer 1 is the primary defence (it is enforced in the kernel per socket); layers 2 and 3
protect the *routing/marking* path that layers 1 does not cover. Note the sibling
report's warning that Xray provides **no** host route or loop detection for the VPN
server itself — that remains our responsibility (§2.6).

The validated ruleset is at
[`assets/20-myvpn-process-route.nft`](assets/20-myvpn-process-route.nft):

```nftables
#!/usr/sbin/nft -f
define VPN_FWMARK = 0xca6c
define VPN_IF     = "myvpn0"
define VPN_CGROUP = "myvpn.slice"

table inet myvpn_route
delete table inet myvpn_route

table inet myvpn_route {
	chain mark_output {
		type route hook output priority mangle; policy accept;
		oifname $VPN_IF return
		socket cgroupv2 level 1 $VPN_CGROUP meta mark set $VPN_FWMARK
	}

	chain mark_prerouting {
		type filter hook prerouting priority mangle; policy accept;
		iifname $VPN_IF return comment "never re-mark tunnel-originated traffic"
		socket cgroupv2 level 1 $VPN_CGROUP meta mark set $VPN_FWMARK
	}

	chain clear_mark {
		type filter hook postrouting priority mangle; policy accept;
		oifname $VPN_IF meta mark set 0
	}
}
```

`type route hook output` (not `filter`) is mandatory here: only a `route` chain triggers
the route re‑lookup after the mark changes (`nft(8)` and
[wiki: Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)).

**The cgroup v2 delegation/permission problem, and why it forces a helper.** The nftables
rule must be loaded by root regardless (it needs `CAP_NET_ADMIN`). Separately, creating
`/sys/fs/cgroup/myvpn.slice` requires write access to the cgroup root, which is
root‑owned (`dr-xr-xr-x root root` on the research host). Delegation *could* in principle
grant a user a subtree — the kernel documents granting write access to the directory and
its `cgroup.procs`/`cgroup.threads`/`cgroup.subtree_control`, and `nsdelegate` can make
cgroup namespaces delegation boundaries (§1.4) — but:

* By default only `memory` and `pids` are delegated to a user's `user@.service`, and
  delegation is configured by an admin drop‑in on `user@.service`, which we cannot
  assume exists. ([runc docs](https://raw.githubusercontent.com/opencontainers/runc/main/docs/cgroup-v2.md))
* The delegated subtree lives at
  `/sys/fs/cgroup/user.slice/user-$UID.slice/user@$UID.service/...`, so our nftables rule
  would have to hard‑code a long, UID‑specific, session‑specific path — brittle across
  logins and multi‑seat setups.
* Even with delegation, the user still cannot load the nftables rule.

So a **root helper** is required for the real feature. The systemd‑native way to give a
service the slice is `Slice=myvpn.slice` in the unit (systemd creates the cgroup) plus
`systemd-run --slice=` for app scopes. For systemd ≥ 255 there is also `NFTSet=` in unit
files, but it is limited to system units and cannot be used from `~/.config/systemd/user`
([project README](https://github.com/mk-fg/systemd-cgroup-nftables-policy-manager)) — so
we load the rules ourselves and do not depend on it.

**Brittleness mitigation (mandatory).** Because the match resolves a cgroup ID, the
helper must re‑apply the routing table **after** the slice is recreated, on every
connect and every app restart. The client should verify that traffic is actually
tunnelled (e.g. read the `counter` on the mark rules, or check `ip rule` presence) and
report a degraded state rather than assume success.

### 2.4 DNS

**Goal:** no query may reach a resolver outside the tunnel, and DNS must be restored
even after a crash.

**Primary design — and a critical distro correction.** An earlier draft of this document
assumed `systemd-resolved` is present on all four target distros. **That is wrong**, and
it changes the implementation. Verified per distro:

| Distro | `systemd-resolved` state | `/etc/resolv.conf` default | `nsswitch.conf` `hosts:` |
|---|---|---|---|
| **Ubuntu 21.10+/22.04/24.04** | **enabled by default** | symlink → `/run/systemd/resolve/stub-resolv.conf` (stub mode) | `files dns` (Ubuntu does **not** use nss-resolve) |
| **Debian 11/12** | **NOT installed, NOT the default resolver** — split into a separate `systemd-resolved` package that *"will not be installed automatically"*; *"systemd-resolved was not, and still is not, the default DNS resolver in Debian"* | managed by `resolvconf` (symlink → `/etc/resolvconf/run/resolv.conf`) or NetworkManager | `files dns` |
| **Fedora 33+** | **default**; `nss-resolve` used instead of `nss-dns` | symlink → `/run/systemd/resolve/stub-resolv.conf` | includes `resolve [!UNAVAIL=return]` |
| **Arch** | package installed by default but **service not enabled by default** | static regular file from the `filesystem` package | `mymachines resolve [!UNAVAIL=return] files myhostname dns` |

Sources: [Debian 12 release notes §5.2.3](https://www.debian.org/releases/bookworm/amd64/release-notes/ch-information.en.html#systemd-resolved);
[Fedora 33 networking release notes](https://docs.fedoraproject.org/en-US/fedora/f33/release-notes/sysadmin/Networking/);
[Fedora Change: systemd-resolved](https://fedoraproject.org/wiki/Changes/systemd-resolved);
[ArchWiki systemd-resolved](https://wiki.archlinux.org/title/Systemd-resolved);
[Arch `filesystem` nsswitch.conf](https://gitlab.archlinux.org/archlinux/packaging/packages/filesystem/-/raw/main/nsswitch.conf).

**Consequence:** DNS handling must be a *runtime-detected strategy*, not a
`systemd-resolved`-only code path. On Debian and on Arch-with-resolved-disabled,
`resolvectl` will not exist or will not be the effective resolver, and the helper must
fall back to the `resolvconf`/NetworkManager path. Do not assume; detect.

When `systemd-resolved` **is** the active manager (Ubuntu, Fedora, opted-in Debian/Arch):

1. Use the **tunnel link only**. Do not overwrite `/etc/resolv.conf`.
   `systemd-resolved` is configured per link:

   ```bash
   # Root or polkit-authorized. Per-link DNS on the tunnel interface only.
   resolvectl dns myvpn0 10.8.0.1
   resolvectl domain myvpn0 '~.'          # catch-all routing domain: everything
   resolvectl default-route myvpn0 yes
   ```

   `~.` as the routing domain means *"prefer the DNS servers on this interface for all
   names"* unless a more specific domain is configured elsewhere (`resolvectl(1)`).
   This is split‑DNS with the tunnel as the default — the correct behaviour for a
   full‑tunnel VPN.
2. **Restore** is a per‑link operation and therefore trivially safe:
   `resolvectl revert myvpn0` on teardown. Nothing global was mutated, so there is
   nothing global to corrupt. The link disappears with the TUN device anyway, taking its
   DNS config with it — this is why per‑link DNS is drastically safer than editing
   `/etc/resolv.conf`.
3. For **split DNS** (only some domains via the tunnel), replace the catch‑all with
   specific domains: `resolvectl domain myvpn0 '~corp.example.com' '~internal.test'`
   and leave the physical link as the default route for everything else.
   Note the documented best‑match rule: the routing domain with the **most labels** wins,
   and `default-route` defaults to true unless a route‑only domain other than `~.` is
   configured — so a split‑DNS profile must set it explicitly rather than rely on the
   default.

**When `systemd-resolved` is NOT the active manager (Debian default, Arch unconfigured).**
`resolvectl` will be absent or ineffective, and `resolv.conf` is managed by `resolvconf`
(a symlink to `/etc/resolvconf/run/resolv.conf`) or by NetworkManager. In that case:

* Detect first (see the detection snippet below), and **do not** run `resolvectl` blind —
  it can appear to succeed while changing nothing, which is the dangerous failure mode.
* Use the `resolvconf` path: provide a hook under `/etc/resolvconf/update.d/` (installed
  by the package) that injects the tunnel resolver while MyVpn is up and removes it on
  teardown, invoked by the helper via `resolvconf -a <iface>.myvpn -m 0 -x` /
  `resolvconf -d <iface>.myvpn`. The interface‑scoped entry name means NetworkManager and
  `dhclient` cannot clobber it, and `-d` removes exactly our record.
* Where NetworkManager owns DNS, prefer a `nmcli`/D‑Bus split‑DNS configuration over
  file edits.
* **Always verify observable resolution after applying** (query a name and confirm the
  answer came from the expected server) instead of trusting the configuration call's
  exit status. This is what turns R‑7 from a silent leak into a caught error.

Detection, run before choosing a strategy:

```bash
systemctl is-active --quiet systemd-resolved && systemctl is-enabled --quiet systemd-resolved && echo resolved
command -v resolvconf >/dev/null 2>&1 && echo resolvconf
command -v nmcli >/dev/null 2>&1 && nmcli -t -f RUNNING general status 2>/dev/null | grep -q running && echo networkmanager
readlink -f /etc/resolv.conf   # stub-resolv.conf|resolv.conf => a resolved-managed mode
```

**Why editing `/etc/resolv.conf` is fragile — do not do it.** On the research host,
`/etc/resolv.conf` is a **symlink** to `../run/systemd/resolve/stub-resolv.conf`.
The resolved docs describe four possible modes, auto‑detected by whether the file is a
symlink to one of the managed files or merely contains `127.0.0.53` (§1.5). If MyVpn
replaces `/etc/resolv.conf` with a regular file:

* `systemd-resolved` flips into "consumer" mode and starts treating our file as its
  *upstream* configuration — a feedback path with surprising results.
* NetworkManager, `resolvconf`, and `dhclient` all consider `/etc/resolv.conf` theirs and
  will overwrite it at the next lease renewal or link event, silently reverting our
  setting mid‑session.
* Restoring the *exact* prior state (which symlink target — `stub-resolv.conf`,
  `resolv.conf`, or the static `/usr/lib/systemd/resolv.conf`) is guesswork after a
  crash. Getting it wrong can break DNS system‑wide even after the VPN is gone.

Per‑link DNS via D‑Bus/`resolvectl` avoids all four problems.

**DoH/DoT options.** Three layers, in increasing order of robustness:

* *In‑tunnel plaintext DNS* (above) — encrypted only insofar as the tunnel is. Adequate
  when the tunnel is trusted and is the default.
* *Xray‑internal DoH/DoT*: point the tunnel link's resolver at the VPN's pushed resolver
  and let Xray's own DNS outbound (`dns` + `doh`/`tls` server config) do the encrypted
  hop. Keeps `systemd-resolved` unaware of DoH, which is simpler.
* *System‑wide DoH/DoT*: `systemd-resolved` supports `DNSOverTLS=yes` and
  `DOH=` per‑link / globally (`resolved.conf(5)`). Setting this on `myvpn0` gives
  encrypted DNS independently of the tunnel, but it must be reverted on teardown, and it
  will bypass the VPN's DNS‑based policy. **UNVERIFIED:** exact per‑link DoH syntax on
  the oldest supported systemd versions must be checked against
  `resolved.conf(5)` on the target release; the option set grew over time.

**DNS leak prevention, defence in depth.**

1. Per‑link `~.` routing domain → queries go to the tunnel resolver.
2. The kill switch permits **no** plaintext :53 (only DHCP and the endpoint are exempt),
   so even a resolver bypass cannot escape.
3. The DNS guard table *forces* :53 from selected processes to the tunnel resolver and
   **drops** IPv6 DNS rather than letting it leak
   ([`assets/30-myvpn-dns-guard.nft`](assets/30-myvpn-dns-guard.nft)):

```nftables
define VPN_DNS4   = 10.8.0.1
define VPN_IF     = "myvpn0"
define VPN_CGROUP = "myvpn.slice"

table inet myvpn_dns
delete table inet myvpn_dns

table inet myvpn_dns {
	chain dns_hijack {
		type nat hook output priority dstnat; policy accept;
		oifname $VPN_IF return comment "DNS already inside the tunnel"
		oifname "lo" return
		socket cgroupv2 level 1 $VPN_CGROUP ip  daddr != 127.0.0.0/8 udp dport 53 dnat to $VPN_DNS4
		socket cgroupv2 level 1 $VPN_CGROUP ip  daddr != 127.0.0.0/8 tcp dport 53 dnat to $VPN_DNS4
		socket cgroupv2 level 1 $VPN_CGROUP ip6 daddr != ::1         udp dport 53 drop
		socket cgroupv2 level 1 $VPN_CGROUP ip6 daddr != ::1         tcp dport 53 drop
	}
}
```

Note the `nat` chain only sees the first packet of a flow, which is the desired
performance characteristic, and that `dnat to` requires the target to be reachable over
the tunnel — the helper must therefore install this **after** `myvpn0` is up.

**`nsswitch.conf` / `resolvconf` variants across distros.**

* `hosts:` line: Debian/Ubuntu and Fedora and Arch all ship a `files`‑first line; Arch
  and Fedora commonly include `myhostname` (e.g. `hosts: mymachines resolve [!UNAVAIL=return]
  files myhostname dns`) when `nss-resolve` is installed, Ubuntu/Debian typically
  `hosts: files mdns4_minimal [NOTFOUND=return] dns` (the research host: `files dns`).
  We must **not** rewrite `nsswitch.conf`; doing so risks breaking hostname resolution
  and is unnecessary because per‑link DNS is transparent to NSS.
* `resolvconf` variants: Debian historically uses the `resolvconf` package (or
  `openresolv`), Fedora uses NetworkManager + `systemd-resolved`, Arch offers
  `openresolv` or `systemd-resolved`. Where `resolvconf` is the active manager and
  `systemd-resolved` is **not** running, the correct integration is a resolvconf hook
  (`/etc/resolvconf/update.d/`) that injects and later removes our resolver, invoked by
  the helper. The client must detect which manager owns DNS before acting:

  ```bash
  # Detection order (read-only, no privileges needed)
  systemctl is-active systemd-resolved 2>/dev/null && echo resolved
  command -v resolvconf >/dev/null && echo resolvconf
  command -v netconfig >/dev/null && echo netconfig   # openSUSE/Linux
  readlink -f /etc/resolv.conf                        # symlink target tells the mode
  ```

  **UNVERIFIED:** whether `resolvconf` is installed by default on current Debian/Fedora
  minimal images varies by release and install profile; detection must be runtime, not
  assumed.

### 2.5 Privileged helper and privilege model

**Decision: a `systemd` **system** service running as root with a minimal capability set,
exposing a D‑Bus interface on the **system** bus, with **polkit** authorization for each
mutating method. `pkexec` is used only as an optional bootstrap to *install/enable*
that service, never as the runtime mechanism.**

**Why not `pkexec` for the runtime job.** `pkexec` is a one‑shot `exec` of a program as
root and it waits for that program to exit (§1.6). A tunnel owner must live across
connect/disconnect/reconnect cycles, be restartable, own cleanup on failure, and stream
state back to the GUI. `pkexec` gives none of that: no supervision, no restart, no shared
state, a new authorization prompt per invocation, and it deliberately strips the GUI
environment so it cannot talk to the user's session bus. Using `pkexec` per operation
would also mean a root process per operation with no ability to hold the `myvpn0`
lifecycle consistently. Finally, `pkexec(1)` states that it **"does no validation of the
ARGUMENTS passed to PROGRAM"** and warns this is a security hole when an authorization is
retained — so a `pkexec`-per-operation design would require us to re-implement argument
validation in every privileged entry point. A long‑lived D‑Bus service validates once, in
a typed interface. (See §1.6 for the claim we explicitly do **not** attribute to
`pkexec(1)`.)

**Why a policy‑checked helper binary alone is insufficient.** A setuid root helper is a
far larger attack surface than a D‑Bus service: it must defend itself against a hostile
environment (`LD_PRELOAD`, `PATH`, inherited fds, argv), and any memory‑safety bug is
directly root. Polkit‑authorized D‑Bus methods let the *daemon* validate every request
against a typed interface and reject malformed input before touching the kernel, and let
systemd sandbox the daemon declaratively.

**Authorization flow.**

1. The client opens the system bus and calls a method, e.g.
   `org.mylvpn.Helper1.Connect(a{sv} profile)`.
2. The system bus daemon has already applied its policy in
   `/etc/dbus-1/system.d/org.mylvpn.Helper1.conf`, which must grant `send_destination`
   for `org.mylvpn.Helper1` to the relevant user/group while denying others. This is the
   coarse gate: **without a matching bus policy, the call never reaches the helper.**
3. The helper is a `polkit` authority client. Before mutating, it checks the caller with
   `polkit_authority_check_authorization()` for action
   `org.mylvpn.helper.manage`, using the caller's **unique bus name** as the subject so
   the UID is taken from the bus daemon, not from anything the client supplied.
4. The action is declared in `/usr/share/polkit-1/actions/org.mylvpn.policy`, e.g.:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE policyconfig PUBLIC
    "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
    "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
   <policyconfig>
     <vendor>MyVpn</vendor>
     <action id="org.mylvpn.helper.manage">
       <description>Configure the MyVpn tunnel</description>
       <message>Authentication is required to change VPN tunnel settings</message>
       <defaults>
         <allow_any>no</allow_any>
         <allow_inactive>no</allow_inactive>
         <allow_active>auth_admin_keep</allow_active>
       </defaults>
     </action>
   </policyconfig>
   ```

   `auth_admin_keep` means "an administrator must authenticate, and the authorization is
   retained for a short time" — appropriate so a user is not re‑prompted on every
   connect/disconnect. `allow_any=no` prevents a non‑admin from ever getting the action.
   (Action file format and `/usr/share/polkit-1/actions` location per `pkexec(1)`.)
   **UNVERIFIED:** whether `auth_admin_keep` is the best default for a desktop VPN versus
   `auth_self_keep` is a policy/product decision; both are valid and the trade‑off
   (admin‑only vs. any active local user) should be confirmed with the product owner.
5. Non‑privileged **read‑only** methods (`Status`, `GetStats`) should be allowed without
   authorization so the tray icon can poll cheaply.

**Authenticating the calling user.** The helper must derive the UID from the D‑Bus
sender's unique name and the bus daemon's credentials — using
`org.freedesktop.DBus.GetConnectionUnixUser` on the *unique* name, or the polkit subject
API — and must not trust any UID passed as a method argument. Any method taking a path,
interface name, DNS server, or command must validate it against a strict allow‑list
before use, because this daemon runs as root.

**D‑Bus policy file** (`/etc/dbus-1/system.d/org.mylvpn.Helper1.conf`, installed by the
package). The shape:

```xml
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.mylvpn.Helper1"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.mylvpn.Helper1"/>
    <allow receive_sender="org.mylvpn.Helper1"/>
  </policy>
  <policy user="someotheruser">
    <deny send_destination="org.mylvpn.Helper1"/>
  </policy>
</busconfig>
```

Allowing `send_destination` broadly is acceptable **only** because every mutating method
is additionally polkit‑gated in the daemon; the bus policy alone is not the security
boundary. **UNVERIFIED:** exact `busconfig` element ordering/semantics should be checked
against the `dbus-daemon(1)` policy documentation for the oldest supported D‑Bus version
before shipping.

**systemd unit + hardening.** This is the concrete unit the package installs:

```ini
# /usr/lib/systemd/system/myvpn-helper.service   (installed by the package, NOT at runtime)
[Unit]
Description=MyVpn privileged network helper
After=network-pre.target systemd-resolved.service
Before=network.target
Wants=systemd-resolved.service
ConditionPathExists=/dev/net/tun

[Service]
Type=dbus
BusName=org.mylvpn.Helper1
ExecStart=/usr/lib/myvpn/myvpn-helper --system-bus
# Deterministic cleanup: always clear firewall + routing + DNS, even on crash.
ExecStopPost=/usr/lib/myvpn/myvpn-helper --cleanup
Restart=on-failure
RestartSec=2s

# ---- hardening ----
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=no
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
RuntimeDirectory=myvpn
RuntimeDirectoryMode=0750
StateDirectory=myvpn
# Only these paths may be written given ProtectSystem=strict:
ReadWritePaths=/run/myvpn /var/lib/myvpn

[Install]
WantedBy=multi-user.target
```

Deliberate choices: `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW` gives exactly the
capabilities needed for nftables, routing, and TUN, and nothing else — **not** full root
(`systemd.exec(5)`, `capabilities(7)`). `ProtectControlGroups=no` is required because we
must create cgroups and move processes into them; this is a real, justified hole in the
sandbox and should be documented as such. `ProtectSystem=strict` + `ReadWritePaths=` keeps
the daemon from writing anywhere but its own runtime/state directories.
`NoNewPrivileges=yes` prevents re‑escalation via setuid or file capabilities
(`systemd.exec(5)`). Note the daemon spawns Xray; if Xray is spawned as a child it
inherits this sandbox, so either relax appropriately for the child or (preferred) run
Xray as its own `myvpn-xray.service` and have the helper only supervise it.

### 2.6 Routing

**Recommendation: drive routing through the kernel netlink API from .NET
(`AF_NETLINK`, `NETLINK_ROUTE`), with `ip` invocation as a documented, tested fallback.**

Comparison:

* **Invoking `ip` as a subprocess** (as root, via the helper) is simple, debuggable, and
  universally available. Downsides: text parsing is brittle across iproute2 versions,
  no transactional grouping (each `ip` call is separate — an interrupted sequence leaves
  half‑applied routing), and it requires `iproute2` to be installed (it is, on all four
  distros, as a dependency of the init system).
* **Netlink from .NET** is atomic per message, returns structured errors (`NLMSG_ERROR`
  with errno), needs no external binary, and lets us batch related changes in one
  `NLM_F_ACK`‑tracked sequence. Downsides: `AF_NETLINK` sockets must be created manually
  (P/Invoke `socket(2)`/`sendmsg(2)` or a managed netlink library), the codec for
  `RTM_NEWROUTE`/`RTM_NEWRULE` is non‑trivial, and struct layout must be
  architecture‑correct for both **x64 and arm64** (alignment differs — this is the main
  correctness risk).

**Decision:** implement netlink as the primary path because routing changes must be
grouped and because parsing `ip` output is a known source of platform bugs; keep the
`ip`‑invocation implementation behind the same `IRouteManager` interface as a fallback
and as the reference implementation used in differential tests.

**What the helper actually installs.** With `VPN_FWMARK = 0xca6c` and table id `100`:

```bash
# Root / CAP_NET_ADMIN.
# 1. The tunnel's own default route, in a dedicated table so we never touch main.
ip route add default dev myvpn0 table 100
# 2. Send only marked traffic to that table. Lower number = higher precedence.
ip rule add fwmark 0xca6c/0xca6c lookup 100 priority 1000
# 3. The tunnel's own upstream packets (to the VPN server) must use the physical
#    uplink, NOT table 100 — otherwise the tunnel would route into itself.
ip rule add to 203.0.113.7 lookup main priority 900
# 4. Fail-closed: if the tunnel is down, marked traffic must DIE, not fall back to
#    the physical uplink. A throw/prohibit rule makes this explicit.
ip rule add fwmark 0xca6c/0xca6c prohibit priority 1100
```

Key points:

* **Interaction with Xray's own routing.** Xray writes its `autoSystemRoutingTable`
  entries into the **main** table, and on Linux a `0.0.0.0/0` entry there **replaces** the
  physical default route ([`03-xray-tun-inbound.md`](03-xray-tun-inbound.md)). Our policy
  routing lives entirely in table 100 and does not depend on the main table's default, so
  the two coexist **provided** we never put `0.0.0.0/0` in `autoSystemRoutingTable` for
  process‑selected mode. In addition Xray provides no host route for the VPN server, so
  rule 3 below is not redundant with anything Xray does.
* **Table id 100 and priorities are MyVpn‑owned constants.** We never mutate `main`,
  so restoring on crash is a matter of deleting our own rules/routes — no need to
  remember what the system's default route was. This is a major robustness win over
  "replace the default route", which requires saving and restoring the previous
  nexthop and is the classic way VPN clients brick networking.
* **Avoiding loops:** rule 3 (endpoint via `main`, higher precedence than the fwmark
  rule) plus the nftables `oifname myvpn0 return` guard plus keeping Xray outside
  `myvpn.slice` gives three independent loop preventions.
* **Source‑based routing** (per‑source‑address policy) is available with
  `ip rule add from <addr> lookup 100`; needed if we ever expose the tunnel to a
  container or secondary address. Prefer the mark approach for process selection and
  reserve `from` for address‑based selection.
* **Interface metrics:** when MyVpn needs the *physical* link to be preferred for the
  endpoint (e.g. to survive a VPN reconnect), set an explicit metric on the tunnel
  route (`ip route add default dev myvpn0 table 100 metric 50`). Metrics only order
  routes within the *same* table, so they do not interfere with our separate table.
* **Clean restore on crash** — all operations are idempotent‑delete:
  `ip rule del fwmark 0xca6c/0xca6c lookup 100` etc., and the route table is dropped
  with `ip route flush table 100`. Because the table is not `main`, a failure to clean
  up leaves at most an unused table, never a broken default route. `ip rule del` on a
  non‑existent rule errors, so the helper must tolerate/ignore that error.

**UNVERIFIED:** the exact `ip rule`/`ip route` syntax above is standard iproute2 but was
not executed (no `CAP_NET_ADMIN`); it must be validated in the privileged VM test tier
(§6). The `prohibit` rule type should be confirmed to behave as fail‑closed in the
target kernel (it should return `EACCES`/`ENETUNREACH` rather than falling through).

### 2.7 System proxy

**Reality check first: setting a system proxy does not intercept most application
traffic, and it is not a security control.** GNOME/KDE settings are honoured by
well‑behaved GTK/Qt apps and by some CLI tools via environment variables; browsers
often have their own independent proxy settings. It must therefore be positioned as a
*convenience* feature, never as leak prevention — the kill switch is the only leak
control. This must be stated plainly in the UI.

Backends:

* **GNOME:** `gsettings`. The schema is `org.gnome.system.proxy` with
  `mode` (`none`|`manual`|`auto`) and child schemas
  `org.gnome.system.proxy.http`/`.https`/`.ftp`/`.socks` each having `host`, `port`,
  plus `org.gnome.system.proxy ignore-hosts`. Set with e.g.
  `gsettings set org.gnome.system.proxy mode 'manual'`.
  **Restore** requires having captured the previous values per key (including the
  `ignore-hosts` array), not just the mode — a partial restore is a common bug.
* **KDE:** `kwriteconfig5` (Plasma 5) or `kwriteconfig6` (Plasma 6) writing
  `kioslaverc` under `~/.config`, then notifying the running session (in Plasma 5 a
  `qdbus` call to the `KIO` module; in Plasma 6 the equivalent `qdbus6`/`dbus-send`).
  The binary name differs by Plasma major version and must be detected at runtime.
* **Environment variables:** `http_proxy`, `https_proxy`, `all_proxy`, `no_proxy`
  (and uppercase variants). These only affect processes that are *launched with them*
  and that choose to honour them — they cannot retroactively affect a running app, and
  they do not affect apps that ignore them. Creating/persisting them for the user's
  future sessions means writing into the session environment
  (`~/.config/environment.d/*.conf` for systemd user sessions), which is a persistent
  change that **must** be removed on disconnect.
* **Per‑app reality:** Java (own `-D` flags), Electron (usually follows env vars),
  Firefox/Chrome (own profile settings, may ignore the system proxy), and
  statically‑configured apps all behave differently. We should not promise blanket
  coverage.

**Set/restore design:** the helper exposes `SetSystemProxy`/`ClearSystemProxy`. Before
setting anything, snapshot the current values into `/run/myvpn/proxy-backup.json`
(atomic write). On clear, restore from the snapshot; if the snapshot is missing or
corrupt after a crash, fall back to a documented safe default (`mode=none`, empty
env file) and log loudly. Because this state lives in `/run`, it is cleared on reboot,
which conveniently means a reboot cannot leave a dangling proxy pointing at a dead
tunnel.

### 2.8 Packaging

**File layout, FHS‑compliant** ([FHS 3.0](https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html)):

| Path | Contents | Rationale |
|---|---|---|
| `/usr/lib/myvpn/myvpn-helper` | privileged helper binary | architecture‑dependent internal binary → `/usr/lib` |
| `/usr/lib/myvpn/xray` | Xray‑core binary | same; arch‑dependent |
| `/usr/lib/myvpn/xray-<arch>` | per‑arch variant if multi‑arch in one package | avoid AppImage confusion |
| `/usr/share/myvpn/geoip.dat`, `geosite.dat` | routing data | architecture‑**independent** data → `/usr/share` |
| `/usr/share/myvpn/*.json` | default templates | config data |
| `/usr/share/polkit-1/actions/org.mylvpn.policy` | polkit action | package‑owned, root‑only writable |
| `/etc/dbus-1/system.d/org.mylvpn.Helper1.conf` | bus policy | package‑owned; treated as config file |
| `/usr/lib/systemd/system/myvpn-helper.service` | helper unit | package‑owned |
| `/etc/myvpn/config.json` | admin/host config | host‑specific config → `/etc` |
| `/var/lib/myvpn/` | subscriptions, caches, logs | variable state → `/var/lib` |
| `/run/myvpn/` | sockets, pid, proxy backup | runtime state → `/run` |
| `/usr/bin/myvpn` (or `.desktop` + tray) | user‑facing client | user command |

**Critical constraint: geoip.dat/geosite.dat and the xray binary must not be resolved
relative to the client executable's directory.** The client must resolve them through a
search path, because the client's own location differs wildly between package,
`dotnet publish`, and AppImage installs:

1. `$MYVPN_DATA_DIR` (explicit override, for tests and AppImage).
2. `/usr/share/myvpn` (package).
3. `$APPDIR/usr/share/myvpn` (AppImage; `$APPDIR` is the read‑only mountpoint).
4. `AppContext.BaseDirectory/data` (portable/dev).

**AppImage implications.** The AppImage payload is mounted from a **read‑only squashfs**
([AppImage docs](https://docs.appimage.org/)). Consequences:

* **A root helper cannot be installed by an AppImage at runtime.** Installing a systemd
  unit, a polkit action, or a setcap/setuid binary requires writing to `/usr/lib`,
  `/usr/share/polkit-1/actions`, and `/usr/lib/systemd/system` — all root‑owned, and
  `$APPDIR` itself is read‑only. Therefore the privileged helper **must** ship in a
  `.deb`/`.rpm` (or an equivalent system package). The AppImage must detect its absence
  and either offer to guide the user to install the package, or run in a clearly‑labelled
  degraded mode.
* **Paths are not stable across runs.** The squashfs mountpoint changes, so nothing may
  persist an absolute path into `$APPDIR` (no desktop files, no unit files referencing
  it, no remembered config paths). Use `$APPDIR` only at runtime.
* **Xray as a helper‑spawned child.** If the helper (a system package) must exec Xray,
  and Xray lives inside the AppImage, the helper would have to exec a path inside a
  read‑only FUSE mount owned by the user — do not do this. Either ship Xray in the
  system package (consistent, recommended) or have the unprivileged client run Xray and
  have the helper only manage kernel state. **The recommended split is: system package
  ships helper + Xray + geo data; the AppImage ships only the GUI client.** This keeps
  the privileged path fully package‑managed and avoids root ever executing code from a
  user‑writable mount, which would be a privilege‑escalation hole.
* **deb/rpm specifics:** `postinst` must `systemctl daemon-reload` and enable
  `myvpn-helper.service` (not start it unconditionally if it needs `/dev/net/tun`; the
  unit's `ConditionPathExists=` handles that). `prerm`/`postrm` must stop and disable the
  service and, on removal, flush any leftover MyVpn nftables tables via
  `myvpn-helper --cleanup` so uninstalling never leaves a host without internet.
  Dependency: `nftables`; `systemd-resolved` where applicable; `dbus`.
* **arm64/x64:** geo data and Xray binary must match the architecture; the data files
  are arch‑independent but Xray is not. Multi‑arch packages must not mix them.

### 2.9 C# interface proposals

All four interfaces are implemented by exactly two implementations: a **D‑Bus proxy
implementation** (calls the helper; used by the GUI) and a **direct implementation**
(calls the kernel; runs inside the helper). This keeps the GUI free of privileges and
makes the privileged code unit‑testable.

```csharp
namespace MyVpn.Platform.Linux;

/// <summary>VPN endpoint resolved BEFORE arming, so fail-closed never locks out the server.</summary>
public sealed record VpnEndpoint(
    IReadOnlyList<IPAddress> Addresses,
    int Port,
    TransportProtocol Protocol);

public sealed record KillSwitchState(
    bool Armed,
    long BlockedPacketCount,   // read from the nft counter: leak/debug telemetry
    IReadOnlyList<IPAddress> AllowedEndpoints);

public interface IKillSwitch
{
    /// <summary>Atomically load the fail-closed inet table. Requires CAP_NET_ADMIN.
    /// Must be called only after <paramref name="endpoint"/> addresses are resolved.</summary>
    Task ArmAsync(VpnEndpoint endpoint, string tunnelInterface, CancellationToken ct);

    /// <summary>Atomically delete the table. Idempotent; safe to call when not armed.</summary>
    Task DisarmAsync(CancellationToken ct);

    Task<KillSwitchState> GetStateAsync(CancellationToken ct);

    /// <summary>Replace only the endpoint sets, never dropping the drop policy.</summary>
    Task UpdateEndpointsAsync(VpnEndpoint endpoint, CancellationToken ct);

    /// <summary>Validate generated ruleset with `nft -c -f` WITHOUT applying it.</summary>
    Task<ValidationResult> ValidateAsync(string rulesetText, CancellationToken ct);
}

public sealed record RouteLease(int TableId, int RulePriority, string Interface);

public interface IRouteManager
{
    /// <summary>Create table 100 + default route + fwmark rule + endpoint-via-main rule
    /// + fail-closed prohibit rule, as one logical operation.</summary>
    Task<RouteLease> InstallAsync(VpnEndpoint endpoint, string tunnelInterface, int fwmark, CancellationToken ct);
    Task RemoveAsync(RouteLease lease, CancellationToken ct);   // idempotent
    Task<RouteLease?> GetActiveLeaseAsync(CancellationToken ct); // for crash recovery
}

public sealed record DnsLease(string Link, string? BackupPath, bool UsedResolved);

public interface IDnsConfigurator
{
    /// <summary>Detect systemd-resolved vs resolvconf vs NetworkManager.</summary>
    Task<DnsBackend> DetectBackendAsync(CancellationToken ct);

    /// <summary>Per-link DNS + routing domain on the tunnel link only.
    /// Never rewrites /etc/resolv.conf.</summary>
    Task<DnsLease> ApplyAsync(string tunnelInterface, IReadOnlyList<IPAddress> servers,
                              IReadOnlyList<string> routingDomains, CancellationToken ct);
    Task RestoreAsync(DnsLease lease, CancellationToken ct);    // idempotent, safe post-crash
}

public sealed record ProcessRouteLease(IReadOnlyList<string> CgroupPaths, int Fwmark);

public interface IProcessRouter
{
    /// <summary>Create/refresh myvpn.slice and re-apply cgroupv2 mark rules.
    /// MUST be re-run whenever the slice is recreated (cgroup-ID staleness).</summary>
    Task<ProcessRouteLease> ApplyAsync(IReadOnlyList<int> pids, string sliceName, int fwmark, CancellationToken ct);
    Task ClearAsync(ProcessRouteLease lease, CancellationToken ct);

    /// <summary>True if the cgroupv2 match is currently effective (probe, not assumption).</summary>
    Task<bool> VerifyEffectiveAsync(CancellationToken ct);
}
```

**Linux implementation strategy per interface.**

* `IKillSwitch`: render the template in §2.2, write to a temp file under `/run/myvpn`,
  run `nft -c -f` first as a pre‑flight (this is exactly the validation the research used
  and it needs no privileges beyond reading), then `nft -f` to commit. Parse `nft -j`
  (JSON) output for counters/state rather than scraping human‑readable tables. All
  operations require `CAP_NET_ADMIN`.
* `IRouteManager`: primary path is a netlink socket (`AF_NETLINK`/`NETLINK_ROUTE`) with
  `RTM_NEWROUTE`/`RTM_NEWRULE`; fallback path shells out to `ip` with `-json` where
  supported. Serialize all mutating operations behind one lock so concurrent
  connect/disconnect cannot interleave rules.
* `IDnsConfigurator`: prefer the D‑Bus API of `systemd-resolved`
  (`org.freedesktop.resolve1` `SetLinkDNS`/`SetLinkDomains`/`SetLinkDefaultRoute`) and
  fall back to `resolvectl`; detect a `resolvconf`‑only host and use a hook there.
  Never write `/etc/resolv.conf`.
* `IProcessRouter`: create the slice directory (or rely on systemd `Slice=`),
  move PIDs / launch via `systemd-run --slice=`, then load the ruleset from §2.3 and
  immediately call `VerifyEffectiveAsync` by comparing the mark‑rule counter before and
  after generating a test connection.

### 2.10 Validation method for this document

Every nftables snippet above was checked with:

```bash
nft -c -f <file>     # -c/--check: "Check commands validity without actually applying the changes."
```

on nftables v1.0.2 without root. Empirically (verified by injecting deliberate errors):
`nft -c` fully parses and semantically evaluates the file — it reports `Error: syntax
error …`, `Error: unknown identifier …`, and reserved‑word misuse — and then fails only
at the commit step with **empty stderr and exit status 1** because it cannot write to the
kernel. Therefore: **non‑empty stderr ⇒ the file is invalid; empty output ⇒ the file is
valid and only the commit needs root.** This distinction was confirmed by corrupting a
file and by referencing an undefined variable, both of which produced precise errors,
proving the parser genuinely evaluates the whole input rather than skipping it.

Files validated this way and shipped alongside this report:

* [`assets/10-myvpn-killswitch.nft`](assets/10-myvpn-killswitch.nft)
* [`assets/20-myvpn-process-route.nft`](assets/20-myvpn-process-route.nft)
* [`assets/30-myvpn-dns-guard.nft`](assets/30-myvpn-dns-guard.nft)

Two real bugs were found and fixed by this method: `counter comment "..." drop` is
invalid (comment must follow the verdict: `counter drop comment "..."`), and `fwd` is a
reserved chain name. Both would have shipped otherwise.

A third, subtler defect was found the same way: **`destroy table`/`destroy set` are
rejected by nftables v1.0.2** even though the `nft(8)` shipped on this host documents
them. The installed man page is newer than the installed binary, so documenting behaviour
from `man` alone is unsafe — every construct was executed through `nft -c` instead. This
is the reason §2.2 now uses `flush set` + `add element` for the atomic set update and an
existence-check + `delete` for cleanup.

**Limits of this validation:** `nft -c` proves *syntax and static semantics only*. It
does not prove that the rules do what we intend at runtime, does not exercise
`CAP_NET_ADMIN` commit paths, and cannot validate the cgroup‑ID resolution behaviour.
Runtime behaviour must be tested on a privileged VM (§6).

---

## 3. Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| **R‑1** | **cgroup‑ID staleness.** `socket cgroupv2` resolves an ID, so rules silently stop matching after the cgroup is recreated; and rules for a not‑yet‑existing cgroup fail to load. | **High** — process routing silently reverts to "everything through the tunnel" or leaks, depending on config | Helper creates/owns `myvpn.slice` and **re‑applies** rules on every connect and app restart; `VerifyEffectiveAsync` probes the counter rather than assuming; prefer launch‑inside‑slice (`systemd-run --slice=`) over post‑hoc PID moves. |
| **R‑2** | **Foreign firewall precedence.** An `accept` is not final if a later base chain on the same hook exists; a distro or third‑party `drop` policy at a later priority can override our accept rules. | Medium | Use a distinctive table name (`inet myvpn_ks`) and verify the loaded ruleset at runtime; document that MyVpn does not own the whole ruleset. Consider a low (early) priority so our accept is seen, and never rely on our policy being last. |
| **R‑3** | **Fail‑closed = no internet when the helper dies badly** (SIGKILL, OOM, power loss while armed). | Medium (availability) | `ExecStopPost=--cleanup`, a `PartOf=` companion oneshot, client‑side stale‑table detection on next launch, and a documented one‑line manual recovery command. Never persist the kill switch into `/etc/nftables.conf`. |
| **R‑4** | **Endpoint DNS lockout.** Arming the kill switch before resolving the server, or the server's IP changing mid‑session, makes the VPN unreachable. | **High** | Resolve endpoints *before* arming; put all resolved A/AAAA into the sets; re‑resolve on reconnect while temporarily permitting the endpoint hostname's resolver; allow the endpoint block in the kill switch to be updated atomically without dropping the policy. |
| **R‑5** | **Kernel/nftables version drift.** `socket cgroupv2` needs Linux ≥ 5.13 and nftables ≥ 0.99; older Debian/Ubuntu LTS kernels or non‑unified cgroup hosts will reject the rule. | Medium | Feature‑detect at startup (`nft -c` a probe ruleset; check `/sys/fs/cgroup/cgroup.controllers`); fall back to `meta skuid`/`meta skgid`‑based marking (validated syntax) as a documented, weaker mode, and disable per‑process routing with a clear message if cgroup v2 is absent. |
| **R‑6** | **Privileged‑helper attack surface.** A root D‑Bus daemon that takes paths/commands from an unprivileged caller is a classic LPE vector. | **High** | Strict D‑Bus + polkit gating, UID taken from the bus credentials only, no free‑form command/path arguments, `CapabilityBoundingSet` limited to `CAP_NET_ADMIN CAP_NET_RAW`, `NoNewPrivileges`, `ProtectSystem=strict`; fuzz the D‑Bus interface; never exec anything from a user‑writable path (rules out executing Xray from `$APPDIR`). |
| **R‑7** | **DNS manager divergence** across distros. Concretely: **Debian does not ship or enable `systemd-resolved` by default** (it is a separate package and *"was not, and still is not, the default DNS resolver in Debian"*), and **Arch installs but does not enable it** — so a `resolvectl`-only code path silently does nothing on half our target matrix. Can cause a silent leak or an unrestorable state. | **High** | Treat DNS as a **runtime-detected strategy**, never assume `systemd-resolved`. Detect manager, then use per‑link `resolvectl`/`resolve1` where available and a `resolvconf`/NetworkManager hook otherwise; never rewrite `/etc/resolv.conf` or `nsswitch.conf`; keep a lease/backup file in `/run`; **verify resolution after applying** rather than trusting the API call. |
| **R‑8** | **AppImage cannot install the helper**, so a user who only has the AppImage gets a degraded, leak‑prone mode. | Medium | Detect missing helper and label the mode explicitly in the UI ("no kill switch available"); guide installation of the system package; ship helper+Xray+geo data in deb/rpm only. |
| **R‑9** | **Architecture‑specific netlink struct layout** (x64 vs arm64) causing corrupted routing messages. | Medium | Prefer a maintained managed netlink library; add struct‑size/alignment assertions at startup; test both architectures in the privileged tier. |
| **R‑10** | **IPv6 leak** if the tunnel is IPv4‑only and IPv6 is enabled on the physical link. | **High** (silent leak) | `inet` table with a default‑drop policy and no IPv6 exception unless the tunnel carries IPv6; keep `vpn_endpoint6` empty for IPv4‑only profiles so all IPv6 egress is dropped; optionally add an explicit `meta nfproto ipv6 drop`. |

---

## 4. Implementation plan

**Phase 0 — decisions & verification (no code shipping risk).**
Settled by cross‑reference: Xray creates the TUN interface and the config fields are
`name` / `mtu` / `gateway` / `autoSystemRoutingTable` / `autoOutboundsInterface`; pin
**Xray ≥ `v26.9.9`** (see §1.1 and [`03-xray-tun-inbound.md`](03-xray-tun-inbound.md)).
Still to decide: support policy for **minimum kernel 5.13+** (required for per‑process
`cgroupv2` routing) and the documented fallback below it; and the polkit default
(`auth_admin_keep` vs `auth_self_keep`) with the product owner.

**Phase 1 — read‑only foundations in the client (no privileges).**
Implement the four interfaces with *dry‑run* implementations that only render ruleset
text and call `nft -c -f` for validation (mirroring §2.10). Implement distro/DNS/cgroup
detection. Ship this first: it is fully CI‑testable and it de‑risks the ruleset text.

**Phase 2 — privileged helper skeleton.**
`myvpn-helper` as a systemd system service with the D‑Bus name, the polkit action, the bus
policy, and a no‑op `Ping`/`Status`. Verify hardening (`systemd-analyze security`).
Implement `IKillSwitch` (arm/disarm/update/getstate) and `--cleanup`. This is the first
phase that needs the privileged VM tier.

**Phase 3 — connectivity.**
Spawn/supervise Xray on `myvpn.slice` membership rules; implement `IRouteManager`
(netlink primary, `ip` fallback); implement `IDnsConfigurator` for
`systemd-resolved`. End‑to‑end connect/disconnect, including the crash paths
(`kill -9` the helper and confirm internet is restored and no leaked traffic occurred).

**Phase 4 — process routing.**
`IProcessRouter` with slice creation, `systemd-run --slice=` launch, the cgroupv2 mark
ruleset, and `VerifyEffectiveAsync`. Add the `meta skuid` fallback for hosts without
cgroup v2.

**Phase 5 — system proxy & UX.**
GNOME/KDE/env‑var backends with snapshot/restore, plus clear in‑UI labelling that this is
not a security control.

**Phase 6 — packaging.**
deb + rpm with the FHS layout (§2.8), `postinst`/`prerm` handling, AppImage detection of a
missing helper, and a documented manual recovery command.

**Sequencing rationale:** the kill switch and its crash cleanup (Phases 2–3) come before
process routing, because a correct fail‑closed kill switch is the security foundation and
process routing is an optimisation on top of it.

---

## 5. Files/modules affected (`src/MyVpn.*`)

Proposed layout; only new files, no existing `src/` code is modified by this research.

```
src/MyVpn.Core/                         # platform-agnostic contracts (no Linux specifics)
  Networking/IKillSwitch.cs             # + KillSwitchState, VpnEndpoint, ValidationResult
  Networking/IRouteManager.cs           # + RouteLease
  Networking/IDnsConfigurator.cs        # + DnsLease, DnsBackend
  Networking/IProcessRouter.cs          # + ProcessRouteLease
  Networking/NetworkingConstants.cs     # fwmark 0xca6c, table 100, priorities, iface name

src/MyVpn.Platform.Linux/               # unprivileged client-side Linux implementation
  Nftables/NftRulesetTemplates.cs       # renders assets/10,20,30 templates (single source of truth)
  Nftables/NftValidator.cs              # `nft -c -f` pre-flight validation
  Nftables/NftJsonParser.cs             # parse `nft -j` counters/state
  Netlink/NetlinkRouteManager.cs        # primary IRouteManager (AF_NETLINK/NETLINK_ROUTE)
  Netlink/IpCommandRouteManager.cs      # fallback IRouteManager (`ip`), used in diff tests
  Dns/SystemdResolvedDnsConfigurator.cs # per-link DNS via resolve1 D-Bus, resolvectl fallback
  Dns/ResolvconfDnsConfigurator.cs      # Debian/Arch openresolv hook path
  Dns/DnsBackendDetector.cs
  Cgroups/CgroupV2ProcessRouter.cs      # slice + cgroupv2 mark rules; skuid fallback
  Cgroups/CgroupV2Features.cs           # kernel/nftables capability probing
  SystemProxy/GnomeProxyBackend.cs      # gsettings, with snapshot/restore
  SystemProxy/KdeProxyBackend.cs        # kwriteconfig5/6 + Plasma notification
  SystemProxy/EnvironmentProxyBackend.cs# ~/.config/environment.d
  Helper/DbusHelperProxy.cs             # client-side D-Bus proxy implementing the 4 interfaces
  Packaging/PathResolver.cs             # FHS + $APPDIR + $MYVPN_DATA_DIR search order

src/MyVpn.Helper/                       # the privileged daemon (root, CAP_NET_ADMIN only)
  Program.cs                            # --system-bus | --cleanup
  Dbus/HelperService.cs                 # org.mylvpn.Helper1 methods/signals
  Dbus/PolkitAuthorizer.cs              # polkit check using bus-derived caller identity
  Dbus/CallerIdentity.cs                # GetConnectionUnixUser / polkit subject
  Kernel/NftablesKillSwitch.cs          # IKillSwitch (commit path)
  Kernel/RouteManager.cs                # IRouteManager (commit path)
  Kernel/DnsConfigurator.cs             # IDnsConfigurator (commit path)
  Kernel/ProcessRouter.cs               # IProcessRouter (commit path)
  Xray/XraySupervisor.cs                # spawn/monitor xray, outside myvpn.slice
  Xray/XrayConfigGenerator.cs           # tun inbound config: name="myvpn0", gateway prefixes, autoOutboundsInterface
  Endpoint/EndpointResolver.cs          # resolve BEFORE arming (R-4)
  Cleanup/CleanupService.cs             # ExecStopPost: delete tables (existence-checked), rules, DNS, proxy

packaging/                              # new
  deb/DEBIAN/{control,postinst,prerm,postrm}
  rpm/myvpn.spec
  systemd/myvpn-helper.service          # §2.5
  systemd/myvpn-xray.service
  polkit/org.mylvpn.policy              # §2.5
  dbus/org.mylvpn.Helper1.conf          # §2.5
  appimage/AppRun                        # helper-presence detection, degraded mode

test/MyVpn.Platform.Linux.Tests/        # CI-testable (see §6)
```

Note: `assets/10-myvpn-killswitch.nft`, `assets/20-myvpn-process-route.nft`, and
`assets/30-myvpn-dns-guard.nft` in this research directory are the reference text;
`NftRulesetTemplates.cs` should embed them as resources so the report and the shipped
ruleset cannot drift.

---

## 6. Tests

**Tier A — CI‑testable, no privileges (runs on every commit, both x64 and arm64 runners).**

* **Ruleset syntax & static semantics:** run `nft -c -f` over the rendered templates for
  every profile permutation (IPv4‑only, dual‑stack, split‑DNS, endpoint ranges,
  0/1/many endpoints). Assert **empty stderr**. This is the exact check that caught the
  `counter comment` and `fwd` bugs, and it needs no root. Include negative tests that
  assert deliberate corruption *is* rejected, so the harness cannot silently pass.
* **Ruleset snapshot tests:** golden‑file the rendered text for representative profiles to
  catch unintended changes (including ordering, which is semantically significant).
* **Reserved‑word / identifier tests:** assert chain and set names avoid nftables
  keywords (`fwd`, `drop`, `accept`, `mark`, …).
* **Path resolver tests:** FHS, `$MYVPN_DATA_DIR`, `$APPDIR`, portable layout — assert
  geo data and the Xray binary are never resolved from the client's own directory.
* **DNS backend detection:** table‑driven tests over synthetic `/etc/resolv.conf` symlink
  states, `systemctl is-active` results, and `resolvconf` presence.
* **Proxy snapshot/restore:** round‑trip `gsettings`/`kwriteconfig` invocations against a
  mocked process runner, including corrupt/missing snapshot recovery.
* **Netlink codec round‑trip (unit level):** serialize `RTM_NEWROUTE`/`RTM_NEWRULE`
  messages and assert sizes/alignment for both x64 and arm64 — catches R‑9 without a
  kernel.
* **Cleanup idempotency:** calling `DisarmAsync`/`RemoveAsync`/`RestoreAsync` twice, or on
  never‑installed state, must succeed. This validates the *existence-check then `delete`*
  strategy and guards against a future developer "simplifying" it to `destroy`, which
  nftables 1.0.2 rejects.
* **No‑privilege assertion:** the client‑side (non‑helper) assemblies must not contain any
  `nft`/`ip`/`resolvectl` *mutating* call path — enforceable by an architecture test that
  the client only references the D‑Bus proxy implementations.

**Tier B — requires a privileged VM (root / `CAP_NET_ADMIN`; cannot run in normal CI).**

Provision disposable VMs per distro release (Ubuntu 22.04/24.04, Debian 12, Fedora
latest, Arch) on both x86‑64 and arm64, with a controllable virtual uplink and a real or
containerised VPN endpoint.

* **TUN lifecycle:** assert Xray creates `myvpn0`; assert that killing Xray removes the
  interface **and** its routes.
* **Kill switch effectiveness:** with the switch armed, assert that traffic to an
  arbitrary external IP fails, that traffic to the VPN endpoint succeeds, that IPv6
  (`curl -6`) fails when the tunnel is IPv4‑only, and that DHCP renewal still works
  (R‑10, R‑4).
* **Crash recovery:** `kill -9` the helper with the switch armed; assert the host is
  *not* leaking (fail‑closed held) and that `--cleanup`/next launch restores full
  connectivity. Then kill the whole VM and assert reboot is clean because nothing was
  persisted to `/etc/nftables.conf` (R‑3).
* **Atomic replacement:** with continuous ping/DNS traffic in flight, reload the ruleset
  repeatedly and assert **zero** dropped/delayed packets attributable to a partially
  configured firewall — the empirical proof of atomicity.
* **Process routing correctness:** put app A in `myvpn.slice` and app B outside; assert
  A's traffic egresses via `myvpn0` and B's via the physical link (compare source IPs at
  the far end). Then **recreate** the slice and assert the rules are re‑applied and still
  effective (R‑1) — this is the test most likely to catch the cgroup‑ID staleness bug.
  Also assert Xray's own upstream traffic never enters the tunnel (loop prevention).
* **cgroup v2 fallback:** on a host booted with `systemd.unified_cgroup_hierarchy=0` or a
  pre‑5.13 kernel, assert `socket cgroupv2` is detected as unavailable and the `skuid`
  fallback engages with a clear state message (R‑5).
* **DNS:** assert that per‑link DNS is used, that `resolvectl revert` restores the prior
  state, that no query escapes to the physical resolver (capture on the virtual uplink),
  that the IPv6 DNS drop works, and that killing the helper mid‑session leaves DNS
  recoverable (R‑7).
* **DNS on a `systemd-resolved`-absent host — must be an explicit matrix row.** On a
  **Debian 12 default install** (no `systemd-resolved`) and on **Arch with the service
  left disabled**, assert that MyVpn detects the real manager, configures DNS via the
  `resolvconf`/NetworkManager path, still produces zero leaks, and restores cleanly.
  A `resolvectl`-only implementation will appear to "succeed" while changing nothing —
  so this test must assert the *observable* resolver, not the exit code of the
  configuration call (R‑7).
* **Polkit/D‑Bus:** assert an unprivileged user without the action is denied; that an
  authorized user is prompted once with `auth_admin_keep` and not re‑prompted; that the
  helper ignores a forged UID argument; and that a malformed argument is rejected (R‑6).
  Run `systemd-analyze security myvpn-helper.service` and assert the exposure score is
  below an agreed threshold.
* **Routing:** assert table 100/priorities are installed correctly, that the endpoint
  route uses the physical uplink (no loop), that `prohibit` makes marked traffic
  fail‑closed when the tunnel is down, and that cleanup removes every rule (R‑9,
  §2.6).
* **Packaging:** install/upgrade/remove the deb and rpm; assert the unit, polkit action,
  and bus policy land in the right paths; assert removal flushes MyVpn tables so the host
  regains internet; solve the AppImage‑with‑no‑helper degraded‑mode path.

**Recommended CI split:** Tier A on every pull request (fast, hermetic, both arches via
cross‑compiled unit tests). Tier B nightly and on release candidates, on a matrix of
distro × arch VMs, with network fault injection. The Tier B matrix is the only place the
security claims of this design can actually be falsified.

---

## Appendix A — Primary sources

* Kernel TUN/TAP: <https://docs.kernel.org/networking/tuntap.html>
* Kernel cgroup v2: <https://docs.kernel.org/admin-guide/cgroup-v2.html>
* nftables — atomic rule replacement: <https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement>
* nftables — configuring chains (types/hooks/priority/policy): <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains>
* nftables wiki — scripting: <https://wiki.nftables.org/wiki-nftables/index.php/Scripting>
* nftables wiki — setting packet metainformation (marks, kernel ≥ 3.14): <https://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_metainformation>
* nfnetlink batch commit-or-abort (kernel source): <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0628b123c96d126e617beb3b4fd63b874d0e4f17>
* nft_socket cgroupv2 kernel commit (5.13): <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e0bb96db96f8ca94349344a2ea7bebc6f8cefdae>
* Debian 12 release notes — systemd-resolved is not the default resolver: <https://www.debian.org/releases/bookworm/amd64/release-notes/ch-information.en.html#systemd-resolved>
* Fedora 33 networking release notes — resolved becomes default: <https://docs.fedoraproject.org/en-US/fedora/f33/release-notes/sysadmin/Networking/>
* Fedora Change: systemd-resolved (stub mode, nsswitch): <https://fedoraproject.org/wiki/Changes/systemd-resolved>
* ArchWiki: systemd-resolved (installed but not enabled by default): <https://wiki.archlinux.org/title/Systemd-resolved>
* ArchWiki: cgroups (cgroup v2; v1 force removed in systemd v258): <https://wiki.archlinux.org/title/Cgroups>
* Debian wiki resolv.conf / resolvconf package: <https://wiki.debian.org/resolv.conf>
* polkit(8) authorization rules and action semantics: <https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html>
* CVE-2021-4034 (PwnKit) advisory: <https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt>
* network_namespaces(7): <https://man7.org/linux/man-pages/man7/network_namespaces.7.html>
* kernel no_new_privs: <https://docs.kernel.org/userspace-api/no_new_privs.html>
* nft(8) man page (socket expression, meta, table flags): <https://www.mankier.com/8/nft> and the installed `nft(8)` on the research host (nftables v1.0.2)
* `nft_socket` cgroupv2 support (Linux ≥ 5.13, nftables ≥ 0.99): <https://patchwork.ozlabs.org/project/netfilter-devel/patch/20210426171056.345271-3-pablo@netfilter.org/>
* cgroupv2 rule staleness, `NFTSet=`, systemd integration: <https://github.com/mk-fg/systemd-cgroup-nftables-policy-manager>
* cgroup v2 default distros + delegation defaults: <https://raw.githubusercontent.com/opencontainers/runc/main/docs/cgroup-v2.md>
* systemd-resolved: <https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html>
* systemd.exec hardening: <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html>
* polkit `pkexec`: <https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html> (also installed `pkexec(1)`)
* polkit reference: <https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html>
* D‑Bus system bus policy: <https://www.freedesktop.org/software/dbus/doc/dbus-daemon.1.html>
* FHS 3.0: <https://refspecs.linuxfoundation.org/FHS_3.0/fhs-3.0.html>
* AppImage docs (read‑only squashfs, `$APPDIR`): <https://docs.appimage.org/>
* `ip-rule(8)` / `ip-route(8)`: <https://man7.org/linux/man-pages/man8/ip-rule.8.html>

## Appendix B — Items explicitly marked UNVERIFIED

1. ~~Xray‑core's exact TUN inbound config schema, default device name, MTU/`IFF_NO_PI`
   behaviour, and multi‑queue support for the pinned version.~~
   **RESOLVED** by cross‑referencing the sibling report
   [`03-xray-tun-inbound.md`](03-xray-tun-inbound.md): Xray creates the interface via
   `/dev/net/tun` + `TUNSETIFF` with `IFF_TUN|IFF_NO_PI`; the name is the `name` field
   (default a random `utunN`); the address comes from `gateway`; `mtu` is scalar from
   `v26.4.15` (broken `repeated` in `v26.4.13`); minimum recommended version `v26.9.9`.
   See §1.1. Remaining residual: `IFF_MULTI_QUEUE` is **not** used by Xray, so MTU/single
   queue throughput tuning is not available to us.
2. `pkexec` is unsuitable for long‑running operations — this is inferred from its
   one‑shot `exec` model and argument‑validation gap; **`pkexec(1)` contains no sentence
   stating it verbatim**, and in particular does **not** claim the process is killed or
   must re-authenticate when the terminal/agent disconnects. An independent verification
   pass against three copies of the man page found no such language. Do not cite the man
   page for this claim (§1.6).
3. `resolved.conf(5)` per‑link DoH syntax on the oldest supported systemd releases (§2.4).
4. `resolvconf` presence by default on current Debian/Fedora minimal installs varies;
   detection must be runtime (§2.4). **Partially resolved:** Debian 12 release notes
   confirm `systemd-resolved` is *not* the default resolver and is not auto‑installed;
   whether the `resolvconf` binary itself is present on a *default* install is still
   unconfirmed.
5. D‑Bus `busconfig` element ordering/semantics against the oldest supported D‑Bus
   version (§2.5).
6. The `ip rule … prohibit` fail‑closed behaviour and full `ip rule`/`ip route` syntax
   were not executed (no `CAP_NET_ADMIN` on the research host) (§2.6).
7. Whether `auth_admin_keep` or `auth_self_keep` is the right polkit default is a
   product decision (§2.5).
8. Whether an `accept`/`drop` from a third‑party nftables chain at a later priority will
   interfere in practice on each target distro's default firewall configuration (§1.3,
   R‑2) — must be tested on real installs.
9. The **exact first userspace nftables release** that shipped `socket cgroupv2` support
   (likely 1.0.0, Aug 2021) — unconfirmed; the kernel side (5.13) is verified. We
   feature‑detect rather than rely on a version string (§1.2).
10. The "create new table, delete old table, same transaction" pattern is a **design
    inference** from confirmed commit‑or‑abort semantics, not an upstream‑documented
    recommendation; the wiki page `Ruleset_replace` does not exist (404) (§1.3).
11. FHS's canonical home has moved (Linux Foundation 3.0 = 2015, now also mirrored at
    freedesktop); the two copies agree on the directory purposes we rely on (§1.7).
12. `RestrictAddressFamilies=` ABI caveats: on some 32‑bit ABIs it is silently ignored —
    combine with `SystemCallArchitectures=native` (§2.5).
