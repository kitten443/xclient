# 08 — macOS Platform Networking Research (Intel + Apple Silicon)

**Scope:** how a self-distributed (non-App-Store) .NET 8 + Avalonia Xray client can install a
privileged helper, create a packet tunnel, install a kill switch, configure DNS and routing,
and what is *actually* possible for per-process routing on modern macOS.

**Author:** macOS Platform Networking Research Agent
**Date:** 2026-09-16
**Host constraint:** research performed on Linux/x86-64. No macOS machine was available, so **no
claim in this document was executed or observed on macOS**. Every claim is either (a) backed by a
cited primary source (Apple documentation, Apple open-source XNU source, macOS man pages), or
(b) explicitly marked `UNVERIFIED`. Where a claim is an engineering inference rather than a
documented fact, it is marked `INFERENCE`.

**macOS versions in scope:** macOS 13 Ventura, 14 Sonoma, 15 Sequoia, 26 Tahoe (the release
shipped in 2025 and current at the time of writing, September 2026). Anything specific to a single
release is called out. Apple's documentation copyright read at fetch time was "Copyright © 2026
Apple Inc." — i.e. the docs below are current-generation.

Legend used throughout:

| Marker | Meaning |
| --- | --- |
| `[DEV-ID]` | Works for a Developer ID–signed, self-distributed app (notarized, outside the App Store). |
| `[APP-STORE]` | Works only for App Store distribution. |
| `[MANAGED]` | Requires a configuration profile / MDM (managed device). |
| `UNVERIFIED` | Could not confirm against a primary source; treat as a research task before shipping. |
| `INFERENCE` | Engineer's conclusion from cited facts, not itself a cited statement. |

**Method.** Three parallel research passes (PF/kill switch; DNS/routing/proxy; packaging/signing),
each primary-source-first, plus direct verification of the privileged-helper, NetworkExtension,
utun, `IP_BOUND_IF` and per-process mechanisms. ~90 sources; the full list is in Appendix A and the
open questions in Appendix B.

### TL;DR (the three answers that matter)

1. **Tunnel:** raw `utun` created by a root privileged helper (`SMAppService` daemon on macOS 13+).
   No Apple-gated entitlement — the kernel control is registered `CTL_FLAG_PRIVILEGED`. `[DEV-ID]`
   `NEPacketTunnelProvider` is *also* possible for Developer ID but needs the `*-systemextension`
   entitlement plus a provisioning profile and a **native** extension, so it is a poor fit for an
   open-source .NET client.
2. **Kill switch:** replace the main PF ruleset (preserving Apple's `com.apple/*` anchors), take a
   `pfctl -E` reference token, release only that token, `pfctl -F states` on every transition.
   **But Apple TN3165 says PF "is not considered API" and tells you not to ship products that rely on
   it — so this is a best-effort feature, and the plan must keep the option of Network Extension
   open.**
3. **Per-process routing: not achievable.** PF `user`/`group` filter but do not route (and are
   TCP/UDP-only, credential-at-socket-creation); macOS PF *does* document `route-to`, but a
   `user`-scoped `route-to` is directional-only, cannot rewrite source addresses, and is unproven;
   `ipfw` is gone; NECP is internal; NE per-app VPN is read-only to the provider and installed by a
   managed profile; `NEFilterDataProvider` cannot relay. Ship destination-based split tunnelling,
   UID block-lists, and proxy mode — and say so plainly in the UI.

---

## 1. Findings

### 1.1 Privileged helper: `SMJobBless` vs `SMAppService`, signing, XPC, .NET hosting

#### 1.1.1 What Apple recommends now

`SMJobBless` is **deprecated as of macOS 13.0**, with the deprecation message *"Please use
SMAppService instead"*. Apple's own documentation for the symbol states
`deprecatedAt: 13.0`, `introducedAt: 10.6`.
Source: <https://developer.apple.com/documentation/servicemanagement/smjobbless(_:_:_:_:)>

`SMAppService` is the replacement, introduced in **macOS 13.0** (and Mac Catalyst 16.0). Apple
describes it as: *"In macOS 13 and later, use `SMAppService` to register and control `LoginItems`,
`LaunchAgents`, and `LaunchDaemons` as helper executables for your app."* and maps each kind to the
older API it replaces (e.g. `LaunchDaemons` → replacement for *"installing property lists in
`/Library/LaunchDaemons`"*).
Source: <https://developer.apple.com/documentation/servicemanagement/smappservice>

Key API surface (verified from the same page and its symbol references):

| Symbol | Notes |
| --- | --- |
| `SMAppService.daemon(plistName:)` | *"Initializes an app service object with a launch daemon with the property list name you provide."* |
| `SMAppService.agent(plistName:)` | Launch agent variant. |
| `SMAppService.loginItem(identifier:)` | Login item variant. |
| `SMAppService.mainApp` | *"An app service object that corresponds to the main application as a login item."* |
| `register()` | *"Registers the service so it can begin launching subject to user approval."* — throws. |
| `unregister()` / `unregister(completionHandler:)` | *"Unregisters the service so the system no longer launches it."* |
| `status` → `SMAppService.Status` | *"A property that describes registration or authorization state of the service."* |
| `SMAppService.Status` | Confirmed four cases with Apple's own descriptions: `notRegistered` — *"The service hasn't registered with the Service Management framework, or the service attempted to reregister after it was already registered."*; `enabled` — *"The service has been successfully registered and is eligible to run."*; `requiresApproval` — *"The service has been successfully registered, but the user needs to take action in System Preferences."*; `notFound` — *"An error occurred and the framework couldn't find this service."* (ObjC: `SMAppServiceStatus*`.) |
| `SMAppService.daemon(plistName:)` path requirement | *"The property list name must correspond to a property list in the calling app's `Contents/Library/LaunchDaemons` directory."* |
| `SMAppService.openSystemSettingsLoginItems()` | *"Opens System Settings to the Login Items control panel."* |
| `SMAppService.statusForLegacyPlist(at:)` | Authorization status for a pre-macOS-13 plist. |

#### 1.1.2 Bundle layout for a modern helper (this differs from `SMJobBless`)

Apple's article "Updating helper executables from earlier versions of macOS" gives the required
layout **inside the app bundle**:

- helper executable: *"Install the helper executable within the app bundle, such as in
  `Contents/Resources`."*
- `LaunchAgent` plists → `Contents/Library/LaunchAgents`
- `LaunchDaemon` plists → `Contents/Library/LaunchDaemons`
- in the plists, *"replace the `Program` key with the `BundleProgram` key and make the path
  relative to the bundle, such as `Contents/Resources/mydaemon`."*
- the sample shows `SMAppService.daemon(plistName: "com.example.daemon.plist")` resolving to
  `$APP.app/Contents/Library/LaunchDaemons/com.example.daemon.plist`
- legacy plists need the optional `AssociatedBundleIdentifiers` key; *"The Team Identifier of the
  `Program` or `ProgramArguments` executable in the legacy property list must match that of the app
  bundle"*.
- *"If your app uses launch daemons, it needs to register those first. Launch daemons require
  authentication by the user because the user is authorizing a system level-process. If the user
  authorizes the `LaunchDaemon`, the system approves all the other helper executables present in
  the app bundle"* — i.e. one approval covers the app's other helpers.

Source: <https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos>
Related sample: <https://developer.apple.com/documentation/servicemanagement/updating-your-app-package-installer-to-use-the-new-service-management-api>

**The `–attribute–` consequence:** with `SMAppService` the helper no longer needs to live in
`Contents/Library/LaunchServices`. That directory is an `SMJobBless` requirement (see 1.1.3).
A build that supports both paths must ship the helper in the location each API expects, or keep a
single helper in `Contents/Resources` and use `SMAppService` only on 13+, falling back to
`SMJobBless` on 12 and older.

#### 1.1.3 The `SMJobBless` code-signing handshake (`[DEV-ID]`, macOS ≤ 12; deprecated 13+)

Apple's `SMJobBless` documentation specifies the complete handshake. It requires:

1. *"Xcode must sign both the calling app and target executable tool."*
2. The **calling app's** `Info.plist` must contain `SMPrivilegedExecutables`, a dictionary of
   strings: *"Each string is a textual representation of a code signing requirement the system uses
   to determine whether the app owns the privileged tool once installed (for example, in order for
   subsequent versions to update the installed version)."* Each key is *"a reverse-DNS label for the
   helper tool that must be globally unique."*
3. The **helper tool** must have an *embedded* `Info.plist` containing `SMAuthorizedClients`, an
   array of strings, *"Each string is a textual representation of a code signing requirement
   describing a client allowed to add and remove the tool."*
4. The helper must have an embedded launchd property list whose only required key is `Label`; the
   framework **overwrites** `ProgramArguments` with a single element pointing at the installed
   location: *"You can't specify your own program arguments, so don't rely on the system passing
   custom command line arguments to your tool. Pass any parameters through an inter-process
   communication (IPC) channel."*
5. *"The helper tool must reside in the `Contents/Library/LaunchServices` directory inside the
   application bundle, and its name must be its launchd job label."*
6. The `AuthorizationRef` passed in must hold `kSMRightBlessPrivilegedHelper`; the only supported
   domain is `kSMDomainSystemLaunchd`.

Source: <https://developer.apple.com/documentation/servicemanagement/smjobbless(_:_:_:_:)>

The **same Team ID** requirement is implicit in the requirement strings: the string in
`SMPrivilegedExecutables` (app-side, describing the helper) and the strings in `SMAuthorizedClients`
(helper-side, describing allowed clients) are *code signing requirement* strings. In practice they
are written as `identifier "com.example.myvpn.helper" and anchor apple generic and certificate
leaf[subject.OU] = "TEAMID1234"`, which pins both the signing identifier and the Team ID. The
requirement-string language is Apple's Code Signing Requirement Language — the canonical reference
is `man 1 csreq` / the "Code Signing Guide" requirement-language chapter, **UNVERIFIED for the exact
current URL** (Apple's archived Code Signing Guide). Any deviation (different Team ID, ad-hoc
signing, changed identifier) makes `SMJobBless` fail.

#### 1.1.4 XPC: the Mach service model

The launchd plist for a system daemon advertises a Mach service:

```xml
<key>Label</key><string>com.example.myvpn.helper</string>
<key>BundleProgram</key><string>Contents/Resources/MyVpnHelper</string>
<key>MachServices</key>
<dict><key>com.example.myvpn.helper</key><true/></dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
```

The client connects to it with the XPC C API:

- `xpc_connection_create_mach_service(name, targetq, flags)`.
- *"If the destination service is advertised in the root Mach bootstrap (i.e. the launchd.plist
  lives in /Library/LaunchDaemons), the caller may ensure that the service that it connects to is
  privileged and not being spoofed through a man-in-the-middle attack by OR'ing the
  `XPC_CONNECTION_MACH_SERVICE_PRIVILEGED` flag into the flags argument. This flag will cause
  `XPC_ERROR_CONNECTION_INVALID` to be given to the event handler if the service name was not found
  in the root Mach bootstrap."*
- Server side: *"The launchd job using XPC is required to create a listener connection manually by
  calling `xpc_connection_create_mach_service`() with the `XPC_CONNECTION_MACH_SERVICE_LISTENER`
  flag OR'ed into the flags argument."*
- *"If the service name for the connection is not present in your launchd.plist's MachServices
  dictionary, your listener connection's event handler will receive the
  `XPC_ERROR_CONNECTION_INVALID` error, as XPC disallows ad-hoc service name registrations."*
- Lifecycle: a peer that crashes delivers `XPC_ERROR_CONNECTION_INTERRUPTED` (recoverable — the
  connection stays usable) and an unloaded job delivers `XPC_ERROR_CONNECTION_INTERRUPTED` followed
  by `XPC_ERROR_CONNECTION_INVALID`.
- *"New service names may NOT be dynamically registered using
  `xpc_connection_create_mach_service`(). Only launchd jobs may listen on certain service names."*

Source: `man 3 xpc_connection_create` — <https://keith.github.io/xcode-man-pages/xpc_connection_create.3.html>

**Client authentication (critical).** The same man page is explicit that legacy credential checks
are insecure:

- *"Modern XPC applications should use peer requirement APIs for secure validation of connecting
  processes. These APIs provide automatic, continuous validation of every incoming message and
  prevent connection sharing attacks."* The available functions are
  `xpc_connection_set_peer_lightweight_code_requirement()`,
  `xpc_connection_set_peer_code_signing_requirement()`,
  `xpc_connection_set_peer_entitlement_exists_requirement()`,
  `xpc_connection_set_peer_entitlement_matches_value_requirement()`,
  `xpc_connection_set_peer_team_identity_requirement()`, and
  `xpc_connection_set_peer_platform_identity_requirement()`; failures are delivered as
  `XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT`.
- *"Legacy credential information … PID, EUID, EGID and ASID … credential checking using these APIs
  is inherently insecure and should be avoided. A malicious client can send its connection mach port
  to another process with different credentials, bypassing credential checks performed only at
  connection establishment time. Additionally, **PIDs on macOS roll over when they reach a
  relatively small value, and a given PID cannot be assumed to be unique for a given boot session**,
  making PID-based validation unreliable."*

**Design consequence:** the helper must call
`xpc_connection_set_peer_team_identity_requirement(peer, "<TEAMID>")` (and/or
`xpc_connection_set_peer_code_signing_requirement` with a full requirement string) on **every**
inbound peer connection, not merely at first connection. Never authenticate by PID/EUID.

#### 1.1.5 Hosting/consuming XPC from .NET — honest assessment

Facts:

- `SMAppService` is documented **only as an Objective-C class / Swift class**
  (`@interface SMAppService : NSObject`, `class SMAppService`). No C function equivalent is
  documented. Source: the `SMAppService` page cited above (its declarations section).
  → A pure-.NET caller must either P/Invoke `objc_msgSend` against `libobjc.dylib` using the
  Objective-C runtime's `objc_getClass`/`sel_registerName`, or ship a tiny signed native shim.
- `SMJobBless` **is** a C function and is directly P/Invokable:
  `Boolean SMJobBless(CFStringRef domain, CFStringRef executableLabel, AuthorizationRef auth,
  CFErrorRef *outError)` with
  `[DllImport("/System/Library/Frameworks/ServiceManagement.framework/ServiceManagement")]`.
- **A .NET helper cannot work under `SMJobBless` unless it is single-file/self-contained.** Apple
  documents that the framework *"extracts the launchd property list and writes it to disk, it sets the
  key for `ProgramArguments` to an array of **1 element** that points to a standard location. You can't
  specify your own program arguments."* SMJobBless therefore installs **one** executable. A normal
  framework-dependent .NET helper is a *directory* (`MyHelper`, `MyHelper.dll`,
  `MyHelper.runtimeconfig.json`, `MyHelper.deps.json`, plus the runtime), so it cannot be blessed as-is.
  The options are (a) `PublishSingleFile` + self-contained for the helper, or (b) install the payload
  with a `.pkg` and use SMJobBless only to register it. **This is a strong argument for
  `SMAppService`, whose bundle-resident model (`BundleProgram`) handles a folder-based helper
  naturally.** (`UNVERIFIED` as a verbatim Apple statement that side-by-side `.dll`s break
  SMJobBless; it follows directly from the quoted "array of 1 element".)
- The XPC **C** API is public and documented (man page above): listener creation, message
  dictionaries, synchronous reply, fds, and the modern peer-requirement setters.

Practical hosting options, in order of robustness:

| Option | Description | Risk |
| --- | --- | --- |
| **A (recommended)** | Ship the privileged daemon as a **small native binary** (Swift/ObjC/C, ~300 lines) that owns the utun, routes, DNS and PF operations and speaks XPC. The Avalonia/.NET app is a pure XPC *client*. | Lowest risk; .NET only needs `xpc_connection_create_mach_service` + `xpc_connection_send_message_with_reply_sync`, neither of which needs a block. |
| **B** | .NET daemon using XPC C API. The **listener** requires an event-handler *block*. .NET cannot pass a managed delegate as a block; a static "global block" struct (`struct BlockLayout { void* isa; int flags; int reserved; void* invoke; void* descriptor; }`) pointing at an `[UnmanagedCallersOnly]` function can be synthesized, but this is ABI-fragile and unsupported. | High; needs a native `_Block_copy` helper at minimum. |
| **C** | Skip XPC. Have launchd create a **UNIX-domain socket** for the daemon (`Sockets` key with `SockPathName`), and consume it from .NET with `Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified)` — no blocks, no ObjC. Authenticate the peer with `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, …)` to obtain an **audit token**, then validate code signature with `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` + `SecRequirementCreateWithString` + `SecCodeCheckValidity`. | Medium; `LOCAL_PEERTOKEN` is defined in XNU `<sys/un.h>` as `0x006 /* retrieve peer audit token */` (see sources) so the mechanism is real, but it is less traveled than XPC and Apple's deployment guidance centres on XPC. |
| **D** | `NSXPCConnection` from .NET | Not practical; requires ObjC protocol conformance and blocks. Not recommended. |

`LOCAL_PEERTOKEN` primary source: <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/un.h>
(also defines `LOCAL_PEERCRED 0x001`, `LOCAL_PEERPID 0x002`, `LOCAL_PEEREPID 0x003`,
`LOCAL_PEERUUID 0x004`, `LOCAL_PEEREUUID 0x005`).

Also: pass the utun file descriptor from the root helper to an unprivileged data-path process with
`xpc_fd_create()` / `xpc_dictionary_set_fd()` / `xpc_dictionary_get_fd()`. These are part of the
public XPC C object API (`<xpc/xpc.h>`) — **UNVERIFIED as to the specific man page section**
(verify `xpc_object(3)`/`xpc_objects` at implementation time). This is what makes "privileged helper
creates the utun, unprivileged Xray core pumps packets" possible without running the whole VPN core
as root.

#### 1.1.6 Notarization implications for the helper

- If the helper is installed **inside the app bundle** (`Contents/Resources/...` for
  `SMAppService`), it is covered by the app's signature and by the app's notarization ticket. Apple's
  `SMAppService` article explicitly frames the bundle-resident layout as the fix for
  *"specialized installation scripts or permission to write files into system directories."*
- `SMJobBless` copies the helper to `/Library/PrivilegedHelperTools/<label>` — a **copy outside the
  bundle**. Apple's `SMJobBless` requirements above are about signing, not notarization, and Apple
  does not document a separate notarization requirement for the copy; the practical guidance from
  the Gatekeeper model is that an independently-launched executable must itself carry a valid
  Developer ID signature and a stapled/online-notarized ticket, and that its `Info.plist`-embedded
  `SMAuthorizedClients` must be covered by the signature. **UNVERIFIED**: whether a helper copied to
  `/Library/PrivilegedHelperTools` needs its *own* notarization ticket, or whether inheriting the
  app's Developer ID signature is sufficient for the copy. Treat as a must-test item on a clean
  machine with Gatekeeper enabled.
- `SMAppService` daemons are launched by launchd from **inside the bundle**, so there is no
  out-of-bundle copy to notarize.
- Notarization is enforced at *first launch of the app* by Gatekeeper, not at helper registration.
  A non-notarized app cannot be expected to run at all on a stock machine, so notarization is
  mandatory regardless of helper mechanism.

#### 1.1.7 What changed in recent macOS versions (helper area)

| Change | Evidence |
| --- | --- |
| macOS 13: `SMJobBless` deprecated, `SMAppService` introduced; daemons require a **user-approval** step in System Settings → Login Items (and for network extensions also Login Items & Extensions → Network Extensions). | Apple docs above; the Log-in-Items architecture is described in the "Updating helper executables" article. |
| macOS 13+: helper plists move inside the bundle (`Contents/Library/LaunchDaemons`, `BundleProgram`). | Apple article above. |
| macOS 15 Sequoia: users more frequently had to re-approve VPN/network extensions after upgrade; NEHelper behaviour tightened; network filter approvals consolidated in Login Items & Extensions. | Secondary source (blog), **not** Apple: <https://ova.productdevbook.com/blog/macos-sequoia-network-changes> — treat as corroborating context only, `UNVERIFIED`. |
| macOS 26 Tahoe: developer reports of `SMAppService`-based LaunchDaemon XPC connections failing on *some* macOS 26 machines ("`FATAL ERROR - fullPath is nil`"). | Apple Developer Forums thread 813148 found via search; **the thread body could not be fetched** (Apple forums returned a human-verification page). `UNVERIFIED` — listed here as a known-risk to investigate, not as a fact. |

**This is a real risk item:** Apple Developer Forums were not machine-fetchable during this
research (they serve a JS/anti-bot verification page). Several forum URLs found by search could not
be quoted: thread 816877 ("Request for Guidance on Approval Process for Network Extension
Entitlement"), thread 813148 (macOS 26 SMAppService daemon XPC failure), thread 786886 ("Entitlement
Request Support — We require the following Network Extension entitlements without the
`-systemextension` suffix"). Their existence is evidence that the network-extension entitlement
path for Developer ID is a **support-gated** area; their content is `UNVERIFIED`.

---

### 1.2 Packet tunnel options — an honest comparison

#### 1.2.1 (a) Raw `utun` device created by the helper + userspace TUN read/write

**This is what Xray-based macOS clients actually do** (an Xray `tun`-style inbound over a utun
device, or an equivalent `sing-tun`-style TUN front end): a root process creates a utun interface,
reads/writes raw IP packets, and feeds them to the Xray core.

Mechanism (XNU primary source): the utun driver registers a kernel control named
`com.apple.net.utun_control`:

```c
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
```

and registers it with the **privileged** flag:

```c
kern_ctl.ctl_flags = CTL_FLAG_PRIVILEGED | CTL_FLAG_REG_SETUP | CTL_FLAG_REG_EXTENDED; /* Require root */
```

Source: `bsd/net/if_utun.c`, `utun_register_control()` —
<https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.c>
and `bsd/net/if_utun.h` for `UTUN_CONTROL_NAME` and the flags
(`UTUN_FLAGS_NO_OUTPUT 0x0001`, `UTUN_FLAGS_NO_INPUT 0x0002`,
`UTUN_FLAGS_ENABLE_PROC_UUID 0x0004`):
<https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.h>

Additional privileged options: `UTUN_OPT_FLAGS`, `UTUN_OPT_EXT_IFDATA_STATS` and
`UTUN_OPT_SET_DELEGATE_INTERFACE` are gated in `utun_ctl_setopt()` by
`if (kauth_cred_issuser(kauth_cred_get()) == 0) return EPERM;`.

**Answers to the specific questions:**

| Question | Answer |
| --- | --- |
| Privileges needed | **Root**, to open the control socket (`socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` + `connect` to `com.apple.net.utun_control`), plus root to set the interface address/MTU/routes. Confirmed by the `CTL_FLAG_PRIVILEGED` registration and the `kauth_cred_issuser` checks in XNU. |
| Entitlement needed (`com.apple.developer.networking.networkextension`)? | **No documented requirement.** That entitlement is documented as required for the *NetworkExtension classes* (`NEPacketTunnelProvider`: *"The `com.apple.developer.networking.networkextension` entitlement is required in order to use the `NEPacketTunnelProvider` class"*; same statement on `NETunnelProvider`). Raw utun is a kernel control, not a NetworkExtension API. **`UNVERIFIED` as a positive Apple statement that no entitlement is needed** — Apple does not document raw utun for third parties at all. `INFERENCE`: no entitlement applies because the gate is Unix privilege (`CTL_FLAG_PRIVILEGED`), which is exactly the gate a privileged helper passes. |
| Can a Developer ID (non-App-Store) build do it? | **Yes** `[DEV-ID]`. Nothing in the mechanism requires an App Store profile; it requires a root process. |
| Data-path privilege after creation | Reading/writing the already-connected control socket and the interface's packets does not require root; the *instance* is created by root. This is what makes the fd-handoff architecture (§2) possible. **`UNVERIFIED`** exactly which subsequent operations (e.g. `SIOCSIFADDR` via `ioctl`) succeed as non-root on a utun created by root; verify empirically. |

Packet framing: utun is a `DLT_NULL`-style interface — the first 4 bytes of each packet written
to/read from the control socket are the address family **in network byte order** (`utun_output()`
does `*mtod(data, uint32_t *) = htonl(*mtod(data, uint32_t *));`, and the receive path does the
converse). `UTUN_HEADER_SIZE` is `sizeof(u_int32_t)`, plus `sizeof(uuid_t)` if
`UTUN_FLAGS_ENABLE_PROC_UUID` is set. Source: `bsd/net/if_utun.c`.

#### 1.2.2 (b) `NEPacketTunnelProvider` Network Extension

Documented platform availability: macOS 10.11+ (and iOS 9+, tvOS 17+, visionOS 1.0+).
Source: <https://developer.apple.com/documentation/networkextension/nepackettunnelprovider>

**Entitlement (primary source, verbatim):** *"The `com.apple.developer.networking.networkextension`
entitlement is required in order to use the `NEPacketTunnelProvider` class. Enable this entitlement
when creating an App ID in your developer account."*
Source: <https://developer.apple.com/documentation/networkextension/nepackettunnelprovider>
Same statement for the `NETunnelProvider` base class:
<https://developer.apple.com/documentation/networkextension/netunnelprovider>

**Distribution — this is the crux, and Apple documents the Developer ID path.**
The Network Extensions Entitlement page lists these possible values (verbatim descriptions):

- `packet-tunnel-provider` — *"The APIs you use to tunnel IP packets to a remote network using any
  custom tunneling protocol."*
- `packet-tunnel-provider-systemextension` — *"The APIs you use to tunnel IP packets to a remote
  network using any custom tunneling protocol, **when signed with a Developer ID profile**."*
- likewise `app-proxy-provider` / `app-proxy-provider-systemextension`,
  `content-filter-provider` / `content-filter-provider-systemextension`,
  `dns-proxy` / `dns-proxy-systemextension`, plus `dns-settings`, `relay`, `app-push-provider`,
  `url-filter-provider`.

And its Discussion says:

> *"To add this entitlement to an App Store app, enable the Network Extensions capability in Xcode.
> To add this entitlement to a macOS app distributed outside of the Mac App Store, perform the
> following steps: 1. In the Certificates, Identifiers and Profiles section of the developer site,
> enable the Network Extension capability for your Developer ID–signed app. Generate a new
> provisioning profile and download it. 2. On your Mac, drag the downloaded provisioning profile to
> Xcode to install it. 3. In your Xcode project, enable manual signing and select the provisioning
> profile downloaded earlier and its associated certificate. 4. Update the project's
> `entitlements.plist` to include the `com.apple.developer.networking.networkextension` key and the
> values of the entitlement."*

Source: <https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension>

So: **a non-App-Store VPN client can ship `NEPacketTunnelProvider`** `[DEV-ID]`, using the
`-systemextension` entitlement values and a Developer ID provisioning profile embedded in the app.
This is corroborated (secondary, `UNVERIFIED` as to wording) by Developer Forums threads that
describe exactly this configuration, including one titled *"I have a macOS VPN app with a Network
Extension (packet tunnel provider) distributed outside the App Store via Developer ID"*, and
another describing *"a MacOS SwiftUI GUI application that bundles a System Network Extension, signed
with a Developer ID certificate"* (found via search; thread bodies not fetchable).

**Practical difficulty for an open-source / self-distributed client — stated plainly:**

1. **The entitlement is not yours by default.** You must enable the Network Extension capability on
   a Developer ID App ID and mint a profile. Developers report an "Entitlement Request Support"
   process and being told to use the `-systemextension` values instead of the plain ones
   (`UNVERIFIED`, forum thread 786886). Budget for an Apple support interaction and possible delay,
   and note that **this gate is incompatible with the norms of an open-source project where any
   contributor may want to build and run the client**: contributors would be unable to sign a build
   that macOS will run with the extension enabled unless they have their own entitled profile.
2. **System-extension packaging.** The `-systemextension` value names imply the provider must be
   packaged as a **System Extension** (`Contents/Library/SystemExtensions/…`), installed via
   `SystemExtensions`/`OSSystemExtensionRequest`-style flows with its own user-approval prompt. The
   `NEPacketTunnelProvider` page still documents the *app-extension* form
   (`NSExtensionPointIdentifier = com.apple.networkextension.packet-tunnel`), which is what App
   Store builds use; whether the app-extension form is still accepted for Developer ID on macOS 15+
   is `UNVERIFIED` — the existence of the `-systemextension` entitlement variants is strong
   evidence that for Developer ID the system-extension form is the supported one.
3. **The data path must be native.** Viewing configuration/`.systemextension` packaging aside, the
   provider subclass (`startTunnel`, `stopTunnel`, `packetFlow`) is an Objective-C class that
   must run in-process in the extension. **You cannot implement `NEPacketTunnelProvider` in .NET**:
   the extension is loaded by `neagent`/`NEHelper` as a Mach-O bundle whose principal class is an
   ObjC class; `NSExtensionPrincipalClass` must name an ObjC class in that bundle. So a .NET client
   using NE needs a **native Swift/ObjC shim extension** which then talks to the .NET Xray core
   (e.g. over XPC or a UNIX socket), which is a second IPC hop between the tun device and Xray.
4. **User approval + re-approval.** Network extensions appear in System Settings → General → Login
   Items & Extensions → Network Extensions and must be approved; Sequoia tightened this and users
   frequently had to re-approve after upgrade (secondary source, `UNVERIFIED`).
5. **App-Store-grade behavioural rules.** NE is a privileged Apple framework; shipping a custom
   proxy/tunnel through it subjects you to its semantics (`enforceRoutes`,
   `includeAllNetworks`, `excludeLocalNetworks`, `excludeAPNs`, `excludeCellularServices`,
   `disconnectOnSleep` on `NEVPNProtocol`). Source:
   <https://developer.apple.com/documentation/networkextension/nevpnprotocol>.
   Good news: `includeAllNetworks` + `enforceRoutes` give a *framework-level* kill switch that is
   more robust than a PF rule set (see §1.3).

**Verdict for (b):** `[DEV-ID]` **technically possible**, but it is a **heavy, entitlement-gated,
native-only, approval-gated** path that is a poor fit for an open-source self-distributed Xray
client. It is the right answer only if the project is willing to (i) obtain and maintain an
entitlement + provisioning profile, (ii) ship a native system extension, and (iii) accept that
third-party builders cannot fully run the tunnel from source without their own entitlement.

#### 1.2.3 (c) No TUN: userspace proxy + system proxy / PF redirect

- System proxy (`networksetup` / SystemConfiguration) covers HTTP/HTTPS for apps that honour the
  system proxy; many do not (see §1.7). It is trivially `[DEV-ID]` and needs **no privilege at all
  for the user's own settings** (changing system proxy settings does require admin auth in practice
  — `networksetup` needs root).
- PF `rdr` redirect of TCP to a local port is possible, but **PF on macOS cannot redirect UDP to a
  userspace socket**, and TCP `rdr` requires the userspace side to recover the original destination
  (`getsockname` on the accepted socket only yields the local port; you need `DIOCNATLOOK` on
  `/dev/pf`, i.e. the pf ioctl interface, to recover the original address/port). That is a
  substantial native component, needs root, and breaks for QUIC/HTTP3 (UDP 443).
- **Consequence:** a proxy-only approach cannot cover UDP/QUIC, cannot cover arbitrary IP protocols,
  and cannot cover apps that ignore the system proxy. It is a *good fallback*, not a VPN.

**A fourth option worth naming: `NETransparentProxyProvider`** (macOS 10.15+, macOS-only).
This is the NetworkExtension class built specifically to transparently intercept TCP and UDP flows
without a TUN device, and its superclass is `NEAppProxyProvider`. It is *not* a packet tunnel and it
*is* entitlement-gated (`app-proxy-provider` for App Store, `app-proxy-provider-systemextension` for
Developer ID — see §1.2.2's entitlement list), so it is `[DEV-ID]`-possible but requires the same
provisioning-profile machinery and a native extension. Important documented caveats:

- *"This provider ignores `NEDNSSettings` and `NEProxySettings` specified within
  `NETransparentProxyNetworkSettings`. Flows that match the `includedNetworkRules` within
  `NETransparentProxyNetworkSettings` use the same DNS and proxy settings that other flows on the
  system currently use."* → **transparent-proxy mode cannot fix DNS.** DNS must still be handled by
  `/etc/resolver`/SystemConfiguration, and the leak problem in §1.5 remains.
- *"Returning `NO` from `handleNewFlow(_:)` and `handleNewUDPFlow(_:initialRemoteEndpoint:)` causes
  the flow to proceed to communicate directly with the flow's ultimate destination, instead of
  closing the flow with a 'Connection Refused' error."* → non-proxied flows fail open, not closed.
- It is scoped by `NETransparentProxyNetworkSettings.includedNetworkRules` / `excludedNetworkRules`
  (`NENetworkRule`), i.e. **network rules (destination), not per-application rules** — the same
  destination-based limitation as everywhere else on this platform.
- `NETransparentProxyManager` inherits `NEVPNManager` and has
  `loadAllFromPreferences(completionHandler:)`.

Sources: <https://developer.apple.com/documentation/networkextension/netransparentproxyprovider>,
<https://developer.apple.com/documentation/networkextension/netransparentproxymanager>,
<https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings>

For completeness, the DNS-side sibling is `NEDNSProxyProvider` (`dns-proxy` /
`dns-proxy-systemextension` entitlement), which can intercept all DNS traffic system-wide. It is the
*framework-blessed* way to guarantee no DNS leak — and it is the same entitlement-gated, native,
MDM-adjacent story. `UNVERIFIED` whether a Developer ID system extension DNS proxy is approved for
self-distributed apps; assume it is gated like the others.

**Which approach is actually viable for a self-distributed, non-App-Store Xray client?**

> **Raw `utun` + privileged helper.** It is the only option that (i) gives a true IP-level tunnel,
> (ii) covers TCP+UDP+ICMP and all apps, (iii) requires no Apple-gated entitlement, (iv) works with
> an unmodified Xray core, and (v) is fully reproducible by any contributor with a Developer ID
> certificate (or even, for local development, by running the helper from a terminal with `sudo`).
> The costs are: you must write and secure a root helper, and you must implement the kill switch /
> DNS / routing yourself. That is exactly the trade the mainstream third-party macOS VPN/firewall
> ecosystem already makes.

#### 1.2.4 Capability matrix

| Capability | Developer ID (self-distributed) | App Store | Managed/MDM |
| --- | --- | --- | --- |
| Raw utun via root helper | **Yes** (root required) | Yes in principle, but App Store sandbox/guideline friction | Yes |
| `NEPacketTunnelProvider` | **Yes**, with `*-systemextension` entitlement + Developer ID provisioning profile; native extension required | Yes (Network Extensions capability in Xcode) | Yes |
| Per-app VPN (`NEAppRule`) | **No** — see §1.4 | Requires managed config in practice | **Yes** |
| PF kill switch | **Yes** (root) | Yes (root helper needed → App Store friction) | Yes |
| System proxy | **Yes** (admin auth) | Limited (sandbox) | Yes |
| `NEFilterDataProvider` | Yes with `content-filter-provider-systemextension` entitlement, native, user-approved | Yes | Yes |

---

### 1.3 PF anchors and a fail-closed kill switch

**Primary sources:** `pfctl(8)`, macOS man page set —
<https://keith.github.io/xcode-man-pages/pfctl.8.html> (man page dated July 1, 2007, shipped through
macOS 12+; the utility's documented interface is stable); `pf.conf(5)` —
<https://keith.github.io/xcode-man-pages/pf.conf.5.html>; Apple XNU `bsd/net/pf_ioctl.c` and
`bsd/net/pf_if.c`; and Apple **TN3165** (below). Verbatim quotations are from those sources.

> ### ⚠️ Strategic warning first: Apple says PF is *not API*
>
> Apple Technote **TN3165, "Packet Filter is not API"** (first published 2024-02-27) states, verbatim:
>
> > *"macOS implements the BSD Packet Filter mechanism. This has two expected use cases: As an
> > implementation detail of various system services built-in to macOS; As an advanced feature for
> > users, site admins, and so on. **It is not considered API. Do not use Packet Filter in a software
> > product that you distribute to a wide audience.** If you're currently shipping software that
> > relies on Packet Filter, plan to migrate to Network Extension."*
> >
> > *"PF is not considered API because the PF rules you install might clash with those installed by:
> > The user; macOS system services, either now or in the future; Other third-party products."*
> >
> > *"In the meantime, test your existing product to ensure that it's compatible with various macOS
> > system services. Specifically, test with: Mac Virtual Display for visionOS devices; Xcode;
> > Internet Sharing; AirDrop; Other Continuity features."*
>
> Source: <https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api>
>
> **Consequence for MyVpn:** the PF kill switch is a **best-effort, explicitly-unsupported-by-Apple
> feature**. It is still the only way to get a fail-closed kill switch without the Network Extension
> entitlement, so it stays in the plan — but it must be (a) isolated behind `IKillSwitch` so it can be
> replaced, (b) tested against Internet Sharing / AirDrop / Continuity / Xcode device debugging as
> Apple instructs, (c) accompanied by user-facing documentation that it may conflict with other
> firewalls and system services, and (d) revisited if the project ever obtains the NE entitlement
> (where `NEPacketTunnelProvider`'s `includeAllNetworks` + `enforceRoutes` provide a supported kill
> switch — see §1.2.2). TN3165 also names the network-extension deployment technote
> **TN3134: Network Extension provider deployment** as the packaging reference.

**Headline conclusions:**

1. `pfctl` is still present and usable on modern macOS. PF is compiled into XNU (it is **not** a
   load-on-demand kext): `pfinit()` in `bsd/net/pf_ioctl.c` creates the character device with
   `devfs_make_node(makedev(maj, PFDEV_PF), DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0600, "pf")`, so
   `/dev/pf` exists from boot. (`ipfw` is gone — see §1.4.3.) PF is **not** auto-enabled at boot; the
   stock `/etc/pf.conf` says so explicitly (see item 2).
2. A kill switch implemented by **replacing the main PF ruleset** is the standard approach, and the
   man page contains an explicit warning that this is exactly what `-f` does:
   > `-f file` — *"Load the rules contained in file. This file may contain macros, tables, options,
   > and normalization, queueing, translation, and filtering rules. With the exception of macros and
   > tables, the statements must appear in that order. **Use of this option, could result in flushing
   > of rules present in the main ruleset added by the system at startup.** See /etc/pf.conf for
   > further details."*

   The stock `/etc/pf.conf` carries Apple's own header making the same point in stronger terms
   (reproduced in the wild, e.g.
   <https://apple.stackexchange.com/questions/451252/internet-connection-is-disabled-after-updating-the-pf-conf-file>;
   exact per-version wording `UNVERIFIED`):
   > *"This file contains the main ruleset, which gets automatically loaded at startup. **PF will not
   > be automatically enabled, however.** Instead, each component which utilizes PF is responsible for
   > enabling and disabling PF **via -E and -X** as documented in pfctl(8). That will ensure that PF is
   > disabled only when the last enable reference is released. **Care must be taken to ensure that the
   > main ruleset does not get flushed**, as the nested anchors rely on the anchor point defined here.
   > In addition, to the anchors loaded by this file, some system services would dynamically insert
   > anchors into the main ruleset."*

   That is Apple's `-E`/`-X` discipline stated by Apple, and Apple's own warning that flushing the
   main ruleset breaks the `com.apple/*` anchor point that system services insert into. Two safety
   rules dominate the design:
   - **Enable/disable only through the reference count.** The man page defines the contract exactly:
     > `-e` — *"Enable the packet filter."*
     > `-E` — *"Enable the packet filter and increment the pf enable reference count."*
     > `-X token` — *"Release the pf enable reference represented by the token passed."*
     > `-d` — *"Disable the packet filter."*

     So: call `pfctl -E`, **capture the token it prints**, and on shutdown call
     `pfctl -X <that token>` — nothing else. The man page documents the audit tool:
     > `-s References` — *"Show pf-enable reference statistics (pid/name of enabler, token,
     > timestamp)."*

     XNU confirms the mechanism and pins down the failure modes precisely
     (`bsd/net/pf_ioctl.c`, <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/pf_ioctl.c>):
     tokens are 64-bit, kernel-generated per enable, and carry `pid`/`proc_name`/`timestamp`;
     `DIOCSTARTREF` (`-E`) allocates a token and increments `pf_enabled_ref_count`;
     `DIOCSTOPREF` (`-X`) removes *that* token and decrements the count, stopping PF only when the
     count reaches zero; and **`DIOCSTOP` (`-d`) does `pf_stop(); pf_enabled_ref_count = 0;
     invalidate_all_tokens();`** — it unconditionally disables PF and destroys every other holder's
     token. A bare `-e` increments the count only when no token-holders exist, so its holder can never
     release its own reference selectively.

     **Design rules for MyVpn:**
     - `pfctl -d` is **forbidden** — it stomps the Application Firewall (which enables PF via `-E` and
       owns the `com.apple/250.ApplicationFirewall` anchor) and any other enabler.
     - `pfctl -e` is **forbidden** — take a reference with `-E` or you cannot release it.
     - `pfctl -X <token>` with **our own captured token** only.
     - Correcting a common belief: **`pfctl -X 0` does not disable PF.** `0` is never inserted into
       the token list, so `remove_token` finds no match and returns `EINVAL` — a harmless failure, not
       a global shutdown. It is still a bug to ship (`-X` with the wrong value is meaningless), but the
       real hazard is `-d`.
     - Divergence worth knowing: Mullvad's `pfctl-rs` crate drives `/dev/pf` directly with
       `DIOCSTART`/`DIOCSTOP` (bare `-e`/`-d`) and saves/restores the prior PF-enabled state rather
       than using tokens
       (<https://docs.rs/pfctl/0.7.0/src/pfctl/lib.rs.html>) — a valid alternative, but it inherits the
       `-d` global-stomp hazard if a second enabler appears. MyVpn should use tokens.
   - **Preserve Apple's anchor.** Because `-f` flushes the startup ruleset, our ruleset must
     re-establish Apple's own evaluation point. The safe pattern is to *include* the Apple anchor
     lines in the ruleset we load:
     ```
     scrub-anchor "com.apple/*"
     nat-anchor "com.apple/*"
     rdr-anchor "com.apple/*"
     dummynet-anchor "com.apple/*"
     anchor "com.apple/*"
     load anchor "com.apple" from "/etc/pf.anchors/com.apple"
     ```
     Anchors are documented in `pfctl(8)` as: *"In addition to the main ruleset, pfctl can load and
     manipulate additional rulesets by name, called anchors. The main ruleset is the default anchor.
     Anchors are referenced by name and may be nested, with the various components of the anchor
     path separated by '/' characters…"*, and *"By default, recursive inline printing of anchors
     applies only to unnamed anchors specified inline in the ruleset. If the anchor name is
     terminated with a '*' character, the `-s` flag will recursively print all anchors in a brace
     delimited block."*

     Omitting `anchor "com.apple/*"` breaks Apple features that rely on dynamically inserted anchors.
     The documented example is Internet Sharing: enabling it appends
     `scrub-anchor "com.apple.internet-sharing"` and `anchor "com.apple.internet-sharing"` to the main
     ruleset (<https://apple.stackexchange.com/questions/430415/source-of-pf-anchor-com-apple-internet-sharing-all>),
     which only works while the main ruleset survives.
     **`UNVERIFIED`**: that **Content Caching** uses PF at all — no evidence was found; the commonly
     repeated claim that it does should be treated as unsupported. Apple's TN3165 names Internet
     Sharing, AirDrop, Continuity, Xcode device debugging and Mac Virtual Display as the things to
     test against instead.

   **SIP status (corrected):** `/etc` is **not** in SIP's protected set. Apple's System Integrity
   Protection Guide lists the system-only locations as `/bin`, `/sbin`, `/usr`, `/System`
   (<https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/FileSystemProtections/FileSystemProtections.html>);
   `/etc` is a symlink to `/private/etc` and the *symlink* is protected while the target directory is
   not. So `/etc/pf.conf` and `/etc/pf.anchors/` are **writable by root on a SIP-enabled Mac**. That
   does not make editing them a good idea: Apple overwrites `/etc/pf.conf` on OS upgrades, and the
   `/etc/pf.conf` header itself tells you not to flush the main ruleset. **MyVpn must never write
   `/etc/pf.conf` or `/etc/pf.anchors/com.apple`; it must load its own rules via `-f -` / `-a … -f -`
   and treat Apple's files as read-only inputs.** (`/System/Library/LaunchDaemons/com.apple.pfctl.plist`
   *is* SIP-protected and requires Recovery Mode to change — do not attempt it.)

**`pfctl(8)` flags that matter for MyVpn (all quotes from the macOS man page):**

| Flag | Man-page text / use in MyVpn |
| --- | --- |
| `-E` | *"Enable the packet filter and increment the pf enable reference count."* Capture the printed token. |
| `-X token` | *"Release the pf enable reference represented by the token passed."* Release only our token. |
| `-e` | *"Enable the packet filter."* Do **not** use (no reference held → someone else's `-X` can drop PF under us, and vice versa). |
| `-d` | *"Disable the packet filter."* **Forbidden.** |
| `-n` | *"Do not actually load rules, just parse them."* Use as a pre-flight `pfctl -n -f -` dry run before the real load. |
| `-f file` | Load rules; flushes startup rules (warning above). Use `-f -` to read from stdin so no temp file is needed. |
| `-a anchor` | *"Apply flags `-f`, `-F`, and `-s` only to the rules in the specified anchor."* Anchor-scoped loads are how you avoid touching the main ruleset at all — but only if the main ruleset already evaluates your anchor, which the startup ruleset does not, which is why the full-replace approach above is used instead. |
| `-s rules` / `-s nat` / `-s Anchors` / `-s References` / `-s Tables` | Snapshot primitives for the restore journal. `-s Anchors` — *"Show the currently loaded anchors directly attached to the main ruleset."* |
| `-t <table> -T add\|replace\|flush\|show\|test\|kill` | Server-IP table maintenance without a full reload. *"`add` — Add one or more addresses in a table. Automatically create a nonexisting table."* Also *"`replace` — Replace the addresses of the table. Automatically create a nonexisting table."* and *"`-a foo/bar -t mytable -T add 1.2.3.4 5.6.7.8"* for anchor-private tables. |
| `-m` | *"Merge in explicitly given options without resetting those which are omitted."* |
| `-i interface` | *"Restrict the operation to the given interface."* |
| `-o none` | Disable the ruleset optimizer — recommended while developing a kill switch so the loaded rules match the source text 1:1. *"`none` Disable the ruleset optimizer."* (Default is `basic`.) |
3. **Interface names that do not exist yet are accepted, not rejected — but that is a safety trap.**
   XNU creates a `pfi_kif` entry for an unknown interface name at ruleset-load time
   (`pf_rule_setup()` → `pfi_kif_get()`), and the entry binds to the real interface when it later
   attaches; FreeBSD's pf maintainers confirm the behaviour is deliberate: *"the interface may not
   exist at the time the rule is loaded, but may come to exist later, and we still want the rule there,
   so it is 'ready' when the interface appears"*
   (<https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=287462>). **So `pfctl -n` will NOT tell you
   that your tunnel interface name is wrong.** Two consequences:
   - Do **not hardcode `utun0`.** macOS assigns utun numbers dynamically and another product
     (WireGuard, Tailscale, iCloud Private Relay) may already own `utun0`. A rule that says
     `pass on utun0` when your tunnel is `utun4` silently matches nothing, and your traffic is then
     caught by the final `block drop all` — **fail-closed but VPN-broken**, which is the safe
     direction but a silent misconfiguration. Resolve the real name at runtime (`UTUN_OPT_IFNAME`,
     §1.2.1) and template it into the ruleset; PF's `(interface)` parenthesised form and the `utun+`
     prefix wildcard are alternatives (`utun+` behaviour on macOS is **`UNVERIFIED`**).
   - Keep the "create the utun first" ordering anyway: it lets you learn the name, and it removes all
     ambiguity. Order: **create utun → set address/MTU → `pfctl -n -f -` (parse-only) → `pfctl -E`
     (capture token) → `pfctl -f -` → `pfctl -F states`**.
4. **Server address churn** should be handled with a PF **table** (`<myvpn_server>`) rather than a
   ruleset reload. `pfctl -t myvpn_server -T replace <ip>` (or `-T add`) updates it live, and
   *"`-T add`/`replace` automatically create a nonexisting table"*. Tables support `persist` and
   `const` attributes, and *"a table initialized with the empty list, `{ }`, will be cleared on
   load"* — so **do not declare `<myvpn_server> = { }` in the ruleset** or every reload wipes it; use
   an uninitialised table or `persist file "…"`. An anchor-private table is also possible
   (`pfctl -a foo/bar -t mytable -T add …`), and *"when a rule referring to a table is loaded in an
   anchor, the rule will use the private table if one is defined, and then fall back to the table
   defined in the main ruleset."*
5. **States outlive rules — flush them on every transition.** `pf.conf(5)`: *"By default packet
   filter filters packets statefully; the first time a packet matches a pass rule, a state entry is
   created; for subsequent packets the filter checks whether the packet matches any state. If it does,
   **the packet is passed without evaluation of any rules.**"* Installing a stricter ruleset therefore
   does **not** stop flows that already have state. Run `pfctl -F states` (or targeted
   `pfctl -k <host>`) immediately after arming or tightening the kill switch. Shipping clients do
   exactly this.

**Fail-closed kill-switch ruleset (design; to be validated on-device):**

```
# ---- myvpn kill switch (fail-closed) -------------------------------------
# NOTE: 'set' options are global to the MAIN ruleset. If you load this file into an
# anchor, `set skip on lo0` may be silently ignored — so loopback is passed explicitly
# below as well. Both forms are present deliberately.
set skip on lo0
set block-policy drop
set ruleset-optimization none      # keep loaded rules 1:1 with the source while developing

# Keep Apple's own anchors working (macOS specific) — required because -f replaces the main ruleset
scrub-anchor "com.apple/*"
nat-anchor   "com.apple/*"
rdr-anchor   "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"

# --- Loopback: explicit, in case `set skip` was ignored in an anchor context.
pass quick on lo0 all

# --- IPv6: no leaks. Drop everything v6 while the tunnel is v4-only.
#     (If you keep IPv6, you must also pass DHCPv6 and NDP 133-136 and must NOT block
#      ICMPv6 type 2 (Packet Too Big), or path-MTU discovery breaks.)
block drop quick inet6 all

# --- Bootstrap: the VPN transport must reach the server OUTSIDE the tunnel.
#     Server IPs live in a persistent table (do NOT initialise it with { }).
pass out quick proto udp from any to <myvpn_server> port 443
pass out quick proto tcp from any to <myvpn_server> port 443

# --- DHCPv4 bootstrap on the physical interface (ports 67/68)
pass out quick on en0 proto udp from any port 68 to any port 67
pass in  quick on en0 proto udp from any port 67 to any port 68

# --- DNS: only through the tunnel (prevents the packet-level DNS leak).
#     NB: this makes leaked queries FAIL rather than redirect them — see section 1.5 for the
#     resolver-configuration half of the fix, which is required for resolution to keep working.
pass out quick on utun0 proto { tcp, udp } from any to any port 53

# --- The tunnel itself.  Replace utun0 with the runtime-resolved name.
pass quick on utun0 all

# --- Everything else: dead. (fail closed).  'quick' is required: without it a later rule wins.
block drop quick all
```

Notes and traps:

- `set skip on lo0` bypasses PF entirely for loopback — `pf.conf(5)`: *"List interfaces for which
  packets should not be filtered. Packets passing in or out on such interfaces are passed as if pf was
  disabled, i.e. pf does not process them in any way."* **Caveat:** `set` options are global to the
  *main* ruleset, so if the ruleset is loaded into an **anchor**, a `set skip on lo0` inside it may be
  silently accepted and ignored (secondary source: a 2026 practitioner report of exactly this,
  <https://zenn.dev/i0/articles/c59917b9270925>; **`UNVERIFIED`** against Apple docs, but consistent
  with `pf.conf(5)`'s statement-order model). That is why the ruleset above also carries explicit
  `pass quick on lo0 all`. Belt and braces, and it costs nothing.
- **`quick` is load-bearing.** `pf.conf(5)`: *"If a packet matches a rule which has the quick option
  set, this rule is considered the last matching rule, and evaluation of subsequent rules is skipped."*
  Without `quick` on the terminal block, a later `pass` wins. Equally, note the default action:
  *"If no rule matches the packet, the default action is to pass the packet."* A fail-closed ruleset
  must therefore begin from a block and end with an explicit `block … quick all`.
- The DNS rule above is deliberately *permissive* toward `utun0` and *closed* elsewhere. It makes a
  leaked query **fail**; it does **not** redirect resolution, and it does **not** stop
  mDNSResponder from *choosing* a physical-interface resolver — see §1.5, which is required reading
  together with this rule.
- **Server IP changes**: keep `<myvpn_server>` updated from the app whenever it re-resolves the
  server hostname, using `-T replace` (which, unlike a ruleset reload, does not flush states).
- **IPv6, if you choose to carry it:** a fail-closed IPv6 policy must also pass DHCPv6 and IPv6
  neighbour discovery (router solicitation/advertisement, neighbour solicitation/advertisement,
  ICMPv6 types 133–136) or the link becomes unusable, and must **not** block ICMPv6 type 2
  (Packet Too Big) or path-MTU discovery breaks. If MyVpn is IPv4-only, the single
  `block drop quick inet6 all` above is the safer choice.
- **Restore path**: on clean shutdown, restore the ruleset and then release the reference:
  `pfctl -f /etc/pf.conf` (the documented restoration path — the man page's own pointer is *"See
  /etc/pf.conf for further details"*) followed by `pfctl -X <token>`; verify with
  `pfctl -s References` that our pid/token is gone and with `pfctl -s rules` that the expected ruleset
  is loaded. Capture `pfctl -s rules`, `-s nat`, `-s Anchors`, `-s Tables` and `-s References`
  **before** arming, into the journal. **`UNVERIFIED`**: whether a snapshot taken with `pfctl -sr`
  can be fed back verbatim into `pfctl -f -` (the optimizer and macro/table handling can make
  round-tripping lossy), and whether reloading `/etc/pf.conf` disrupts a system service that had
  dynamically inserted anchors. Note the man page's own warning that `-f` *"could result in flushing
  of rules present in the main ruleset added by the system at startup."* This is a must-test area.
- **Consider the anchor alternative, but understand its fail-open risk.** Loading into an anchor
  (`pfctl -a com.example.myvpn -f -`, or under Apple's wildcard namespace as
  `com.apple/<name>` so that the stock `anchor "com.apple/*"` attachment point evaluates it) avoids
  replacing the main ruleset and therefore avoids the restore problem entirely — and it is what some
  shipping products and at least one project migration chose for exactly that reason. **But** an
  anchor is only evaluated if the *currently loaded main ruleset* attaches it. If another product has
  replaced the main ruleset, or if the OS changes the attachment points, your kill switch silently
  stops applying — a **fail-open** outcome, which is unacceptable for a security feature. If you take
  the anchor route you must (a) verify attachment as well as loading, not just that your rules are
  present, and (b) live-monitor for main-ruleset replacement. The main-ruleset-replacement design
  above is chosen because its state is directly verifiable with `pfctl -sr` and it fails closed.
  **`UNVERIFIED`**: whether `com.apple/<name>` anchor evaluation is guaranteed on all in-scope macOS
  versions.
- **PF alone is not the whole kill switch.** PF filters packets; it does not stop the resolver from
  *choosing* a physical-interface resolver (see §1.5), and it does not stop an app from using a proxy
  or a non-IP transport. The kill switch is one layer of a defence that also includes correct routes
  and correct DNS scoping.
- **Boot-time and upgrade-time state.** PF's enable reference count and loaded ruleset are not
  persisted by MyVpn across a reboot, but they *are* reset by the OS to Apple's startup state. The
  helper must therefore treat "PF is enabled with a token we do not know" as a normal condition to
  detect (`pfctl -s References`) rather than as a state it owns.
- **Crash safety**: PF state survives the helper's death — that is the *point* of fail-closed, but it
  also means a crashed helper leaves the machine without network (except the tunnel, which is also
  gone). The mitigation is *not* to make the kill switch self-disabling; it is to (a) use launchd
  `KeepAlive` to restart the helper, and (b) have the helper unconditionally restore the previous
  PF state, routes, DNS and proxies from an on-disk journal at daemon start, before doing anything
  else.
- **Test against Apple's services.** Per TN3165: Internet Sharing, AirDrop, Continuity,
  Xcode device debugging (network and USB), Mac Virtual Display, and other third-party VPNs/firewalls.

---

### 1.4 Per-process routing — the hard question

This is the section where honesty matters most. Here is the precise state of the platform.

#### 1.4.1 PF `user` / `group` match rules, and PF's `route-to` (the honest, nuanced answer)

This subsection is the one most likely to be got wrong, so it is written conservatively and cites
`pf.conf(5)` verbatim (macOS man page set: <https://keith.github.io/xcode-man-pages/pf.conf.5.html>).

**(i) `user`/`group` are match criteria, with documented limits.** `pf.conf(5)` says:

> `group ⟨group⟩` — *"Similar to user, this rule only applies to packets of sockets owned by the
> specified group."*
> `user ⟨user⟩` — *"This rule only applies to packets of sockets owned by the specified user. For
> outgoing connections initiated from the firewall, this is the user that opened the connection. For
> incoming connections to the firewall itself, this is the user that listens on the destination port.
> **For forwarded connections, where the firewall is not a connection endpoint, the user and group
> are unknown.** All packets, both outgoing and incoming, of one connection are associated with the
> same user and group. **Only TCP and UDP packets can be associated with users; for other protocols
> these parameters are ignored.** User and group refer to the **effective** (as opposed to the real)
> IDs, in case the socket is created by a setuid/setgid process. **User and group IDs are stored when
> a socket is created**; when a process creates a listening socket as root (for instance, by binding
> to a privileged port) and subsequently changes to another user ID (to drop privileges), the
> credentials will remain root."*

Consequences for MyVpn:

- Matching is **TCP/UDP only**; ICMP and other protocols are not attributable to a user.
- The credential is **frozen at socket creation** and is the *effective* ID at that moment — so a
  process that starts as root and drops privileges carries root credentials in its PF attribution.
- **Forwarded** traffic (i.e. `net.inet.ip.forwarding`) has *unknown* user/group. This matters if
  MyVpn ever routes for a VM or a local network.
- You **can** write `block out quick proto { tcp, udp } user 501` or scope a `pass` to a user/group.

**(ii) PF filter actions do not route — but PF *does* have routing options, and this must not be
glossed over.** `pf.conf(5)` documents a `ROUTING` section:

> `fastroute` — *"does a normal route lookup to find the next hop for the packet."*
> `route-to` — *"routes the packet to the specified interface with an optional address for the next
> hop. When a route-to rule creates state, only packets that pass in the same direction as the filter
> rule specifies will be routed in this way. **Packets passing in the opposite direction (replies) are
> not affected and are routed normally.**"*
> `reply-to` — *"similar to route-to, but routes packets that pass in the opposite direction (replies)
> to the specified interface. Opposite direction is only defined in the context of a state entry, and
> reply-to is useful only in rules that create state."*
> `dup-to` — *"creates a duplicate of the packet and routes it like route-to."*

and, separately, a per-rule routing-table selector:

> `rtable ⟨number⟩` — *"Used to select an alternate routing table for the routing lookup. **Only
> effective before the route lookup happened, i.e. when filtering inbound.**"*

**So the precise statement is not "PF cannot route". It is:** PF *can* rewrite the next hop for a
matching flow, and `user`/`group` can be part of the match. A construct such as

```
pass out quick proto { tcp, udp } user 501 route-to (utun0 <tunnel-peer-address>)
```

is *syntactically* expressible and is the closest thing macOS offers to a per-process route. **It is
also not something this project should promise, for five concrete reasons:**

1. **Reply asymmetry is documented behaviour, not a bug you can work around locally.** `route-to`
   affects one direction only (the man page says so explicitly), so you would additionally need
   `reply-to` rules to make stateful TCP work, and the interaction of two directional route rewrites
   with PF state on a point-to-point userspace tunnel is unproven here.
2. **A next hop must be supplied** for the redirected flow. A utun is point-to-point; whether
   `route-to (utun0 <peer>)` produces a usable route for a tunnel whose peer address is synthetic and
   whose "link layer" is a userspace fd is **`UNVERIFIED`** and must be prototyped before it appears
   in any design document.
3. **It is TCP/UDP-only and credential-at-socket-creation** (see (i)) — so it silently fails to
   cover ICMP, and silently mis-attributes setuid/drop-privileges processes.
4. **`route-to` in shipping code exists — but not `user`-scoped, and for a different purpose.**
   Mullvad's macOS firewall builds a real `pass out quick route-to <utunN>` rule, but as a
   workaround for a specific macOS 14.6–15.1 regression, not as a per-process routing mechanism
   (<https://github.com/mullvad/mullvadvpn-app/blob/a2583edcb7c275064c20f6d02db291f36af82d94/talpid-core/src/firewall/macos.rs>).
   It is also documented that `route-to` **does not rewrite the source address**, so a packet
   originally destined for another interface may not get replies back at all (practitioner source:
   <https://amikewilson.com/2023/09/11/notes-on-pfctl>, `UNVERIFIED`). **No evidence was found of any
   shipping macOS client using `user`-scoped `route-to` as its split-tunnel mechanism.**
5. **`rtable` does not help.** Per the man page it is *only* effective inbound, so it cannot be used
   to steer a local application's *outbound* traffic.

**Documented recommendation for the product:** treat per-process routing as **unavailable**, and
treat `user`-scoped `route-to` as a **research spike** (Phase 0 of the implementation plan) whose
default outcome is "rejected as unreliable". If the spike ever succeeds, it ships behind an explicit
experimental flag with the TCP/UDP-only and freezes-credentials limitations in the UI. The project
must not advertise per-process routing on the strength of the `route-to` grammar alone.

**(iii) What PF *reliably* gives you per process.** A **block-list by UID/GID**:

```
block drop quick out proto { tcp, udp } user 501    # this UID gets no direct network
```

With the global default route already inside the tunnel, this rule means "UID 501 may not reach the
network at all (neither through the tunnel, if your tunnel passes carry `user`-agnostic rules first,
nor around it)". That is an **exclusion** control and it is genuinely useful, but it is not
"route app X through the VPN".

#### 1.4.2 `IP_BOUND_IF` — a per-socket option chosen by the socket's owner

`IP_BOUND_IF` is `25` in XNU's public `<netinet/in.h>`:
`#define IP_BOUND_IF 25 /* int; set/get bound interface */`.
Source: <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/netinet/in.h>

Kernel handling is in `inp_bindif()`/`inp_bindif_common()`/`inp_bindtodevice()` in
`bsd/netinet/in_pcb.c`:
<https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/netinet/in_pcb.c>
The implementation:
- looks up the interface by index (`ifindex2ifnet[ifscope]`, returning `ENXIO` for a bad index),
- sets `inp->inp_boundifp` and the `INP_BOUND_IF` flag,
- **performs no privilege check** — any process may bind its own socket to an interface.

Consequences:
- `IP_BOUND_IF` is how a VPN client **keeps its own transport socket out of the tunnel** (bind the
  Xray client socket to the physical interface, avoiding the routing loop). That is its genuinely
  valuable use for MyVpn.
- It is **not** a per-process routing mechanism. It affects only sockets the *calling process* owns.
  No third-party client can reach into another app and set `IP_BOUND_IF` on its sockets.
- The header documents an interaction worth knowing: *"if `IP_BOUND_IF` is set on the socket,
  `ipi_ifindex` in the ancillary `IP_PKTINFO` option silently overrides the bound interface when it
  is specified during send time."* (same `in.h`).

`IP_BOUND_IF` is not documented in macOS `ip(4)` — the man page lists the historical IP options and
stops at `IP_HDRINCL`-era options. **`UNVERIFIED`**: whether Apple documents `IP_BOUND_IF` anywhere
formal. The header definition and the XNU implementation above are the authoritative artifacts.

#### 1.4.3 `ipfw` — deprecated since OS X 10.11 El Capitan, and gone

`ipfw` was the BSD firewall that *did* have the primitives people remember for this job (`uid`/`gid`
rules, `fwd` to a local port, and `setfib` policy routing on FreeBSD). On macOS:

- Apple deprecated `natd` and `ipfw` in **OS X 10.11 (El Capitan)** — the widely-cited record of
  this is the Ask Different discussion "Deprecated 'natd' and 'ipfw' in El Capitan"
  (<https://apple.stackexchange.com/questions/219261>) — secondary source.
- The **kernel implementation is no longer in the current XNU tree**:
  `https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/netinet/ip_fw2.c`
  returns **HTTP 404** (the historical ipfw file). Likewise the ipfw man page is not in the current
  macOS/Xcode man page set (`https://keith.github.io/xcode-man-pages/ipfw.8.html` → 404).
- **`UNVERIFIED`**: the exact macOS release in which the `ipfw` *binary* disappeared. What is
  verified is that it is deprecated from 10.11 onward and its kernel implementation is absent from
  current XNU. **Conclusion: do not design anything on `ipfw`.** Also note `ipfw`'s per-UID
  routing never existed on macOS the way FreeBSD's `setfib` did, so even a time machine would not
  give you true per-process routing.

#### 1.4.4 Network Extension per-app VPN (`NEAppRule`) — `[MANAGED]` in practice

Apple's API surface for per-app VPN is real:

- `NEAppRule` (macOS 10.11+): *"The identity of an app whose traffic is to be routed through the
  tunnel."* Constructors `init(signingIdentifier:)` and
  `init(signingIdentifier:designatedRequirement:)`; read properties `matchSigningIdentifier`,
  `matchDesignatedRequirement`, `matchPath`, `matchDomains`, `matchTools`.
  Source: <https://developer.apple.com/documentation/networkextension/neapprule>
- `NETunnelProvider.appRules`: *"The app rules dictating which apps use the current tunneling
  session."* — declared **read-only** (`@property (readonly, nullable) NSArray<NEAppRule *> *appRules;`)
  and the Discussion says: *"This property is only non-`nil` if the current configuration is a
  Per-App VPN configuration."*
  Source: <https://developer.apple.com/documentation/networkextension/netunnelprovider/apprules>
- `NETunnelProviderRoutingMethod` has cases `destinationIP` (*"Route network traffic to the tunnel
  based on destination IP"*), `sourceApplication` (*"Route network traffic to the tunnel based on
  source application"*) and `networkRule`.
  Source: <https://developer.apple.com/documentation/networkextension/netunnelproviderroutingmethod>
  `NETunnelProviderManager.routingMethod` is the corresponding *read* accessor on the manager
  (*"The method that the system uses to route network traffic to the tunnel."*).

**The decisive fact for a self-distributed client:** the provider can **observe** that it is a
per-app VPN (`appRules` is non-nil) but the public API exposes **no setter** — `appRules` is
read-only and there is no public `NEAppRule`-setting API on `NETunnelProviderManager`. Per-app VPN
configurations are installed as **VPN payloads with per-app rules in a configuration profile**, i.e.
by MDM (or by the user double-clicking a `.mobileconfig`). Apple's own deployment documentation
frames per-app VPN as a profile feature.

Therefore: **`[MANAGED]`.** A Developer ID app cannot programmatically install a per-app VPN
configuration that routes another application's traffic. `UNVERIFIED`: whether a profile manually
installed by the user (not MDM) on an unmanaged Mac is accepted for per-app VPN on current macOS;
assume it requires a profile at minimum.

#### 1.4.5 `NEFilterDataProvider` — a filter, not a router

- Platform: macOS 10.15+, iOS 9+. Source:
  <https://developer.apple.com/documentation/networkextension/nefilterdataprovider>
- Its decision surface is allow/deny/delay: `handleNewFlow(_:)`,
  `handleInboundData(...)`, `handleOutboundData(...)`, `handleInboundDataComplete(for:)`,
  `handleOutboundDataComplete(for:)`, `handleRemediation(for:)`, `handleRulesChanged()`,
  `resumeFlow(_:with:)`, `update(_:using:for:)`. Verdicts are
  `NEFilterNewFlowVerdict` / `NEFilterDataVerdict` / `NEFilterRemediationVerdict` — **pass or
  block**. The class's own documentation says: *"The Filter Data Provider can choose to pass or
  block the data when it receives a new flow, or it can ask the system to see more of the flow's data
  in either the outbound or inbound direction before making a pass or block decision."*
- **There is no documented "redirect this flow to a userspace socket/proxy/tunnel" verdict.** The
  only "redirect-like" documented behaviour is confined to WebKit-originated flows and is a UI
  behaviour (a block page, or appending a string to the URL), not a packet redirect.
- *"To protect the user's privacy, the Filter Data Provider extension sandbox prevents the extension
  from moving network content outside of its address space."* — i.e. the framework explicitly
  prevents the extension from being used as a data-path relay.
- It requires the `content-filter-provider` entitlement (App Store) or
  `content-filter-provider-systemextension` (Developer ID), per the entitlement page, and the class
  doc says *"To use the `handleNewFlow(_:)` method, you must enable the Network Extensions capability
  in Xcode and select the Content Filter capability."*

So `NEFilterDataProvider` gives you **visibility of the source app per flow** and a **block**
decision — nothing more. It cannot route a per-app flow into Xray. It is not an answer to
per-process routing.

#### 1.4.6 The one genuinely low-level hook that exists, and why it is not usable

XNU's utun driver can stamp each outbound packet with the originating application's UUID:
`UTUN_FLAGS_ENABLE_PROC_UUID 0x0004`, and in `utun_framer()` /
`utun_netif_sync_tx()` the driver calls `necp_get_app_uuid_from_packet(...)` to fill in the UUID
header (the same path the kernel uses to satisfy per-app policy). See
`bsd/net/if_utun.c` and `bsd/net/if_utun.h` (sources cited in §1.2.1). Reading that header gives a
userspace TUN implementation **per-packet application attribution**.

Why this is not a viable product feature:

- The UUID is supplied by **NECP** (Network Extension Control Policy) classification, which is the
  kernel-internal policy engine that NetworkExtension drives. An ordinary third-party helper does
  not establish NECP app policies; there is no public API to do so.
- Mapping a UUID back to a PID/UID/bundle id requires `proc_uuid_policy`/`necp` interfaces that are
  not part of the public SDK (`<sys/proc_uuid_policy.h>` is a private header; `necp.h` is a private
  header).
- Setting `UTUN_OPT_FLAGS` with `UTUN_FLAGS_ENABLE_PROC_UUID` requires root (it is in the
  `kauth_cred_issuser` gate), so a root helper *could* set it — but with no public way to make the
  kernel populate meaningful UUIDs for arbitrary apps, you would get empty/zero UUIDs for most
  traffic.

`UNVERIFIED` in its specifics (I did not read `necp.h` or `proc_uuid_policy.h`), but the conclusion
is safe: **this is Apple-internal plumbing, not a supported third-party per-process routing API.**
It is documented here so that nobody on the team "discovers" it later and mistakes it for a
solution.

#### 1.4.7 Documented recommendation (platform-specific, no over-promising)

**Question:** is real per-process routing achievable for a self-distributed client on macOS?

**Answer: No. Not reliably, not with public APIs, and not without a managed configuration profile.**

What *is* achievable, stated precisely:

| Capability | Achievable for `[DEV-ID]`? | Mechanism | Honest limitation |
| --- | --- | --- | --- |
| Route *all* traffic through the tunnel | Yes | default route → utun (or NE `includeAllNetworks`) | all-or-nothing |
| Exclude specific destinations (split-tunnel by IP/CIDR) | Yes | PF `pass`/routes for the excluded ranges before the utun route; utun `includedRoutes`/`excludedRoutes` in NE | by **destination**, not by process |
| Exclude specific **UIDs/GIDs** from the network while the tunnel is up | Yes | PF `block ... user <uid>` on the physical interfaces / `block ... user` + tunnel passes | it's a **block-list**; the UID's traffic does not go through the tunnel, it goes nowhere (or direct, if you deliberately pass it direct) |
| Force *only* specific apps through the tunnel | **No** | — | needs NE per-app VPN `[MANAGED]`. A `user`-scoped PF `route-to` is *syntactically* possible (§1.4.1) but is directional-only, does not rewrite source addresses, is TCP/UDP-only, misses ICMP, and is unproven — treat as a spike whose expected outcome is rejection |
| Per-app proxying without TUN | Partially | app-specific proxy settings (PAC/system proxy/Firefox `user.js`/etc.) | apps that ignore system proxy (Firefox default, many Electron/Java apps) are unaffected; UDP/QUIC uncovered |
| Transparent per-flow interception into Xray | **No** | — | `NEFilterDataProvider` cannot relay (it is explicitly sandboxed against moving content out of its address space); PF `rdr` is TCP-only, requires `DIOCNATLOOK` to recover the original destination, and breaks QUIC; `NETransparentProxyProvider` is `[DEV-ID]`-possible but is network-rule-scoped, ignores `NEDNSSettings`/`NEProxySettings`, and fails open |

**Recommended product posture:**

1. Ship global tunnel + kill switch as the primary mode.
2. Ship **destination-based split tunnelling** (CIDR exclusion) as the "split tunnel" feature, and
   label it as such in the UI. Do not call it "per-app".
3. If a UID-based exclusion is offered, present it as **"Block these users from the network"**
   (a PF `user` rule), with a visible warning that the exclusion is a block, not a route, and that
   it applies to all of that UID's traffic. This is genuinely useful (e.g. block a service account)
   and it is honest.
4. Optionally offer "**Proxy mode**" (local HTTP/SOCKS + system proxy / PAC) for users who need
   selective coverage without root; document which apps honour the system proxy and which do not.
5. Document, in user-facing copy, that **true per-app tunnelling requires a managed (MDM) macOS
   profile with a per-app VPN payload** and is out of scope for a self-distributed client.
6. **Prove it in code, not just in docs.** `IProcessRouter` exposes
   `SupportsIncludeByProcess => false` and the UI branches on it; the integration suite includes a
   test that attempts per-process routing through every public mechanism (including `user`-scoped
   `route-to`) and asserts the documented limitation. If a future macOS release changes this, the
   failing test is the signal to re-evaluate — not a quiet behaviour change in the field.

---

### 1.5 DNS

**Primary sources:** `resolver(5)`, macOS man page set —
<https://keith.github.io/xcode-man-pages/resolver.5.html> (man page dated November 23, 2022, "Mac
OS X 14"); Apple's *System Configuration Programming Guidelines → The System Configuration Schema*;
and Apple's open-source `configd` (`Plugins/IPMonitor/dns-configuration.c`, `dnsinfo/dnsinfo.h`,
`dnsinfo/dnsinfo_logging.h`, `scutil.tproj/commands.c`, `SystemConfiguration.fproj/SCSchemaDefinitions.h`).
Verbatim quotes are from those sources.

**What has to be true for MyVpn:**

1. `scutil --dns` is the read-only ground truth for what the resolver stack believes. Apple's
   `dnsinfo_logging.h` emits, per resolver: `domain`, `search domain[i]`, `nameserver[i]`,
   `sortaddr[i]`, `options`, `port`, `timeout`, **`if_index`**, `service_identifier`, `flags`
   (including the tokens **`Scoped`**, `Service-specific`, `Supplemental`), `reach`, and `order`; and
   it prints up to three sections — `DNS configuration`, `DNS configuration (for scoped queries)`,
   and `DNS configuration (for service-specific queries)`. The machine-readable equivalent is Apple's
   `dnsinfo.h` `dns_resolver_t` / `dns_config_t` (with flag values `SCOPED 0x1000`,
   `SERVICE_SPECIFIC 0x2000`, `SUPPLEMENTAL 0x4000`). **Every DNS test must assert against
   `scutil --dns`, not against `networksetup -getdnsservers` alone.**
2. **The dynamic-store key layout** (Apple's schema doc): `Setup:/Network/Service/<ServiceID>/DNS`
   and `State:/Network/Service/<ServiceID>/DNS` (`DomainName`, `ServerAddresses`, `SearchDomains`,
   `SortList`); `State:/Network/Service/<ServiceID>/IPv4` (`Addresses`, `SubnetMasks`, `Router`,
   `InterfaceName`); `Setup:/Network/Global/IPv4` (`ServiceOrder`); `State:/Network/Global/IPv4`
   (`PrimaryService` — *"Identifies which network service is deemed primary"* — `PrimaryInterface`,
   `Router`); `State:/Network/Global/DNS` (*"favouring a property from the `Setup:` key over one from
   the `State:` key"*); `State:/Network/Global/Proxies`.
   The `scutil` command grammar is fixed by Apple's `scutil.tproj/commands.c`:
   `d.init`, `d.add key [*#?%] val [v2 …]` (`*`=array, `#`=number, `?`=boolean, `%`=hex data),
   `d.remove`, `d.show`; `get`/`set`/`add`/`remove`/`show`/`list <pattern>` against the store;
   `snapshot`. Hence `d.add ServerAddresses * 10.0.0.1` — the sigil is required for array values.
3. **Writing `State:/Network/Service/<arbitrary-id>/DNS` *does* work, but only if the dictionary is
   shaped so the DNS configuration agent will use it.** The agent enumerates services with a
   **wildcard regex** (`kSCCompAnyRegex`) and reads `State:/Network/Global/IPv4` only for
   `PrimaryService` — it does **not** require a matching `Setup:` entry. This is exactly what shipping
   VPN clients do: OpenVPN writes `State:/Network/Service/openvpn-${dev}/DNS`, vpnc-script writes
   `State:/Network/Service/$TUNDEV/DNS` **and** `…/IPv4` with `InterfaceName $TUNDEV`, and Tunnelblick
   writes both keys for `openvpn-${dev}`.
   **The condition that matters:** in Apple's `dns-configuration.c`, `add_supplemental()` only builds
   a supplemental resolver when the dictionary carries a non-empty **`SupplementalMatchDomains`**
   *and* a non-empty `ServerAddresses`; `add_scoped_resolvers()` builds a scoped resolver from a
   dictionary carrying **`InterfaceName`**; and the *default* resolver comes from the **primary
   service's** DNS. `SupplementalMatchDomainsNoSearch` (`# 1`) controls whether those domains are
   also added to the search list.
   **Therefore:** a bare `State:/Network/Service/<id>/DNS` containing only `ServerAddresses` and
   nothing else, on a non-primary service, is **probably never consulted** — this is a strong
   inference from the source, marked **`UNVERIFIED`** as a verbatim Apple statement. MyVpn must do one
   of: (a) add `SupplementalMatchDomains` (split DNS), (b) publish a sibling `IPv4`/`IPv6` dict with
   `InterfaceName` (scoped resolver for the tunnel), or (c) make the tunnel service primary.
4. **`networksetup` operates on *network services*, not BSD interfaces.** `networksetup(8)`:
   `-getdnsservers <networkservice>`, `-setdnsservers <networkservice> dns1 [dns2 …]` — *"If you want
   to clear all DNS entries for the specified network service, type 'empty' in place of the DNS server
   names."* (note lowercase `empty` for DNS/search; `-setproxybypassdomains` documents `Empty`),
   `-getsearchdomains`/`-setsearchdomains`, `-listallnetworkservices`, `-listnetworkserviceorder`.
   `networksetup` writes persistent SystemConfiguration preferences and *"requires at least admin
   privileges to change network settings."*
   **`UNVERIFIED`**: the exact sentence `-getdnsservers` prints when nothing is configured (clients
   detect it by testing for a space, e.g. WireGuard's `wg-quick`), and the accepted syntax for a
   link-local IPv6 nameserver (which needs a scope/zone id on a multi-interface host). Test both.
5. **`/etc/resolver/<domain>` is the documented split-DNS mechanism.** `resolver(5)` lists
   `/etc/resolv.conf` and *"the files found in the /etc/resolver directory"* as the file-based client
   configurations and documents the format:
   - `nameserver` — *"IPv4 or IPv6 address of a name server that the resolver should query. The
     address may optionally have a trailing dot followed by a port number. For example,
     `10.0.0.17.55` specifies that the nameserver at 10.0.0.17 uses port 55. Up to `MAXNS` (currently
     3) name servers may be listed, one per keyword."*
   - `port` — default 53 (overridable per nameserver via the trailing-dot form above).
   - `domain` — *"normally not required by the macOS DNS search system when the resolver
     configuration is read from a file in the /etc/resolver directory. In that case **the file name
     is used as the domain name**. However, domain must be provided when there are multiple resolver
     clients for the same domain name."*
   - `search` — *"only used by the "Super" DNS resolver"*; limited to *"six domains with a total of
     256 characters."*
   - `search_order` when several clients share a domain; plus `sortlist`, `timeout`, and `options`
     (`debug`, `usevc`, `ndots:n`, `timeout:n`, `attempts:n`, `no_tld_query`, `reload-period:n`).

   So MyVpn's split-DNS feature is **one root-owned file per domain under `/etc/resolver/`** with
   `nameserver <vpn-dns-ip>`. This is documented and stable. **`UNVERIFIED`**: the tie-break between
   an `/etc/resolver/<domain>` file and a dynamic-store `SupplementalMatchDomains` resolver for the
   *same* domain (`resolver(5)` only defines `search_order` ordering among clients), and whether a
   2025–26 report that macOS 26 ignores `/etc/resolver` for non-standard TLDs is accurate.
6. **Resolver selection is a best-domain-match, not first-nameserver-wins.** `resolver(5)` describes
   a *"Super" DNS client* that *"acts as a router for DNS queries"* and chooses among clients *"by
   finding a best match between the domain name given in a query and the names of all known
   clients"* — *"the client with the maximum number of matching domain components"* — falling back to
   the default client, *"generally corresponding to the /etc/resolv.conf file or to the "primary" DNS
   configuration on the system"*. This explains precisely why a tunnel interface's resolvers do **not**
   automatically win for ordinary names: only a matching `/etc/resolver/` domain entry (or a changed
   primary-service DNS) redirects the Super client to them.
7. **Why the leak happens — the definitive mechanism: mDNSResponder binds its DNS sockets to a
   specific interface with `IP_BOUND_IF`.** Apple's `mDNSResponder` source (`mDNSMacOSX/mDNSMacOSX.c`)
   does:
   ```c
   #ifdef IP_BOUND_IF
       const mDNSu32 ifindex = info ? info->scope_id : IFSCOPE_NONE;
       setsockopt(s, IPPROTO_IP, IP_BOUND_IF, &ifindex, sizeof(ifindex));
   #endif
   ```
   So **a route change does not move an interface-scoped resolver onto the tunnel** — the resolver's
   query is bound to its own interface by design. Combined with item 6 (the Super client uses the
   **primary service's** resolvers for unmatched names), this is the complete explanation of the
   classic macOS "VPN DNS leak": Wi-Fi stays primary, so the default resolver is still the ISP/LAN
   resolver, and mDNSResponder still sends those queries out `en0` no matter where the default route
   points.
   The **fix** therefore needs both halves:
   - packet level: block UDP/TCP 53 outside the tunnel (§1.3) — this prevents the leak but leaves
     resolution **broken**, not redirected;
   - configuration level: make the resolvers the Super client *selects* reachable inside the tunnel.
     The two documented mechanisms are:
     - **make the tunnel service primary** — the state-level form is `OverridePrimary # 1` in the
       tunnel service's `State:/Network/Service/<id>/IPv4` dictionary (as vpnc-script does); the
       SystemConfiguration form is `SCNetworkServiceSetPrimaryRank(service,
       kSCNetworkServicePrimaryRankFirst)` (*"Allows a service to sort ahead of other services. Used by
       connection-oriented services like VPN"*), which lives in
       `SCNetworkConfigurationPrivate.h` — **`UNVERIFIED` as public API, do not ship it**;
     - **publish split/supplemental resolvers** — `/etc/resolver/<domain>` files and/or
       `SupplementalMatchDomains` (+`SupplementalMatchDomainsNoSearch # 1`) on the tunnel service's
       DNS dict.
   This must be tested with an observation resolver that logs the interface on which queries egress.
   **Additional packet-filter interaction:** because `getaddrinfo` goes through mDNSResponder, DNS
   traffic is attributed to the `_mdnsresponder` user, not the calling process — so UID-based PF rules
   will not classify DNS the way an application-level view suggests (practitioner source:
   <https://amikewilson.com/2023/09/11/notes-on-pfctl>, `UNVERIFIED`). This also means **PF
   `user`/`group` rules cannot be used to make per-application DNS policy** (§1.4.1).
8. **Cache flushing.** `dscacheutil(1)` documents `-flushcache` as *"Flushes the entire cache. **This
   should only be used in extreme cases.**"* and describes the tool as operating on the Directory
   Service cache; the DNS responder is signalled with `killall -HUP mDNSResponder`. Shipping clients
   run both (Tunnelblick runs `dscacheutil -flushcache` then `killall -HUP mDNSResponder` on up and
   down; OpenVPN's macOS DNS script runs `dscacheutil -flushcache`). Apple's user-facing article is
   *"Reset the DNS cache"* (<https://support.apple.com/en-us/101481>); its body could not be fetched,
   so the current wording and the deprecation status of either command are **`UNVERIFIED`**.
   `resolver(5)` also documents that the resolver re-checks `/etc/resolv.conf` every `reload-period`
   seconds (default 2). Flush after every resolver change and after tunnel bring-up.
9. **Restore — and prefer an on-disk journal to the dynamic store.** Shipping clients snapshot into
   the dynamic store itself: Tunnelblick stores the pre-VPN state under
   `State:/Network/OpenVPN/OldDNS` / `Setup:/Network/OpenVPN/OldDNSSetup` (using a sentinel key to
   record "no such key"), OpenVPN copies the primary service's DNS into
   `State:/Network/Service/openvpn-<dev>/DnsBackup` and restores **only if the current
   `ServerAddresses` still match what it installed**, and WireGuard's `wg-quick` snapshots
   `-getdnsservers`/`-getsearchdomains` per service into arrays. **Snapshot before changing anything:**
   the `scutil --dns` text, the per-service DNS values for **all** services, and the exact set of files
   MyVpn creates under `/etc/resolver/`. Restore on teardown *and* at helper start after a crash. A
   client that crashes leaving DNS pointed at a dead `utun` address is the classic bricked-network
   failure; the helper's start-up recovery must fix
   routes, DNS, PF and proxies before doing anything else.

---

### 1.6 Routing

**Primary sources:** `route(8)` — <https://keith.github.io/xcode-man-pages/route.8.html>;
`route(4)` (the PF_ROUTE/routing-socket interface) —
<https://keith.github.io/xcode-man-pages/route.4.html>; `netstat(1)`;
`launchd.plist(5)`; XNU `bsd/net/if.c` (`if_rtdel`); and the OpenVPN and WireGuard implementations
cited inline. Verbatim quotes are from those sources.

1. **Modification requires root; reading does not.** *"route uses a routing socket and the new
   message types `RTM_ADD`, `RTM_DELETE`, `RTM_GET`, and `RTM_CHANGE`. As such, **only the super-user
   may modify the routing tables**."* This is why route management belongs in the privileged helper.
   The commands are `add`, `flush`, `delete`, `change`, `get`, `monitor`.

2. **Reading routes.** Human tools: `route -n get default`, `netstat -rn -f inet` / `-f inet6`.
   Programmatic: a **`PF_ROUTE` socket** — `socket(PF_ROUTE, SOCK_RAW, family)` with the `RTM_*`
   message types; `route(4)` documents the exact structures:
   > `#define RTM_ADD 0x1`, `RTM_DELETE 0x2`, `RTM_CHANGE 0x3`, `RTM_GET 0x4`, `RTM_REDIRECT 0x6`,
   > `RTM_MISS 0x7`, `RTM_RESOLVE 0xb`
   > `struct rt_msghdr { … u_short rtm_index; /* index for associated ifp or interface scope */ … int
   > rtm_flags; … };`
   > `#define RTF_IFSCOPE 0x1000000 /* has valid interface scope */`
   > `RTA_DST 0x1`, `RTA_GATEWAY 0x2`, `RTA_NETMASK 0x4`, `RTA_IFP 0x10`, `RTA_IFA 0x20`

   and *"User processes can obtain information about the routing entry to a specific destination by
   using a `RTM_GET` message."* `netstat(1)` decodes `RTF_IFSCOPE` as the flag letter `I` — *"Route is
   associated with an interface scope … A route which is marked with the `RTF_IFSCOPE` flag is
   instantiated for the corresponding interface."*
   The helper should also run **`route -n monitor`** (*"Continuously report any changes to the routing
   information base, routing lookup misses, or suspected network partitionings"*), optionally with
   `-ifindex`, to detect a third party (or configd) changing routes while MyVpn believes it owns them.
   **`UNVERIFIED`**: a `sysctl` MIB for dumping the table (`net.route.*`). `route(4)` documents no
   such MIB; prefer `PF_ROUTE` / `netstat`.

3. **The `route(4)`-level fact that makes the def1 approach necessary: duplicate destinations are
   refused.** *"The routing code returns `EEXIST` if requested to duplicate an existing entry."* So
   `route add default …` a second time fails; you cannot simply stack a second unscoped default.

4. **Two ways to take over the default route, and which to prefer.**

   **(A) Recommended: the "def1" half-routes.** OpenVPN documents exactly why:
   > `--redirect-gateway def1` — *"Use this flag to override the default gateway by using
   > `0.0.0.0/1` and `128.0.0.0/1` rather than `0.0.0.0/0`. **This has the benefit of overriding but
   > not wiping out the original default gateway.**"*
   > (general `--redirect-gateway`) *"(1) Create a static route for the `--remote` address which
   > forwards to the pre-existing default gateway … so that (3) will not create a routing loop.
   > (2) Delete the default gateway route. (3) Set the new default gateway to be the VPN endpoint
   > address … When the tunnel is torn down, all of the above steps are reversed so that the original
   > default route is restored."*
   > Source: <https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/vpn-network-options.rst>

   WireGuard's `wg-quick` does the same thing on Darwin, verbatim from
   <https://github.com/WireGuard/wireguard-tools/blob/master/src/wg-quick/darwin.bash>:
   ```
   route -q -n add -inet 0.0.0.0/1 -interface "$REAL_INTERFACE"
   route -q -n add -inet 128.0.0.0/1 -interface "$REAL_INTERFACE"
   # (IPv6 analogue: ::/1 and 8000::/1)
   ```
   Because `0.0.0.0/1` and `128.0.0.0/1` are more specific than `0.0.0.0/0`, they win for every
   address while leaving the original default installed. **Consequences that matter:**
   - No `EEXIST`, no `change`, no interface-scope juggling.
   - **Restoration is just deleting the two /1 routes** — the original default was never touched.
   - The kernel **removes them automatically** when the utun interface goes away (item 8), so a crash
     is far less likely to leave a broken default.
   - Reuse the same trick for a **destination split tunnel**: install explicit routes for the excluded
     ranges before the /1 routes.

   **(B) Alternative: `route change` the existing default.** The man page's `change` command
   (*"Change aspects of a route (such as its gateway)"*) is the only way to mutate the single real
   default in place. The documented `-interface` form applies to point-to-point links:
   > *"Alternately, if the interface is point to point the name of the interface itself may be given,
   > in which case the route remains valid even if the local or remote addresses change."*
   ```
   route -n change default -interface utun0
   # teardown:
   route -n change default -interface <orig-if> <orig-gateway>
   ```
   Use this only if you specifically want to own the default entry; it carries the risk that a
   subsequent interface disappearance leaves the machine with **no** default until configd's IP monitor
   reinstalls one for the new primary service. Snapshot `route -n get default` before changing it.
   Probe safely with `route -d` (debug-only, *"do not actually modify the routing table"*) and
   `route -t` (*"Run in test-only mode. /dev/null is used instead of a socket."*).

5. **`-ifscope` / `RTF_IFSCOPE`, precisely.** macOS *does* support multiple entries for the same
   destination, distinguished by interface scope:
   > *"`-ifscope` … allows for the presence of multiple route entries with the same destination, where
   > each route is associated with a unique interface. This modifier is required in order to
   > manipulate route entries marked with the `RTF_IFSCOPE` flag."*

   But a scoped route applies only to traffic associated with that interface (e.g. sockets bound with
   `IP_BOUND_IF`), so `-ifscope` is **not** a way to send all applications into the tunnel. It is the
   right tool for the tunnel's *own* transport scope, not for the global default.

6. **Route flags useful for a fail-closed design:**
   - `-blackhole` → `RTF_BLACKHOLE`, *"silently discard pkts (during updates)"*. WireGuard uses it as
     the **loop-prevention fallback when there is no gateway**: `route -q -n add -inet "<endpoint>"
     127.0.0.1 -blackhole`, commented *"# Prevent routing loop"* (and `::1 -blackhole` for v6).
   - `-reject` → `RTF_REJECT`, *"emit an ICMP unreachable when matched"* — fail fast; better UX than a
     black hole when the tunnel is down.
   - `-static` → `RTF_STATIC`, *"manually added route"* — mark MyVpn's routes for identification.
   - `-prefixlen` (IPv6) / `-netmask` (IPv4) for split-tunnel destinations.

7. **Loop avoidance — three independent layers:**
   (a) the host route (or `-blackhole`) for the VPN server via the original gateway — OpenVPN step (1)
   and the WireGuard fallback above;
   (b) `IP_BOUND_IF` on the Xray client's outbound socket to the physical interface (§1.4.2);
   (c) PF rules that pass the server's IPs before the final `block` (§1.3). These fail independently.

8. **Crash recovery — the interface-route question is now answered.** XNU's `if_rtdel()` in
   `bsd/net/if.c` exists *"to delete all route entries referencing a detaching network interface"*,
   walking the routing table and issuing `RTM_DELETE` for every route whose `rt_ifp` is the departing
   interface (`if_rtproto_del()` does the same per address family). WireGuard's Darwin script encodes
   the practical consequence: on teardown it does **not** delete routes, because *"routes are deleted
   automatically on device shutdown"*. Source:
   <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if.c>

   So the failure mode is *bounded* — but it is not zero, and the mitigations still matter:
   - Use **def1 half-routes** rather than mutating the system default (item 4A): interface-scoped
     cleanup then removes MyVpn's routes by itself.
   - If you *did* `change` the system default, expect a window with **no** default after the utun
     disappears, until configd's IP monitor republishes one. Journal the original gateway/interface.
   - Write a **route/PF/DNS/proxy journal** to disk before each mutation and replay the restore at
     daemon start; a crash + relaunch must not assume the previous process cleaned up.
   - Keep the helper alive with launchd `KeepAlive` (`launchd.plist(5)`: *"This optional key is used to
     control whether your job is to be kept continuously running … The value may be set to true to
     unconditionally keep the job alive"*; *"The use of this key implicitly implies RunAtLoad"*;
     relaunch throttling defaults to no more than once every 10 seconds; launchd sends `SIGTERM`
     before `SIGKILL`, with `ExitTimeOut` controlling the gap). Run the idempotent cleanup from
     `SIGTERM` **and** from a fresh-launch repair pass.
   - The app must treat `XPC_ERROR_CONNECTION_INTERRUPTED` as "the helper restarted, resynchronise
     state" and `XPC_ERROR_CONNECTION_INVALID` as "connection is dead, re-establish it" (documented in
     `xpc/connection.h`; see `xpc_connection_create(3)` in §1.1.4).

---

### 1.7 System / browser proxy

**Primary sources:** `networksetup(8)` — <https://keith.github.io/xcode-man-pages/networksetup.8.html>;
Apple's `SCSchemaDefinitions.h`, `SCPreferences.h`, `SCNetworkConfiguration*.h` from the `configd`
open-source tree — <https://github.com/apple-oss-distributions/configd>; and
`SCDynamicStoreCopyProxies`. Verbatim quotes are from those sources.

1. **Exact `networksetup` grammar** (the common shorthand is *wrong* — the trailing `on|off` is the
   *authenticated-proxy* switch, not the enable switch):
   > `-getwebproxy` networkservice — *"Displays Web proxy (server, port, enabled value) info."*
   > `-setwebproxy` networkservice domain portnumber authenticated username password — *"Set Web proxy
   > for <networkservice> with <domain> and <port number>. **Turns proxy on.** Optionally, specify
   > <on> or <off> for <authenticated> to enable and disable authenticated proxy support. Specify
   > <username> and <password> if you turn authenticated proxy support on."*
   > `-setwebproxystate` networkservice on | off
   > `-getsecurewebproxy` / `-setsecurewebproxy` networkservice domain portnumber authenticated
   > username password / `-setsecurewebproxystate` networkservice on | off
   > `-getsocksfirewallproxy` / `-setsocksfirewallproxy` / `-setsocksfirewallproxystate`
   > `-getproxybypassdomains` / `-setproxybypassdomains` networkservice domain1 [domain2] […] —
   > *"Specify 'Empty' for <domain1> to clear all Domain Name entries."*
   > `-setautoproxyurl` networkservice url — *"Set proxy auto-config to url for <networkservice> and
   > enable it."* / `-getautoproxyurl` networkservice
   > `-getproxyautodiscovery` / `-setproxyautodiscovery` networkservice on | off
   > *"Any flag that takes a password will accept '-' in place of the password to indicate it should
   > read the password from stdin."*

   Consequences: **enabling a manual proxy and setting its state are two operations**
   (`-setwebproxy …` follows implicitly by `-setwebproxystate`), and restoration must reset both the
   values and the state. Never interpolate user-supplied host/port into a shell string; pass them as
   separate `argv` entries.

2. **The key mapping** (verbatim string ↔ constant, from `SCSchemaDefinitions.h`):

   | CFString key | Constant | Type |
   | --- | --- | --- |
   | `HTTPEnable`, `HTTPPort`, `HTTPProxy` | `kSCPropNetProxiesHTTPEnable`, `…HTTPPort`, `…HTTPProxy` | CFNumber(0/1), CFNumber, CFString |
   | `HTTPSEnable`, `HTTPSPort`, `HTTPSProxy` | `kSCPropNetProxiesHTTPS*` | as above |
   | `SOCKSEnable`, `SOCKSPort`, `SOCKSProxy` | `kSCPropNetProxiesSOCKS*` | as above |
   | `ProxyAutoConfigEnable`, `ProxyAutoConfigURLString`, `ProxyAutoConfigJavaScript` | `kSCPropNetProxiesProxyAutoConfig*` | CFNumber(0/1), CFString, CFString |
   | `ProxyAutoDiscoveryEnable` | `kSCPropNetProxiesProxyAutoDiscoveryEnable` | CFNumber(0/1) |
   | `ExceptionsList`, `ExcludeSimpleHostnames` | `kSCPropNetProxiesExceptionsList`, `…ExcludeSimpleHostnames` | CFArray[CFString], CFNumber(0/1) |
   | `FTP*`, `Gopher*`, `RTSP*` | `kSCPropNetProxiesFTP*`, … | — |
   | `SupplementalMatchDomains` | `kSCPropNetProxiesSupplementalMatchDomains` | CFArray[CFString] |

   `SCDynamicStoreCopyProxies` returns exactly this dictionary ("Gets the current internet proxy
   settings"), and `scutil --proxy` prints it, so the CLI snapshot and the API snapshot agree.

3. **Framework equivalents** (all documented in Apple's SystemConfiguration headers):
   `SCPreferencesCreate` (or `…WithAuthorization` when elevation is required) → `SCPreferencesLock` →
   `SCNetworkServiceCopyAll` → identify the service (`SCNetworkInterfaceGetBSDName` for the BSD name)
   → `SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies)` →
   `SCNetworkProtocolSetConfiguration(protocol, dict)` with the keys above →
   `SCPreferencesCommitChanges` (*"Commits changes … to persistent storage"*) →
   `SCPreferencesApplyChanges` (*"Requests that the currently stored configuration preferences be
   applied to the active configuration"*) → `SCPreferencesUnlock`.
   **Correction to a common assumption:** `SCNetworkProtocolCreate` was **not found** in Apple's
   `SCNetworkConfiguration.h` / `SCNetworkConfigurationPrivate.h` in the `configd` tree — use
   `SCNetworkServiceCopyProtocol` + `SCNetworkProtocolSetConfiguration`. (`UNVERIFIED` that
   `SCNetworkProtocolCreate` never existed; it is not in the current open-source headers.)

4. **Proxies are per *network service*, and "the global proxy" is the primary service's.** Apple's
   schema documents `State:/Network/Global/Proxies` as *"If available, uses the primary service's
   proxy information in the `Setup:` key, otherwise, uses the proxy information in the `State:`
   key."* The default route and the *primary service* are **separate concepts** — `State:/Network/Global/IPv4`
   publishes `PrimaryService`, `PrimaryInterface` and `Router` as distinct properties. **So moving the
   default route to the tunnel does not change which service's proxies apps see.** If proxy mode is
   meant to apply to the tunnel, the tunnel service must be made primary or the proxies must be set on
   the service that is actually primary.
   Making a service primary: the state-level approach used by VPN scripts is to add `OverridePrimary`
   to the tunnel service's `IPv4` dictionary (`d.add OverridePrimary # 1`, as vpnc-script does);
   `SCNetworkServiceSetPrimaryRank(service, kSCNetworkServicePrimaryRankFirst)` exists
   (*"Allows a service to sort ahead of other services. Used by connection-oriented services like
   VPN"*) but lives in `SCNetworkConfigurationPrivate.h` — **`UNVERIFIED` as public API**; do not
   depend on it in a shipped product.

5. **Honest limits of proxy mode.** Proxy settings only affect applications that choose to honour the
   system proxy. Firefox uses system settings only when *"Use system proxy settings"* is selected;
   Java needs `java.net.useSystemProxies` plus per-protocol properties; many Electron/Chromium apps
   override proxy configuration in code. (These app-level claims are well-known behaviour but were
   **not** verified against each project's current docs in this pass — `UNVERIFIED`, verify before
   publishing user-facing text.) Proxy mode also cannot cover UDP/QUIC. It is a fallback, never a VPN.

6. **State restoration — and why it must be journaled to disk.** Proxies are per service and the
   "primary"/current service changes when the user moves between Wi-Fi and Ethernet, so:
   - snapshot **every** service (`networksetup -listallnetworkservices`, then the getters for each),
     not just the one you intend to change — the same per-service pattern WireGuard's Darwin script
     uses for DNS;
   - modify only what you must, and restore exactly that;
   - **remember that the change is persistent.** It is a SystemConfiguration preference write
     (`SCPreferencesCommitChanges` → persistent storage), so a stale proxy pointing at a dead local
     helper port **survives a crash and a reboot** and blackholes every proxy-honouring app until it
     is cleared. Store the pre-change state in the on-disk journal *and* mark MyVpn's own values so a
     later launch can recognise "this proxy is ours and our helper is gone" and repair it.
   - Repair from three places: graceful exit, the XPC invalidation handler, and the next-launch
     repair pass.

7. **PAC.** Manual proxies and PAC are independent settings (`HTTPEnable/HTTPProxy/HTTPPort` vs
   `ProxyAutoConfigEnable`/`ProxyAutoConfigURLString`, plus `ProxyAutoDiscoveryEnable` for WPAD).
   `networksetup -setautoproxyurl <service> <url>` sets the URL *and* enables PAC in one step.
   A `file://` PAC URL is representable (it is just a CFString, and CFNetwork exposes
   `kCFProxyAutoConfigurationURLKey`), but **`UNVERIFIED`**: whether every current macOS component
   that evaluates PAC will fetch a `file://` PAC (System Settings' UI only offers http/https PAC URLs,
   and sandboxed apps may lack read access to the file). **Recommendation: serve the PAC from a
   loopback HTTP server** (`http://127.0.0.1:<port>/proxy.pac`) rather than relying on `file://` —
   which also means the PAC is only useful while the local helper runs, reinforcing the
   stale-state hazard in item 6.

---

### 1.8 Packaging, signing, notarization, universal builds

**Primary sources:** Apple's *Placing content in a bundle*
(<https://developer.apple.com/documentation/bundleresources/placing-content-in-a-bundle>);
*Creating distribution-signed code for macOS*; *Notarizing macOS software before distribution*;
*Customizing the notarization workflow*; *Resolving common notarization issues*; *Packaging Mac
software for distribution*; TN2206 (archived *macOS Code Signing In Depth*); TN3126/TN3127/TN3147;
the `codesign(1)`, `notarytool(1)`, `stapler(1)`, `spctl(8)`, `syspolicy_check(1)` man pages;
Microsoft's *Publish .NET apps for macOS*; `dotnet/runtime` `doublemapping.cpp` and
`clrconfigvalues.h`; Avalonia's macOS deployment docs; and Apple's open-source `SecTranslocate.h`.

#### 1.8.1 Bundle layout — Apple's normative table

Apple's *Placing content in a bundle* gives the authoritative locations (macOS rows):

| Content | Location |
| --- | --- |
| `Info.plist` | `Contents/Info.plist` |
| main executable | `Contents/MacOS/` |
| **resource** (data files) | `Contents/Resources/` |
| **framework / dynamic library** | `Contents/Frameworks/` |
| app extension, plug-in | `Contents/PlugIns/` |
| help app, helper tool | `Contents/MacOS/` **or** `Contents/Helpers/` |
| XPC Service | `Contents/XPCServices/` |
| **privileged helper tool (`SMJobBless`)** | **`Contents/Library/LaunchServices/`** |
| Service Management login item | `Contents/Library/LoginItems/` |
| system extension | `Contents/Library/SystemExtensions/` |
| provisioning profile | `Contents/embedded.provisionprofile` |

Apple warns why this matters: *"If you put content in the wrong location, you may encounter
hard-to-debug code signing and distribution problems… incorrectly placed code might work during
day-to-day development, but might cause problems during notarization."*

**Corrected layout for MyVpn.app** (note `Frameworks/` for dylibs — this differs from the
"everything in `MacOS/`" .NET habit):

```
MyVpn.app/Contents/
  Info.plist
  MacOS/
    MyVpn                       # .NET apphost (native Mach-O, per-architecture)
    *.dll, *.json, *.pdb        # managed assemblies + runtimeconfig.json/deps.json
    libAvaloniaNative.dylib -> ../Frameworks/libAvaloniaNative.dylib   # relative symlink if needed
  Frameworks/                   # ALL nested Mach-O libraries live here
    libAvaloniaNative.dylib, libSkiaSharp.dylib, libHarfBuzzSharp.dylib,
    libcoreclr.dylib, libclrjit.dylib, libhostfxr.dylib, libhostpolicy.dylib,
    libSystem.Native.dylib, libSystem.Security.Cryptography.Native.OpenSsl.dylib, …
  Resources/
    geoip.dat, geosite.dat      # data assets
    AppIcon.icns
    MyVpnHelper                 # native privileged helper (routine for SMAppService)
  Library/
    LaunchDaemons/com.example.myvpn.helper.plist   # BundleProgram -> Contents/Resources/MyVpnHelper
                                                   # MachServices  -> com.example.myvpn.helper
    LaunchServices/com.example.myvpn.helper        # ONLY if shipping the SMJobBless fallback (<= macOS 12)
  embedded.provisionprofile     # ONLY if the NetworkExtension entitlement path is ever used
  _CodeSignature/
```

**The explicit Apple rule about data files** (this is the one the .NET habit violates):

> *"Don't save non-executable files in places that require code signatures, like
> `MyApp.app/Content/MacOS/`. Instead, save these files to a directory that doesn't require a code
> signature, like `MyApp.app/Contents/Resources/`."* — *Customizing the notarization workflow*

and TN2206:

> *"If a file is in a code location, it must be code, and it must be signed. **Do not put data files
> into code locations.** Move these elsewhere, such as `Contents/Resources`."*
> *"You can work around this by moving the files to the correct locations and **leave behind symlinks**
> so your code can still find the files."*

If you use the symlink workaround, it must stay **inside** the bundle — Gatekeeper *"rejects apps
containing symbolic links that … point outside the app bundle, except to locations in `/System` and
`/Library`"* (TN2206), while *"a nested bundle may contain symlinks that point into the enclosing
bundle."* `codesign --verify --strict` (not plain `codesign`) checks this.

**Avalonia's own manual guide contradicts itself here** — its layout dumps the whole `dotnet publish`
output into `Contents/MacOS`, and then its App Store section says the opposite (*".dll files are not
considered code by Apple… should be placed inside the /Resources folder"*, *"/MacOS files should
contain only executable mach-o"*, *"All other mach-o .dylib files should be inside the Frameworks/
folder"*). **Do not copy Avalonia's layout verbatim**; use the table above, and prefer
**Avalonia Parcel** (<https://docs.avaloniaui.net/tools/parcel/packaging-for-macos>), which generates
the bundle, signs and notarizes across platforms.

**The bundle is immutable once signed** (TN2206): *"I store data in or otherwise modify my bundle
after I sign it. — This is no longer allowed."* So a self-updating geo database must live outside:
ship a seed in `Contents/Resources`, and write updates to
`~/Library/Application Support/<bundle-id>/`. The only legal in-bundle mutation is the
`com.apple.application-instance` xattr on the top-level directory.

#### 1.8.2 `Info.plist` keys

| Key | Status | Notes |
| --- | --- | --- |
| `CFBundleExecutable` | required | Must equal the `Contents/MacOS/` filename. |
| `CFBundleIdentifier` | required | Reverse-DNS; also the default code-signing identifier. |
| `CFBundlePackageType` | required | `APPL` for an app; TN2206 ties a Gatekeeper denial directly to this being wrong. |
| `CFBundleVersion` | required | *"For macOS apps, increment the build version before you distribute a build."* |
| `CFBundleShortVersionString` | recommended | *"The required format is three period-separated integers."* |
| `LSMinimumSystemVersion` | recommended | Gates the app on old systems (the SDK does not). |
| `NSHighResolutionCapable` | set it | `true`. |
| `NSPrincipalClass` | **not required** | The claim that a .NET/Avalonia app needs `NSPrincipalClass = NSApplication` is **`UNVERIFIED` and probably a myth**: `NSPrincipalClass` is consumed by Cocoa's `NSApplicationMain` startup path, which Avalonia does not use (it drives `NSApplication` via `libAvaloniaNative.dylib`), and **Avalonia's own `Info.plist` template does not contain it**. Test with and without. |
| `NSSupportsAutomaticGraphicsSwitching` | optional | Only meaningful for the **OpenGL** path on dual-GPU Macs. |
| `LSApplicationCategoryType` | optional | App-Store-facing metadata; effect for Developer ID is `UNVERIFIED`. |
| `SMPrivilegedExecutables` | `SMJobBless` only | Dictionary, key = helper label, value = **code-requirement string**. Not used by `SMAppService`. |
| `SMAuthorizedClients` | `SMJobBless` only | In the **helper's** embedded `Info.plist`; array of client requirement strings. |

#### 1.8.3 Signing: order, entitlements, and the two silent traps

Apple: *"Determine the signing order — Sign code from the inside out. That is, if component A depends
on component B, sign B before you sign A."* and *"Don't include entitlements or profiles when signing
frameworks. Including them produces an invalid code signature."*

Order for MyVpn: **(1)** every nested Mach-O in `Contents/Frameworks/` — bare, no entitlements, no
`--options runtime`; **(2)** the privileged helper — its **own** minimal entitlements; **(3)** the
`.app` last, with the app's entitlements.

**Trap 1 — `codesign` is "verb noun".** The man page: *"As a general rule `codesign` follows a verb
noun rule. For example `--sign` should be placed before `--options`… **If these are inverted and
`--options` is provided before `--sign` in the invocation, the value of `--options` is ignored
silently.**"* Writing `codesign --options runtime --sign "$ID" MyVpn.app` therefore produces an app
with **no hardened runtime**, and notarization fails with
`The executable does not have the hardened runtime enabled.` Always `--sign "$ID" … --options runtime`.

**Trap 2 — never `sudo codesign`**: *"Don't run `codesign` using `sudo` because `codesign` relies on
information in your user account when it signs code."*

**Why `--deep` is forbidden here.** The man page signature line itself now reads
**"`--deep` (DEPRECATED for signing as of macOS 13.0)"**, with:
> *"Beware: All signing options will be applied, in turn, to all nested content. This is almost never
> what you want."*
> *"The `codesign` tool will only discover nested code content in the following directories:
> `Contents`, `Contents/Frameworks`, `Contents/SharedFrameworks`, `Contents/PlugIns`,
> `Contents/Plug-ins`, `Contents/XPCServices`, `Contents/Helpers`, `Contents/MacOS`,
> `Contents/Library/Automator`, `Contents/Library/Spotlight`, `Contents/Library/LoginItems`"*
> *"If any code (Mach-Os, bundles) are located outside the above listed locations they will not be
> signed by the `--deep` option"*

Apple's guide has a section literally titled **"Avoid deep code signing"**, and TN2206 adds:
*"Signing with `--deep` is for emergency repairs and temporary adjustments only."*
**Consequence specific to this project:** the discovery list **omits
`Contents/Library/LaunchServices`** — the directory Apple's own content table mandates for a
privileged helper. So a `--deep` build can leave the privileged helper unsigned. (`UNVERIFIED` as a
verbatim Apple statement; it is a direct reading of the quoted list.) `--deep` also applies *one*
options/entitlements set to every nested item, which is exactly wrong when the helper and the app need
different entitlements.

**`--deep` *is* appropriate for pre-flight `--verify`** (`codesign --verify --deep --strict`), because
*"Gatekeeper always performs `--deep` style validation"* (TN2206). But note the man page's warning
that *"Verification/validation do not check the signature against OS policy"* — use `spctl` /
`syspolicy_check` for policy.

#### 1.8.4 Hardened-runtime entitlements for .NET 8 — `allow-jit`, and nothing else

Microsoft is explicit: *"**Entitlements for apps not published as Native AOT** — For apps not
published as Native AOT, the `com.apple.security.cs.allow-jit` entitlement is required."* (No
architecture qualifier → required on **both** x64 and arm64.) *"For apps published as Native AOT, no
entitlements are required."*
Source: <https://learn.microsoft.com/en-us/dotnet/core/deploying/macos>

Why `allow-jit` is the right and sufficient one:
- Apple defines it as exactly the `MAP_JIT` permission: *"A Boolean value that indicates whether the
  app may create writable and executable memory using the `MAP_JIT` flag."*
- CoreCLR detects and uses `MAP_JIT` under the hardened runtime — `IsMapJitFlagNeeded()` in
  `src/coreclr/minipal/Unix/doublemapping.cpp` probes for `PROT_READ|PROT_WRITE|PROT_EXEC`, retries
  with `MAP_JIT`, and the JIT's mmap then sets `mmapFlags |= MAP_JIT`.
- `DOTNET_EnableWriteXorExecute` **defaults to 1 in .NET 8**
  (`src/coreclr/inc/clrconfigvalues.h` @ `release/8.0`: `RETAIL_CONFIG_DWORD_INFO(EXTERNAL_EnableWriteXorExecute, W("EnableWriteXorExecute"), 1, …)`),
  i.e. W^X is on by default, which is the `MAP_JIT` path.

**Entitlements deliberately *not* used:**

| Entitlement | Why not |
| --- | --- |
| `com.apple.security.cs.allow-unsigned-executable-memory` | The non-`MAP_JIT` escape hatch; Apple warns it *"exposes your app to common vulnerabilities in memory-unsafe code languages."* Not needed when W^X/`MAP_JIT` is in play. |
| `com.apple.security.cs.disable-library-validation` | Library validation permits loading code *"signed with the same Team ID as the main executable."* Every Mach-O we ship is signed by us, and managed `.dll`s are PE/IL, not Mach-O, so `dyld` never validates them. Apple warns *"Gatekeeper runs extra security checks on programs that have it disabled."* |
| `com.apple.security.cs.allow-dyld-environment-variables` | For `DYLD_*` injection; .NET uses `DOTNET_*`/`DOTNET_ROOT`. |
| `com.apple.security.get-task-allow` | Notarization **fails**: `The executable requests the com.apple.security.get-task-allow entitlement.` |
| `com.apple.security.cs.debugger` | For debugger products (`task_for_pid`), not for the VPN app. |
| `com.apple.security.cs.disable-executable-page-protection` | TN3126: *"Don't do that!"* |

Recommended `MyVpn.entitlements` (applied to the apphost **and**, separately, to a .NET helper):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.cs.allow-jit</key><true/>
</dict></plist>
```

Entitlements must be ASCII with no BOM, and `plutil -lint` should pass before use.
**`UNVERIFIED`**: whether `PublishSingleFile=true` causes an unsigned Mach-O to be loaded at runtime
(which would then force `disable-library-validation`); and whether a custom publish step that
re-signs the apphost silently drops entitlements
(<https://github.com/dotnet/runtime/issues/113707> — title verified, body not).

#### 1.8.5 Notarization

- **`altool` is dead.** *"Starting November 1, 2023, the Apple notary service no longer accepts
  uploads from `altool` or Xcode 13 or earlier."* Use `notarytool` (or Xcode 14+).
- **You cannot submit a bare `.app`.** `notarytool(1)`: *"`notarytool` **submit** works only with UDIF
  disk images, signed 'flat' installer packages, and zip files."* The standard recipe:
  `ditto -c -k --keepParent MyVpn.app MyVpn.zip` → `xcrun notarytool submit MyVpn.zip
  --keychain-profile <profile> --wait` → `xcrun notarytool log <id> <profile> log.json`.
  **Read the log even on success**: *"Always check the log file, even if notarization succeeds,
  because it might contain warnings that you can fix prior to your next submission."*
  Operational limit: *"Limit notarizations to 75 per day."*
- **The seven requirements** (verbatim): code-sign every executable; use a **Developer ID**
  certificate (*"Don't use a Mac Distribution, ad hoc, Apple Developer, or local development
  certificate"*); enable the **Hardened Runtime** *"for your app and command line targets"*; include a
  **secure timestamp**; **no** `get-task-allow`; link against the macOS 10.9+ SDK; properly-formatted
  ASCII entitlements.
  Failure strings to grep for: `The signature of the binary is invalid.` · `The binary is not signed
  with a valid Developer ID certificate.` · `The signature does not include a secure timestamp.` ·
  `The executable requests the com.apple.security.get-task-allow entitlement.` · `The binary uses an
  SDK older than the 10.9 SDK.` · `The executable does not have the hardened runtime enabled.` ·
  `Embedded entitlements are invalid: syntax error near line 1`
- **Timestamp check:** `codesign -dvv` shows `Timestamp=` for a secure timestamp; the presence of
  **`Signed Time`** instead means there is **no** secure timestamp. Hardened-runtime bit: look for
  `flags=0x10000(runtime)`. Universal binaries are *"signed independently, each with its own code
  directory"*, so check both slices (`codesign -dvv --arch arm64` / `--arch x86_64`).
- **A `.pkg` is not required** — a zipped, signed `.app` is accepted — **but a signed DMG or signed
  `.pkg` is better**, because a ZIP cannot be signed or stapled as a whole, while *"You can sign a
  disk image, which protects all files and folders you include from modification."* (`.pkg` requires a
  **Developer ID Installer** certificate, which is a different OID from the Application certificate.)
- **Nested files get their own tickets:** *"The notary service generates a ticket for the top-level
  file that you specify, as well as for each nested file."* Tickets are *"a set of cdhash values"*
  (TN3126) and are also published online for Gatekeeper lookup.
- **Stapling rules that bite:** *"Stapling does not invalidate the code signature"* but
  *"Code-signing a supported file format invalidates any stapled tickets, so `stapler staple` must be
  run again"*; *"While you can notarize a ZIP archive, you can't staple to it directly. Instead, run
  `stapler` against each item… Then create a new ZIP"*; and **"Although tickets are created for
  standalone binaries, it's not currently possible to staple tickets to them."** `stapler` also only
  processes **one path per invocation**.
- **Notarize the outermost container only** (*"If you distribute your product using nested containers,
  only notarize the outermost container."*).
- **The helper installed to `/Library/PrivilegedHelperTools/`** is nested code inside the submitted
  app, so it is covered by that submission and gets a ticket; the installed copy is byte-identical and
  therefore has the same cdhash. It **cannot** carry a stapled ticket (standalone binaries can't be
  stapled), so its verification depends on the **online** notary lookup. *Conclusion: the installed
  copy should not need its own submission, but first use on an offline machine is a real risk.
  `UNVERIFIED` as a verbatim Apple statement — test on a clean, offline Mac.*

#### 1.8.6 App translocation (Gatekeeper path randomization)

The policy is documented in Apple's open-source `SecTranslocate.h` — the clearest primary source
available:

> `SecTranslocateURLShouldRunTranslocated` … *"The policy is as follows: 1. If path is already on a
> nullfs mountpoint - no translocation; 2. **No quarantine attributes - no translocation**; 3. If
> `QTN_FLAG_DO_NOT_TRANSLOCATE` is set or `QTN_FLAG_TRANSLOCATE` is not set - no translocations;
> 4. Otherwise, if `QTN_FLAG_TRANSLOCATE` is set - translocation"*
> *"Translocations will be created in the calling user's `DARWIN_USER_TEMPDIR/AppTranslocation/<UUID>`…
> Resulting translocations are of the form `/<DARWIN_USER_TEMPDIR>/AppTranslocation/<DIR>/d/myApp.app`"*

**So translocation is quarantine-triggered.** Apple's macOS 10.12 release notes state the effect:
*"An app distributed outside the Mac App Store runs from a randomized path when it is launched and so
cannot access such external resources. To provide secure execution, code sign your disk image itself
using the codesign tool…"*

Consequences for MyVpn:
- The **whole bundle** is mounted together, so bundle-relative resource reads (geo data, helper) still
  work; the mount is **read-only** and at a randomized path, so **writes fail**, absolute paths
  recorded on a previous launch break, and auto-update cannot replace the running bundle.
- The app must therefore: read everything via bundle-relative APIs, never write inside the bundle,
  never assume a stable install path, and treat `Contents/Resources` as the only place its own data
  lives.
- **`SMJobBless` is requirement-string based, not path based**, so translocation does not break the
  signature match; it also installs a copy outside the bundle. **`UNVERIFIED`**: whether
  `SMAppService` registration from a *translocated* path is refused (the system tracks a stable app
  location for Login Items). This is a concrete reason to distribute via a **signed DMG or `.pkg`**,
  which Apple names as the mitigation, and to test first-run from the quarantined download explicitly.
  (`SecTranslocateIsTranslocatedURL` / `SecTranslocateCreateOriginalPathForURL` exist but are SPI, and
  Apple DTS is on record that the exact circumstances of translocation are undocumented and have
  changed over time.)

#### 1.8.7 Universal (x64 + arm64) builds — the honest state

- **The .NET SDK does not produce a universal (fat) Mach-O.** Microsoft's own macOS page shows the
  universal step as a manual `lipo` over two per-RID publishes, and even the `net*-macos` workload
  does not produce a universal package. There is no usable `osx-universal` RID for third-party native
  resolution. `-p:RuntimeIdentifiers=osx-x64;osx-arm64` is a **restore/multi-targeting** aid, not a
  universal-output feature; it yields `…/osx-x64/publish/` and `…/osx-arm64/publish/`.
- **What must be `lipo`'d:** the apphost, every `Contents/Frameworks/*.dylib` (Avalonia, Skia,
  HarfBuzz, and the self-contained CoreCLR natives: `libcoreclr`, `libclrjit`, `libhostfxr`,
  `libhostpolicy`, `libSystem.Native`,
  `libSystem.Security.Cryptography.Native.OpenSsl`, …), and any **ReadyToRun** images (R2R is native
  code, so it is architecture-specific — for a universal build prefer `PublishReadyToRun=false`).
  **What must not:** managed IL `.dll`s, `.pdb`, `.json` — these are architecture-neutral.
- **`lipo` invalidates the signature**, so `lipo` **before** signing, then sign inside-out. Apple
  confirms the converse is safe: *"Removing the Mach-O slice for a particular architecture from a
  universal binary will also not invalidate the code signature."* (TN2206)
- **Microsoft's own example then runs `codesign --force --sign -`** — that is **ad-hoc signing**
  (*"ad-hoc signing does not use an identity at all"*). **Never ship that output.** Re-sign with
  Developer ID + timestamp + runtime + entitlements.
- **The unsolved problem is `deps.json`/`runtimeconfig.json`.** A self-contained `deps.json` embeds
  the RID in `runtimeTarget` (`.NETCoreApp,Version=v8.0/osx-x64` vs `…/osx-arm64`), so a fat binary
  with one managed tree is internally inconsistent for at least one architecture. **No supported merge
  was found and the host's tolerance for a mismatched `runtimeTarget` is `UNVERIFIED`.** This is the
  single highest-risk unknown in the packaging plan. Options, least to most risky:
  1. **Ship two app bundles** (`MyVpn-x64.app`, `MyVpn-arm64.app`) — no merging, no unknowns. The
     low-risk answer for a first release.
  2. Per-RID subfolders inside one bundle plus a thin native launcher that `exec`s the right slice —
     avoids `lipo` entirely, needs a launcher + careful signing.
  3. `lipo` the natives and hand-merge the JSON — smallest output, highest risk, must be validated on
     a Mac.
- Universal-bundle verification must check **both** slices (`codesign -dvv --arch …`, and launch the
  app under `arch -x86_64` / `arch -arm64`).

#### 1.8.8 Signing/notarization pre-flight checklist

```bash
APP="MyVpn.app"; ID="Developer ID Application: … (TEAMID1234)"; ENT="MyVpn.entitlements"
plutil -lint "$ENT"                                    # ASCII, no BOM
find "$APP/Contents/Frameworks" -name '*.dylib' -print0 \
  | xargs -0 -n1 codesign --force --timestamp --sign "$ID"           # bare: no entitlements
codesign --force --timestamp --sign "$ID" --options runtime \
         --entitlements Helper.entitlements "$APP/Contents/Library/LaunchServices/com.example.myvpn.helper"
codesign --force --timestamp --sign "$ID" --options runtime --entitlements "$ENT" "$APP"   # app LAST
codesign --verify --deep --strict --verbose=2 "$APP"
codesign -dv --verbose=4 "$APP"          # expect flags=0x10000(runtime), Timestamp=, TeamIdentifier=
codesign -d --entitlements - "$APP"      # must NOT print bplist00
syspolicy_check notary-submission "$APP" --verbose
syspolicy_check distribution "$APP" --verbose
spctl -a -vvv "$APP"
ditto -c -k --keepParent "$APP" MyVpn.zip
xcrun notarytool submit MyVpn.zip --keychain-profile notary-acct --wait
xcrun notarytool log <submission-id> --keychain-profile notary-acct notary-log.json   # read even on success
```

Never: `--deep` for signing · `sudo codesign` · `--options` before `--sign` · shipping
`get-task-allow` · shipping the `--sign -` output from the `lipo` step · signing nested libraries with
entitlements.

---

### 1.9 Summary of the honest verdict

| Question | Verdict |
| --- | --- |
| Can a self-distributed Xray client ship a real IP tunnel on macOS? | **Yes** — raw `utun` created by a root privileged helper. `[DEV-ID]` |
| Does that require an Apple-gated entitlement? | **No** documented entitlement; it requires root. The kernel control is registered `CTL_FLAG_PRIVILEGED | CTL_FLAG_REG_SETUP | CTL_FLAG_REG_EXTENDED; /* Require root */`. |
| Is `NEPacketTunnelProvider` available to Developer ID? | **Yes**, but with a Developer ID provisioning profile + the `*-systemextension` entitlement values, a **native** (non-.NET) extension, and user approval. Heavy; poor fit for an open-source self-distributed client. |
| Kill switch? | **Yes, but best-effort and unsupported by Apple.** PF ruleset with a `pfctl -E` token, Apple's `com.apple/*` anchors preserved, fail-closed `block … quick all`, IPv6 dropped, DNS outside the tunnel blocked, server IPs in a persistent PF table, `pfctl -F states` on every transition. **TN3165 explicitly says PF "is not considered API. Do not use Packet Filter in a software product that you distribute to a wide audience."** |
| DNS leak prevention? | Block port 53 outside the tunnel **and** fix the resolver configuration. The packet rule alone leaves resolution *broken*, because mDNSResponder's resolvers are bound to interfaces with `IP_BOUND_IF` and the Super client prefers the **primary service's** resolvers — a route change does not move them. |
| **Per-process routing?** | **No — not reliably.** PF `user`/`group` are match criteria only (TCP/UDP-only, credentials frozen at socket creation, unknown for forwarded traffic, unusable on `nat`/`rdr`). macOS PF **does** document `route-to`/`reply-to`, so a `user`-scoped `route-to` is syntactically possible — but it is **directional only** (replies unaffected), does **not** rewrite source addresses, needs a valid next-hop for a point-to-point utun, and is unproven; `rtable` is inbound-only. `ipfw` is gone (absent from current XNU). NECP/proc-UUID is Apple-internal. Per-app VPN (`NEAppRule`, `NETunnelProviderRoutingMethod.sourceApplication`) is **read-only** to the provider and installed by a managed configuration profile. `NEFilterDataProvider` can allow/deny/delay but is sandboxed against relaying flows. **The best available approximations are destination-based split tunnelling, UID-based *block*-lists via PF, and app-level proxy configuration.** |
| Packaging a .NET/Avalonia app for both architectures? | Doable but manual: dylibs in `Contents/Frameworks`, data in `Contents/Resources`, helper in `Contents/Resources` (SMAppService) or `Contents/Library/LaunchServices` (SMJobBless), sign inside-out with `--sign` before `--options`, `allow-jit` only, ship a **signed DMG/`.pkg`** to avoid translocation. Universal binaries need `lipo` **before** signing, and the `deps.json` RID problem is unsolved — shipping two bundles is the low-risk answer. |

---

## 2. Architecture proposal

### 2.1 Process model

```
┌──────────────────────────────────────────────────────────────────────┐
│ MyVpn.app (Developer ID, notarized, hardened runtime)                │
│                                                                      │
│  ┌──────────────────┐   XPC (Mach service)   ┌────────────────────┐  │
│  │ MyVpn (Avalonia) │◄──────────────────────►│ MyVpnHelper        │  │
│  │ runs as the user │  sync request/reply    │ LaunchDaemon, root │  │
│  │                  │                        │ SMAppService       │  │
│  │ • UI             │                        │ • utun create      │  │
│  │ • config store   │                        │ • route mgmt       │  │
│  │ • xray-core      │◄── utun fd (XPC fd) ───│ • DNS mgmt         │  │
│  │   (unprivileged) │                        │ • PF kill switch   │  │
│  └──────────────────┘                        │ • state journal    │  │
│                                              └────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

Rationale:

- **Least privilege.** Only utun creation, routing, DNS and PF need root. The Xray core, the config
  parser (which consumes untrusted subscription data), the geo-asset loader and the UI stay
  unprivileged. Passing the utun control socket to the unprivileged core is what makes this possible
  (`xpc_fd_create`/`xpc_dictionary_set_fd`; §1.1.5).
- **A native helper shim is recommended** (`MyVpnHelper`, Swift/ObjC/C). It owns the XPC listener
  (blocks are natural there), the peer-requirement validation, and the privileged syscalls; its
  surface is a small, auditable command set. The .NET side then needs **no block interop at all**:
  `xpc_connection_create_mach_service(...)` +
  `xpc_connection_send_message_with_reply_sync(...)`.
- If the team insists on a .NET helper, see §1.1.5 options B/C for the block-interop cost, and
  prefer C (UNIX socket + `LOCAL_PEERTOKEN`) over synthesizing global blocks.

### 2.2 Helper installation and lifecycle

```
App start
  ├─ SMAppService.daemon(plistName:"com.example.myvpn.helper.plist").status
  │    ├─ .enabled            → connect XPC, proceed
  │    ├─ .notRegistered      → register(); status may become .requiresApproval
  │    ├─ .requiresApproval   → show UI: "Allow MyVpn in Login Items"; call
  │    │                         openSystemSettingsLoginItems(); poll status
  │    └─ .notFound           → bundle layout bug (plist path / BundleProgram)
  └─ (macOS 12 and older, if supported) SMJobBless(kSMDomainSystemLaunchd, label, auth, &err)
```

The helper must be **idempotent and self-healing**: on every start it reads its state journal and
restores routes/DNS/PF/proxies to the pre-VPN state before accepting any commands.

### 2.3 Bring-up / tear-down state machine (fail-closed ordering)

```
Bring up:
  1  helper: recover journal (apply any pending restore first)
  2  helper: snapshot current state  → routes (default gw/if), DNS per service,
                                        PF (rules/nat/anchors/tables + `pfctl -s References`),
                                        proxy per service
  3  helper: open utun control socket; read back interface name (UTUN_OPT_IFNAME)
  4  helper: set address/MTU on utun
  5  helper: anti-loop host route for the server via the ORIGINAL gateway
             (or `-blackhole` if no gateway is known)
  6  app:    start xray-core with the tun fd; bind its outbound socket with IP_BOUND_IF
             to the physical interface                                   (anti-loop, second layer)
  7  helper: install the def1 half-routes (0.0.0.0/1 + 128.0.0.0/1 via utun)
             OR `route change default` (see section 1.6 item 4)
  8  helper: pfctl -n -f - (parse-only) ; TOKEN=$(pfctl -E) ; pfctl -f - <ruleset>
  9  helper: pfctl -F states          (stale states would bypass the new policy)
 10  helper: apply DNS (tunnel-scoped resolvers / /etc/resolver for split DNS)
 11  helper: flush caches (dscacheutil -flushcache ; killall -HUP mDNSResponder)
 12  helper: journal state = UP

Tear down (reverse, and always executed on helper start if journal says UP):
  a  helper: restore DNS ; restore proxies ; flush caches
  b  helper: pfctl -f /etc/pf.conf ; pfctl -X <TOKEN>      (verify with pfctl -s References)
  c  helper: delete the def1 half-routes (or restore the default route if it was changed)
  d  helper: delete the server host route
  e  app:    stop xray-core; close tun fd
  f  helper: close utun control socket (interface disappears; kernel drops its routes via if_rtdel)
  g  helper: journal state = DOWN
```

Invariants:

- **PF is enabled with our own token *before* the default route moves, and released only *after* the
  route is restored.** This makes the failure mode "no network" instead of "traffic leaks".
- **Every step is journaled before it is performed**, so a crash between steps is recoverable.
- **Never `pfctl -d`** (it stomps every other enabler). Only `-X <our token>`. **Never `pfctl -e`**
  (no token → no selective release).
- **Flush PF states after every policy transition** (`pfctl -F states`), or previously-approved flows
  keep passing under the new, stricter ruleset.
- **Use def1 half-routes in preference to mutating the system default**, so teardown is a two-route
  delete and a crashed helper cannot leave the machine with no default at all.

### 2.4 C# interface proposals

Design rules: every capability is queryable; every operation returns a structured failure; nothing
pretends to be portable when it is not; macOS-specific limitations are part of the API surface.

```csharp
namespace MyVpn.Platform.MacOS;

public enum CapabilityLevel
{
    Supported,                 // works, no caveats
    SupportedWithCaveats,      // works, documented limitation
    Unsupported,               // cannot be done by this app
    RequiresManagedDeployment, // only via MDM/config profile
}

public sealed record Capability(CapabilityLevel Level, string Statement, string? Evidence = null);

public interface IPlatformCapabilities
{
    Capability PerProcessRouting   { get; }   // macOS: Unsupported
    Capability PerAppRouting       { get; }   // macOS: RequiresManagedDeployment
    Capability DestinationSplit    { get; }   // macOS: Supported
    Capability UidBlockList        { get; }   // macOS: SupportedWithCaveats
    Capability KillSwitch          { get; }   // macOS: Supported
    Capability Ipv6LeakPrevention  { get; }   // macOS: Supported
    Capability SystemProxyMode     { get; }   // macOS: SupportedWithCaveats
    Capability TunnelMode           { get; }  // macOS: Supported (utun), or NetworkExtension
}
```

```csharp
public interface IPrivilegedHelper : IAsyncDisposable
{
    HelperStatus Status { get; }                    // NotInstalled/RequiresApproval/Enabled/NotFound/Error
    Task<HelperInstallResult> EnsureInstalledAsync(CancellationToken ct);
    Task OpenApprovalUiAsync(CancellationToken ct); // SMAppService.openSystemSettingsLoginItems
    Task<HelperPing> PingAsync(CancellationToken ct);
}

public interface ITunnelProvider
{
    // macOS: creates a utun via the helper, returns the fd to the unprivileged core.
    Task<TunnelHandle> CreateAsync(TunnelRequest req, CancellationToken ct);
    Task SetInterfaceAsync(TunnelHandle h, TunnelInterfaceConfig cfg, CancellationToken ct);
    Task DestroyAsync(TunnelHandle h, CancellationToken ct);
}

public interface IKillSwitch
{
    Capability Capability { get; }
    Task<KillSwitchState> SnapshotAsync(CancellationToken ct);   // ruleset + token + pf enabled state
    Task ArmAsync(KillSwitchPolicy policy, CancellationToken ct);  // validate, -E, -f
    Task DisarmAsync(CancellationToken ct);                        // restore ruleset, -X token
    Task UpdateServerTableAsync(IReadOnlyList<IPAddress> serverIps, CancellationToken ct);
}

public sealed record KillSwitchPolicy(
    string TunnelInterface,            // e.g. "utun4" — resolved at runtime, not hardcoded utun0
    IReadOnlyList<IPAddress> ServerIps,
    bool BlockIpv6,
    bool BlockDnsOutsideTunnel,
    IReadOnlyList<string> PhysicalInterfaces,   // for DHCP bootstrap rules
    bool AllowLan);                    // when false, RFC1918/link-local are also blocked

public interface IRouteManager
{
    Task<RouteSnapshot> SnapshotAsync(CancellationToken ct);
    Task<DefaultRoute> GetDefaultAsync(CancellationToken ct);
    Task AddHostRouteViaGatewayAsync(IPAddress host, DefaultRoute via, CancellationToken ct);
    Task SetDefaultViaTunnelAsync(string utunName, CancellationToken ct);
    Task RestoreAsync(RouteSnapshot snapshot, CancellationToken ct);
    // Reads via PF_ROUTE / sysctl, writes via the helper. Never shell-string interpolation.
    IAsyncEnumerable<RouteEntry> EnumerateAsync(CancellationToken ct);
}

public interface IDnsConfigurator
{
    Task<DnsSnapshot> SnapshotAsync(CancellationToken ct);       // scutil --dns + per-service values
    Task SetTunnelResolversAsync(IReadOnlyList<IPAddress> servers, IReadOnlyList<string> searchDomains, CancellationToken ct);
    Task AddSplitResolverAsync(string domain, IReadOnlyList<IPAddress> servers, CancellationToken ct); // /etc/resolver/<domain>
    Task FlushAsync(CancellationToken ct);                        // dscacheutil -flushcache; HUP mDNSResponder
    Task RestoreAsync(DnsSnapshot snapshot, CancellationToken ct);
    IReadOnlyList<ScopedResolver> DescribeAsync(CancellationToken ct);  // parsed `scutil --dns`
}

public interface IProcessRouter
{
    // DELIBERATELY LIMITED. See docs/research/08-macos-networking.md §1.4.
    Capability Capability { get; }                       // Unsupported for include-routing
    bool SupportsIncludeByProcess { get; }               // false on macOS
    bool SupportsExcludeByUid { get; }                   // true on macOS (PF `user`), block semantics only

    Task SetUidBlockListAsync(IReadOnlyList<uint> uids, CancellationToken ct);
    Task ClearUidBlockListAsync(CancellationToken ct);
    Task<IReadOnlyList<ProcessNetworkAttribution>> ListAttributableAsync(CancellationToken ct);
}

public interface ISystemProxyManager
{
    Task<ProxySnapshot> SnapshotAsync(CancellationToken ct);       // all services
    Task SetAsync(ProxyConfig cfg, CancellationToken ct);
    Task RestoreAsync(ProxySnapshot snapshot, CancellationToken ct);
    Capability Capability { get; }                                 // SupportedWithCaveats
}
```

Implementation notes that belong in the code, not just the doc:

- `IProcessRouter` **must** be able to say "no". `SupportsIncludeByProcess == false` is not an error
  condition on macOS; it is the correct answer, and the UI must branch on it.
- `IKillSwitch` must resolve the actual utun name at runtime (`UTUN_OPT_IFNAME`) — never assume
  `utun0`, which may be taken by another VPN product (WireGuard, Tailscale, iCloud Private Relay).
- All privileged operations go through the helper's typed XPC command set; the app never runs
  `pfctl`/`route`/`networksetup` itself, and the helper never accepts a raw argv array from the app.
- The helper validates each peer connection with
  `xpc_connection_set_peer_team_identity_requirement` (Team ID) before dispatching.

---

## 3. Risks

| # | Risk | Severity | Mitigation |
| --- | --- | --- | --- |
| R1 | **Bricked network after crash** (routes/DNS/PF left pointing at a dead tunnel). | High | On-disk journal + unconditional restore at helper start; launchd `KeepAlive`; PF token discipline; test with SIGKILL at every step. |
| R2 | **Per-process routing promised in UI but impossible** → user-visible security failure (traffic they believed was tunnelled goes direct or dies). | High | `IProcessRouter.SupportsIncludeByProcess == false`; UI shows the real modes; documentation states the limitation; QA tests assert the limitation. |
| R3 | `SMAppService` registration requires **user approval**; users may not find/act on it. | Medium | Detect `requiresApproval`, call `openSystemSettingsLoginItems()`, re-check on foreground, never silently degrade. |
| R4 | **Wrong helper layout** for the OS version (`Contents/Resources` vs `Contents/Library/LaunchServices`; `Program` vs `BundleProgram`). | Medium | Ship one layout, branch per macOS major version; integration test on 13/14/15/26. |
| R5 | **PF ruleset clobbers Apple's anchors** → breaks Internet Sharing / AirDrop / Continuity / Xcode device debugging. | High | Always include the `com.apple/*` anchor lines; snapshot and restore the original ruleset; never edit `/etc/pf.conf`; run Apple's TN3165 test list in CI. |
| R6 | **PF enabled by another product** and our teardown disables theirs. | High | Always `pfctl -E` and release only our own token; never `-e`, never `-d`, never `-X 0`; assert coexistence with the Application Firewall (`com.apple/250.ApplicationFirewall`) and a second `-E` holder. |
| R6b | **Apple does not support PF for third-party products at all** (TN3165: *"It is not considered API… plan to migrate to Network Extension"*). The kill switch may break on any macOS update and Apple will not treat that as a bug. | High | Keep the kill switch behind `IKillSwitch`; document it as best-effort in user-facing text; re-test on every macOS release; revisit if the NE entitlement ever becomes practical. |
| R6c | **Stale PF states bypass a newly tightened ruleset** — PF passes stateful flows *"without evaluation of any rules"*. | High | `pfctl -F states` after every transition; test that an in-flight flow is actually cut when the kill switch arms. |
| R7 | **DNS leak** via the primary service's interface-bound resolvers (mDNSResponder uses `IP_BOUND_IF`, so a route change does not move them). | High | PF port-53 rules **plus** making the tunnel service/resolvers the ones the Super client selects; test with an observation resolver that records the egress interface; document what is and isn't covered. |
| R8 | **Route installation**: unscoped duplicate defaults are refused (`EEXIST`), and mutating the system default can leave no default after an interface disappears. | High | Use the OpenVPN/WireGuard **def1 half-routes** (`0.0.0.0/1` + `128.0.0.0/1`); journal the original gateway/interface; anti-loop host route + `IP_BOUND_IF`; per-OS-version integration tests. |
| R9 | **Notarization/Gatekeeper**: translocation breaks paths, entitlements wrong for .NET, shipping a `--deep`/`--sign -` artefact, `--options` silently dropped by flag order. | High | Sign inside-out with `--sign` before `--options`; never `--deep` for signing; `allow-jit` only; ship a **signed DMG or `.pkg`** to avoid translocation; verify with `syspolicy_check`, `spctl`, `stapler validate` on a clean VM. |
| R9b | **The installed helper copy in `/Library/PrivilegedHelperTools/` cannot carry a stapled ticket** (standalone binaries can't be stapled), so first use may depend on an online notary lookup. | Medium | Test on a clean, **offline** Mac; prefer the bundled `SMAppService` layout (no out-of-bundle copy) where possible. |
| R10 | **macOS 26 `SMAppService` daemon XPC failures** reported by developers (forum thread 813148, content `UNVERIFIED`). | Medium | Reproduce on macOS 26 hardware early; consider the UNIX-socket + `LOCAL_PEERTOKEN` IPC variant (§1.1.5 option C) as a documented fallback; keep `SMJobBless` only for macOS ≤ 12. |
| R11 | **NE entitlement not obtainable / approval delays** (if the project ever pursues NE). | Medium | Do not make NE a dependency of the shipped architecture; keep the utun path primary. |
| R12 | `IP_BOUND_IF` behaviour on the transport socket is `UNVERIFIED` in combination with a utun default route. | Medium | Test the loop-avoidance path explicitly with the default route stolen by utun. |
| R13 | **Universal builds**: no fat output from the SDK, `lipo` invalidates signatures, and `deps.json` embeds a RID so a fat binary is internally inconsistent for one architecture. | High | Ship **two app bundles** for the first release (or per-RID subfolders + launcher); never ship the `--sign -` example output; verify both slices. |
| R13b | **A .NET helper cannot be installed by `SMJobBless`** unless single-file/self-contained (the framework copies one executable and synthesizes `ProgramArguments`). | Medium | Use `SMAppService` (bundle-resident, `BundleProgram`) as the primary path; only if macOS ≤ 12 support is required, ship the helper as self-contained single-file. |
| R14 | Helper attack surface (root). | High | Native helper, tiny command set, peer requirement validation on every connection (`xpc_connection_set_peer_team_identity_requirement`), no argv passthrough, no file operations driven by app input. |
| R15 | **Stale proxy settings survive a crash and a reboot** (SystemConfiguration preferences are persistent), blackholing every proxy-honouring app. | High | Journal the pre-change state on disk; mark MyVpn's own proxy values; repair from graceful exit, the XPC invalidation handler, and the next-launch repair pass. |
| R16 | **Silent misconfiguration of the kill switch** — a wrong utun name, or an anchor that is not attached, makes the switch silently stop applying. | High | Resolve the utun name at runtime; verify the loaded ruleset (`pfctl -sr`) *and*, for anchors, that the anchor is attached; live-monitor with `route -n monitor`; live-fire packet tests after every arm. |

---

## 4. Implementation plan

Phases are ordered so that each one is independently testable on real hardware, and so the riskiest
unknowns (`UNVERIFIED` items) are retired early.

**Phase 0 — platform spikes (must happen on real macOS hardware, Intel + Apple Silicon).**
1. Build a throwaway native helper that creates a utun, prints `UTUN_OPT_IFNAME`, and echoes packets.
   Retires: raw-utun-without-entitlement, fd handoff to an unprivileged reader, and which utun
   operations a non-root fd holder may perform.
2. Prove the kill switch: `pfctl -n -f -`, `pfctl -E` token capture, `pfctl -f -`, `pfctl -F states`,
   verify with `pfctl -sr` / `pfctl -s References`, `pfctl -X <token>`, and confirm Apple's anchors
   still work by running Apple's TN3165 test list (Internet Sharing, AirDrop, Continuity, Xcode
   device debugging over network and USB, Mac Virtual Display) plus a second `-E` holder.
   Also measure whether an in-flight flow is actually cut when the switch arms.
3. Prove routing both ways: (a) capture the default route, add the anti-loop host route, install the
   **def1 half-routes**, verify, tear down; (b) the same with `route change default`. Record which
   variant survives an interface flap and a SIGKILL, and whether the kernel's `if_rtdel` cleans up.
4. Prove DNS: `scutil --dns` before/after; whether a bare `State:/Network/Service/<id>/DNS` is
   honoured; whether adding `SupplementalMatchDomains` or a sibling `IPv4` dict with `InterfaceName`
   makes it effective; `/etc/resolver/` split DNS; and a leak test with an observing resolver that
   records the egress **interface**.
5. **Spike the per-process question and expect to reject it** (§1.4): try a `user`-scoped `route-to`
   into the utun, with `reply-to`, for TCP and UDP; measure what works, what breaks, and what happens
   to ICMP and to setuid/drop-privilege processes. The documented default outcome is "unreliable —
   do not ship"; the spike exists to make that an evidence-based decision, and to produce the test
   that proves the limitation to future maintainers.
6. Confirm `SMAppService` daemon registration end-to-end on 13/14/15/26, including the
   `requiresApproval` path, first-run from a quarantined `.dmg`/Downloads copy, and the macOS 26
   behaviour.
7. **Packaging spike:** build a universal bundle with `lipo` and settle the
   `deps.json`/`runtimeconfig.json` question (§1.8.7); confirm the notarized helper works on a clean,
   **offline** Mac; and confirm whether a folder-based .NET helper is usable under `SMJobBless`.

**Phase 1 — helper skeleton.**
6. Native `MyVpnHelper` with launchd plist, `BundleProgram`, `MachServices`, XPC listener, peer
   Team-ID requirement validation, structured command set (versioned protocol, typed messages).
7. .NET `MacOsPrivilegedHelperClient` using the XPC C API via `xpc_connection_send_message_with_reply_sync`
   (no blocks), with timeouts, reconnect on `XPC_ERROR_CONNECTION_INTERRUPTED`, and a health check.
8. Bundle assembly: helper in `Contents/Resources`, plist in `Contents/Library/LaunchDaemons`,
   inside-out signing script, `notarytool` + `stapler` in CI, `spctl`/`codesign --verify` gates.

**Phase 2 — tunnel data path.**
9. `ITunnelProvider` implementation: create utun, configure address/MTU, expose the fd; start
   xray-core unprivileged with the fd; verify TCP+UDP+ICMP through the tunnel, and DNS-over-UDP.

**Phase 3 — kill switch.**
10. Ruleset generator (parameterised by utun name, server table, LAN policy, IPv6 policy) with a
    `pfctl -n` dry-run gate in the helper; token management; original-ruleset snapshot/restore.
11. Fail-injection tests (kill the helper at each step; kill the app; pull the network cable).

**Phase 4 — routing + DNS.**
12. `IRouteManager` on PF_ROUTE/sysctl, with `route -n get default` cross-checks.
13. `IDnsConfigurator` with snapshot/restore, split DNS, flush, and a leak test harness.
14. Helper start-up journal replay (routes → DNS → PF → proxies, in the safe order).

**Phase 5 — proxy mode + honest per-process surface.**
15. `ISystemProxyManager` via `networksetup` (all-service snapshot, targeted change, full restore).
16. `IProcessRouter` with `SupportsIncludeByProcess = false`, UID block-list via PF, and UI copy that
    states the limitation. Explicitly no per-app routing claims.

**Phase 6 — packaging for both architectures.**
17. Universal build (lipo or twin bundles), both slices launched and smoke-tested, notarized,
    stapled, first-run from a quarantined `.dmg` verified.

---

## 5. Files / modules affected

Proposed (implementation lives outside this research doc; these are the modules the macOS work
touches):

| Path (proposed) | Responsibility |
| --- | --- |
| `src/MyVpn.Platform.MacOS/Interop/libXpc.cs` | P/Invoke surface for `xpc_connection_*`, `xpc_dictionary_*`, `xpc_fd_*`, peer-requirement setters. |
| `src/MyVpn.Platform.MacOS/Interop/libObjC.cs` | Only if option B (in-process `SMAppService`) is chosen: `objc_getClass`, `sel_registerName`, `objc_msgSend`. |
| `src/MyVpn.Platform.MacOS/Interop/ServiceManagement.cs` | `SMJobBless` P/Invoke (legacy fallback) and `kSMRightBlessPrivilegedHelper`. |
| `src/MyVpn.Platform.MacOS/Interop/Libc.cs` | `socket`, `connect`, `ioctl`, `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`, `setsockopt(IP_BOUND_IF)`. |
| `src/MyVpn.Platform.MacOS/PrivilegedHelperClient.cs` | `IPrivilegedHelper` implementation: status, install/approve flow, typed RPC. |
| `src/MyVpn.Platform.MacOS/Tunnel/UtunTunnelProvider.cs` | `ITunnelProvider`: utun lifecycle, fd handoff, interface config. |
| `src/MyVpn.Platform.MacOS/KillSwitch/PfKillSwitch.cs` | `IKillSwitch`: ruleset generation, `-E` token, snapshot/restore, server table. |
| `src/MyVpn.Platform.MacOS/KillSwitch/PfRulesetBuilder.cs` | Pure function: policy → `pf.conf` text. Unit-testable without root. |
| `src/MyVpn.Platform.MacOS/Routing/RouteManager.cs` | `IRouteManager`: PF_ROUTE/sysctl reads, helper-mediated writes, snapshot/restore. |
| `src/MyVpn.Platform.MacOS/Dns/DnsConfigurator.cs` | `IDnsConfigurator`: scutil parsing, per-service DNS, `/etc/resolver`, flush. |
| `src/MyVpn.Platform.MacOS/Routing/ProcessRouter.cs` | `IProcessRouter`: declared limitations + UID block-list. |
| `src/MyVpn.Platform.MacOS/Proxy/SystemProxyManager.cs` | `ISystemProxyManager`: networksetup wrapper with full-per-service snapshot/restore. |
| `src/MyVpn.Platform.MacOS/State/StateJournal.cs` | Crash-recovery journal (routes/DNS/PF/proxy). |
| `native/MyVpnHelper/` (Swift/ObjC/C) | Privileged daemon: XPC listener, peer validation, utun/route/DNS/PF syscalls. |
| `packaging/macos/Info.plist` | Bundle metadata; `SMPrivilegedExecutables` only if legacy fallback ships. |
| `packaging/macos/com.example.myvpn.helper.plist` | launchd daemon plist (`BundleProgram`, `MachServices`, `KeepAlive`). |
| `packaging/macos/MyVpn.entitlements` | Hardened-runtime entitlements (minimum set). |
| `packaging/macos/sign-and-notarize.sh` | Inside-out `codesign`, `notarytool`, `stapler`, verification. |
| `docs/research/08-macos-networking.md` | This document. |

---

## 6. Tests

**6.1 Unit-testable without macOS (runs on Linux CI).**

- `PfRulesetBuilder`: golden-file tests for the generated ruleset across the policy matrix
  (IPv6 on/off, LAN allow/deny, DNS strict/loose, multiple server IPs, UID block-lists). Assert the
  Apple anchor lines are always present and ordered correctly. Assert the final `block drop` is last.
- `scutil --dns` output parser: fixtures captured from Ventura/Sonoma/Sequoia/Tahoe, asserting
  resolver ordering, scoping and `if_index` extraction.
- `netstat -rn` / `route -n get default` parsers: fixtures for the interesting cases (multiple
  defaults, `-ifscope` routes, IPv6 link-local, utun present/absent).
- XPC message codec: round-trip encode/decode, version negotiation, malformed input rejection.
- `ProcessRouter` capability contract test: asserts `SupportsIncludeByProcess == false` and that
  every public method documents its limitation string.
- `StateJournal`: crash-point simulation — replay from every journal state must converge to DOWN.

**6.2 Integration tests (require a real macOS machine; run in a VM/CI runner per OS version).**

- Helper install/approve/uninstall on 13, 14, 15, 26 (Intel and Apple Silicon), including the
  `requiresApproval` path and re-approval after an OS upgrade.
- Peer validation: a rogue client (different Team ID / unsigned) must be rejected
  (`XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT` / connection invalid); a same-Team-ID client accepted.
- utun bring-up: interface name read back, MTU correctness, address assignment, packet round-trip
  TCP/UDP/ICMP, IPv6 behaviour with `BlockIpv6`.
- Kill switch: with the tunnel up, from a *separate* process, attempt (a) direct IPv4 to a public
  address, (b) direct DNS to 8.8.8.8, (c) IPv6 to a public address, (d) LAN access per policy —
  each must be blocked/allowed exactly per policy. Verify Apple anchors still evaluate (enable
  Internet Sharing and check it still works).
- **Kill-switch state flush**: open a long-lived flow through the physical interface *before* arming
  the tunnel, then arm; assert the flow is actually cut (`pfctl -F states` was effective) rather than
  continuing to pass on stale state.
- **Kill-switch non-invasiveness**: run Apple's TN3165 test list with the switch armed — Internet
  Sharing, AirDrop, Continuity, Xcode device debugging (network *and* USB), Mac Virtual Display — and
  assert each still works.
- PF coexistence: simulate a second product using `pfctl -E` (and the Application Firewall, which owns
  `com.apple/250.ApplicationFirewall`); assert our `-X` does not disable PF for it and vice versa, and
  that `pfctl -s References` correctly lists both holders while we are armed.
- Route restore: kill the helper with SIGKILL at each state-machine step; assert the machine
  recovers connectivity after the helper restarts, and that `route -n get default` matches the
  pre-VPN capture. Repeat using def1 half-routes and using `route change default`, and confirm the
  kernel's `if_rtdel` cleanup on interface disappearance in both cases.
- **Interface flapping**: bring the physical interface down/up while the tunnel is up; assert recovery.
- DNS: leak test with a private observation resolver that records the egress **interface** — assert
  zero queries escape outside the tunnel for the tested app set; split-DNS test via `/etc/resolver/`;
  test the `SupplementalMatchDomains` and sibling-`IPv4`-with-`InterfaceName` variants; verify
  `scutil --dns` shows tunnel-scoped resolvers; verify restore.
- Proxy mode: set/restore across Wi-Fi→Ethernet service switches; assert a stale proxy is never left
  behind after SIGKILL; and **assert repair after a simulated reboot with a stale proxy installed**
  (this is a persistence bug, not a transient one).
- Per-process honesty test: attempt to route only one app through the tunnel via every public
  mechanism — including a `user`-scoped `route-to` — and assert that the *documented* limitation
  holds (this test documents the platform and prevents a future engineer from "fixing" the limitation
  with something unreliable).

**6.3 Packaging tests.**

- `codesign --verify --strict` and `spctl -a -vvv` on both architecture slices.
- **Entitlement assertions** (fail the build if violated): `codesign -d --entitlements -` must show
  `com.apple.security.cs.allow-jit` on the apphost/helper and must **not** print `bplist00`, must not
  contain `get-task-allow`, `cs.debugger`, `allow-unsigned-executable-memory`,
  `disable-library-validation`, `allow-dyld-environment-variables`, or
  `disable-executable-page-protection`.
- **Hardened-runtime assertion**: `codesign -dvv` output must contain `flags=0x10000(runtime)` and a
  `Timestamp=` (not `Signed Time`) for the app, the helper, and the apphost — i.e. the
  `--options`-after-`--sign` trap did not fire.
- Stapled ticket validates offline (`stapler validate`); the notarization log is archived as a build
  artefact and scanned for the known failure strings.
- **The installed helper works on a clean, offline machine** (this is the `/Library/PrivilegedHelperTools`
  ticket question).
- Launch from a quarantined copy in `~/Downloads` and from a read-only `.dmg` mount; assert paths
  resolve (no translocation surprises) and the helper registers.
- Universal-bundle smoke test launching both slices explicitly (`arch -x86_64` / `arch -arm64`), or —
  if twin bundles are shipped — that the correct bundle is selected on each architecture.

**6.4 Manual/exploratory (documented, not automated).**

- Two VPN products installed simultaneously (WireGuard + MyVpn): utun index sharing, PF
  coexistence, route ownership.
- macOS upgrade with MyVpn installed: extension/helper re-approval behaviour in the target release.
- Airplane-mode / Wi-Fi→Ethernet switch while the tunnel is up.

---

## Appendix A — Source list

Everything below was retrieved during this research (2026-09-16) unless marked otherwise.

### A.1 Apple documentation — privileged helper, Network Extension, XPC, code signing

- `SMAppService` — <https://developer.apple.com/documentation/servicemanagement/smappservice>
- `SMAppService.Status` — <https://developer.apple.com/documentation/servicemanagement/smappservice/status-swift.enum>
- `SMAppService.daemon(plistName:)` — <https://developer.apple.com/documentation/servicemanagement/smappservice/daemon(plistname:)>
- `SMJobBless(_:_:_:_:)` (deprecated at macOS 13.0, *"Please use SMAppService instead"*) — <https://developer.apple.com/documentation/servicemanagement/smjobbless(_:_:_:_:)>
- Updating helper executables from earlier versions of macOS — <https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos>
- Updating your app package installer to use the new Service Management API — <https://developer.apple.com/documentation/servicemanagement/updating-your-app-package-installer-to-use-the-new-service-management-api>
- `SMPrivilegedExecutables` — <https://developer.apple.com/documentation/bundleresources/information-property-list/smprivilegedexecutables>
- `SMAuthorizedClients` — <https://developer.apple.com/documentation/bundleresources/information-property-list/smauthorizedclients>
- Network Extensions Entitlement (incl. the `*-systemextension` values and the Developer ID provisioning-profile steps) — <https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension>
- Personal VPN Entitlement — <https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.vpn.api>
- `NEPacketTunnelProvider` — <https://developer.apple.com/documentation/networkextension/nepackettunnelprovider>
- `NETunnelProvider` — <https://developer.apple.com/documentation/networkextension/netunnelprovider>
- `NETunnelProvider.appRules` (read-only) — <https://developer.apple.com/documentation/networkextension/netunnelprovider/apprules>
- `NETunnelProviderRoutingMethod` — <https://developer.apple.com/documentation/networkextension/netunnelproviderroutingmethod>
- `NETunnelProviderProtocol` — <https://developer.apple.com/documentation/networkextension/netunnelproviderprotocol>
- `NEVPNProtocol` (`includeAllNetworks`, `enforceRoutes`, `excludeLocalNetworks`, `excludeAPNs`, `excludeCellularServices`) — <https://developer.apple.com/documentation/networkextension/nevpnprotocol>
- `NEAppRule` — <https://developer.apple.com/documentation/networkextension/neapprule>
- `NEFilterDataProvider` — <https://developer.apple.com/documentation/networkextension/nefilterdataprovider>
- `NETransparentProxyProvider` — <https://developer.apple.com/documentation/networkextension/netransparentproxyprovider>
- `NETransparentProxyManager` — <https://developer.apple.com/documentation/networkextension/netransparentproxymanager>
- `NETransparentProxyNetworkSettings` — <https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings>
- `kSecGuestAttributeAudit` — <https://developer.apple.com/documentation/security/ksecguestattributeaudit>
- `SecRequirementCreateWithString(_:_:_:)` — <https://developer.apple.com/documentation/security/secrequirementcreatewithstring(_:_:_:)>
- Placing content in a bundle — <https://developer.apple.com/documentation/bundleresources/placing-content-in-a-bundle>
- Creating distribution-signed code for macOS — <https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac>
- Using the latest code signature format — <https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format>
- Packaging Mac software for distribution — <https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution>
- Signing a daemon with a restricted entitlement — <https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement>
- Notarizing macOS software before distribution — <https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution>
- Customizing the notarization workflow — <https://developer.apple.com/documentation/security/customizing-the-notarization-workflow>
- Resolving common notarization issues — <https://developer.apple.com/documentation/security/resolving-common-notarization-issues>
- Hardened Runtime — <https://developer.apple.com/documentation/security/hardened-runtime>
- Entitlements: `com.apple.security.cs.allow-jit`, `…allow-unsigned-executable-memory`, `…allow-dyld-environment-variables`, `…disable-library-validation`, `…disable-executable-page-protection`, `…debugger` — <https://developer.apple.com/documentation/bundleresources/entitlements/…>
- *What's New in macOS 10.12* (translocation) — <https://developer.apple.com/library/archive/releasenotes/MacOSX/WhatsNewInOSX/Articles/OSXv10.html>

### A.2 Apple technotes

- **TN3165 — "Packet Filter is not API"** (2024-02-27) — <https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api> (raw markdown: `…/tn3165-packet-filter-is-not-api.md`)
- TN3134 — Network Extension provider deployment (referenced by TN3165) — <https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment>
- TN3147 — Migrating to the latest notarization tool — <https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool>
- TN3126 — Inside Code Signing: Hashes — <https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes>
- TN3127 — Inside Code Signing: Requirements — <https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements>
- TN2206 — macOS Code Signing In Depth (archived) — <https://developer.apple.com/library/archive/technotes/tn2206/_index.html>
- System Integrity Protection Guide → File System Protections (archived) — <https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/FileSystemProtections/FileSystemProtections.html>
- System Configuration Programming Guidelines → The System Configuration Schema — <https://developer.apple.com/library/archive/documentation/Networking/Conceptual/SystemConfigFrameworks/SC_UnderstandSchema/SC_UnderstandSchema.html>

### A.3 Apple open source

- XNU `bsd/net/if_utun.c` (utun kernel control; `CTL_FLAG_PRIVILEGED … /* Require root */`; `UTUN_HEADER_SIZE`; `kauth_cred_issuser` gate; `necp_get_app_uuid_from_packet`) — <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.c>
- XNU `bsd/net/if_utun.h` (`UTUN_CONTROL_NAME`, `UTUN_OPT_*`, `UTUN_FLAGS_*` incl. `UTUN_FLAGS_ENABLE_PROC_UUID 0x0004`) — <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.h>
- XNU `bsd/netinet/in.h` (`IP_BOUND_IF 25`, `IP_PKTINFO 26`) — <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/netinet/in.h>
- XNU `bsd/netinet/in_pcb.c` (`inp_bindif`, `inp_bindif_common`, `inp_bindtodevice` — no privilege check) — <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/netinet/in_pcb.c>
- XNU `bsd/sys/un.h` (`LOCAL_PEERCRED 0x001` … `LOCAL_PEERTOKEN 0x006 /* retrieve peer audit token */`) — <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/un.h>
- XNU `bsd/net/pf_ioctl.c` (token generation, `DIOCSTARTREF`/`DIOCSTOPREF`, `DIOCSTOP` invalidating all tokens, `pfinit()` creating `/dev/pf`) — <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/pf_ioctl.c>
- XNU `bsd/net/pf_if.c` (`pfi_kif_get()` creating an entry for a not-yet-existing interface) — <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_if.c>
- XNU `bsd/net/if.c` (`if_rtdel`, `if_rtproto_del` — deleting routes for a detaching interface) — <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if.c>
- `configd` `scutil.tproj/commands.c` (the authoritative `scutil` interactive command table and the `*#?%` type sigils) — <https://github.com/apple-oss-distributions/configd/blob/main/scutil.tproj/commands.c>
- `configd` `Plugins/IPMonitor/dns-configuration.c` (wildcard service enumeration; `add_supplemental()` requiring `SupplementalMatchDomains`; `add_scoped_resolvers()` using `InterfaceName`; `primaryDNS`) — <https://github.com/apple-oss-distributions/configd/blob/main/Plugins/IPMonitor/dns-configuration.c>
- `configd` `dnsinfo/dnsinfo.h` (`dns_resolver_t`, `DNS_RESOLVER_FLAGS_*`), `dnsinfo_logging.h` (`scutil --dns` field names), `dnsinfo_create.c`
- `configd` `SystemConfiguration.fproj/SCSchemaDefinitions.h` (the proxy key constants), `SCPreferences.h` (`SCPreferencesCommitChanges` / `ApplyChanges`), `SCNetworkConfigurationPrivate.h` (`kSCNetworkServicePrimaryRankFirst`)
- mDNSResponder `mDNSMacOSX/mDNSMacOSX.c` (`setsockopt(…, IP_BOUND_IF, &ifindex, …)`) — <https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-878.200.35/mDNSMacOSX/mDNSMacOSX.c>
- Security `SecTranslocate.h` (the four-rule translocation policy; `AppTranslocation/<UUID>)` path form) — <https://raw.githubusercontent.com/apple-oss-distributions/Security/rel/Security-59754/OSX/libsecurity_translocate/lib/SecTranslocate.h>
- Absence of `bsd/netinet/ip_fw2.c` from current XNU (HTTP 404) — <https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/netinet/ip_fw2.c>

### A.4 Man pages (macOS / Xcode set, via the keith.github.io mirror)

- `pfctl(8)` — <https://keith.github.io/xcode-man-pages/pfctl.8.html>
- `pf.conf(5)` — <https://keith.github.io/xcode-man-pages/pf.conf.5.html>
- `route(8)` — <https://keith.github.io/xcode-man-pages/route.8.html>
- `route(4)` — <https://keith.github.io/xcode-man-pages/route.4.html>
- `netstat(1)` — <https://keith.github.io/xcode-man-pages/netstat.1.html>
- `resolver(5)` — <https://keith.github.io/xcode-man-pages/resolver.5.html>
- `ip(4)` — <https://keith.github.io/xcode-man-pages/ip.4.html> (does **not** document `IP_BOUND_IF`)
- `xpc_connection_create(3)` — <https://keith.github.io/xcode-man-pages/xpc_connection_create.3.html>
- `networksetup(8)` — <https://keith.github.io/xcode-man-pages/networksetup.8.html>
- `scutil(8)` — <https://keith.github.io/xcode-man-pages/scutil.8.html>
- `dscacheutil(1)` — <https://keith.github.io/xcode-man-pages/dscacheutil.1.html>
- `launchd.plist(5)` — <https://keith.github.io/xcode-man-pages/launchd.plist.5.html>
- `codesign(1)` — <https://keith.github.io/xcode-man-pages/codesign.1.html>
- `notarytool(1)` — <https://keith.github.io/xcode-man-pages/notarytool.1.html>
- `stapler(1)` — <https://keith.github.io/xcode-man-pages/stapler.1.html>
- `spctl(8)` — <https://keith.github.io/xcode-man-pages/spctl.8.html>
- `syspolicy_check(1)` — <https://keith.github.io/xcode-man-pages/syspolicy_check.1.html>
- `xattr(1)` — <https://keith.github.io/xcode-man-pages/xattr.1.html>

### A.5 Microsoft / .NET

- Publish .NET apps for macOS (the `allow-jit` requirement; the manual `lipo` recipe) — <https://learn.microsoft.com/en-us/dotnet/core/deploying/macos>
- macOS Catalina notarization and the impact on .NET — <https://learn.microsoft.com/en-us/dotnet/core/install/macos-notarization-issues>
- `dotnet/runtime` `src/coreclr/minipal/Unix/doublemapping.cpp` (`IsMapJitFlagNeeded`, `MAP_JIT`) — <https://github.com/dotnet/runtime/blob/main/src/coreclr/minipal/Unix/doublemapping.cpp>
- `dotnet/runtime` `src/coreclr/inc/clrconfigvalues.h` @ `release/8.0` (`EnableWriteXorExecute` default 1) — <https://github.com/dotnet/runtime/blob/release/8.0/src/coreclr/inc/clrconfigvalues.h>
- `dotnet/macios` `dotnet/BundleContents.md` (the `Contents/MonoBundle` model for `net*-macos`) — <https://raw.githubusercontent.com/dotnet/macios/main/dotnet/BundleContents.md>
- Universal-binary context (titles verified, bodies not retrieved): <https://github.com/dotnet/sdk/issues/33469>, <https://github.com/dotnet/docs/issues/37220>, <https://github.com/dotnet/macios/issues/19391>, <https://github.com/dotnet/runtime/issues/113707>

### A.6 Avalonia

- macOS deployment — <https://docs.avaloniaui.net/docs/deployment/macos> (note: its layout guidance contradicts itself; see §1.8.1)
- macOS platform guide (`libAvaloniaNative.dylib`; Avalonia does not use the .NET macOS workload) — <https://docs.avaloniaui.net/docs/platform-specific-guides/macos>
- **Avalonia Parcel — packaging for macOS** (the most directly applicable tool for this stack) — <https://docs.avaloniaui.net/tools/parcel/packaging-for-macos>

### A.7 Shipping implementations used as evidence of practice

- Mullvad `talpid-core/src/firewall/macos.rs` (PF rules, `route-to`, state flush on transition) — <https://github.com/mullvad/mullvadvpn-app/blob/a2583edcb7c275064c20f6d02db291f36af82d94/talpid-core/src/firewall/macos.rs>
- Mullvad `pfctl-rs` (direct `/dev/pf` `DIOCSTART`/`DIOCSTOP`, save/restore of prior enabled state) — <https://docs.rs/pfctl/0.7.0/src/pfctl/lib.rs.html>
- OpenVPN manual, `--redirect-gateway` / `def1` — <https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/vpn-network-options.rst>
- OpenVPN `distro/dns-scripts/macos-dns-updown.sh` (`State:/Network/Service/openvpn-${dev}/DNS`, `DnsBackup`, `SupplementalMatchDomains`) — <https://github.com/OpenVPN/openvpn/blob/master/distro/dns-scripts/macos-dns-updown.sh>
- WireGuard `wg-quick` Darwin (def1 half-routes, `-blackhole` loop prevention, "routes are deleted automatically on device shutdown", per-service DNS snapshot) — <https://github.com/WireGuard/wireguard-tools/blob/master/src/wg-quick/darwin.bash>
- Tunnelblick (`State:/Network/OpenVPN/OldDNS`; "the DNS settings won't actually be used by macOS unless the SupplementalMatchDomains key is added"; dual DNS flush) — <https://github.com/Tunnelblick/Tunnelblick/blob/master/tunnelblick/client.2.up.tunnelblick.sh>
- vpnc-script (`State:/Network/Service/$TUNDEV/DNS`, `OverridePrimary # 1`) — <https://github.com/cloudflare/vpnc-scripts/blob/master/vpnc-script>
- `vpn-kill-switch` Rust crate (main-ruleset replace + `pfctl -Fa -f /etc/pf.conf` restore) — <https://docs.rs/crate/vpn-kill-switch/0.8.3/source/src/killswitch/pf.rs>
- tuist PR #11425 ("load pf anchor directly (macOS firewall install fails reloading whole pf.conf)") — <https://github.com/tuist/tuist/pull/11425>

### A.8 Secondary / community sources (context only — never the sole basis for a claim)

- Ask Different 451252 (stock `/etc/pf.conf` text) — <https://apple.stackexchange.com/questions/451252/internet-connection-is-disabled-after-updating-the-pf-conf-file>
- Ask Different 430415 (Internet Sharing's dynamic `com.apple.internet-sharing` anchor) — <https://apple.stackexchange.com/questions/430415/source-of-pf-anchor-com-apple-internet-sharing-all>
- Ask Different 219261 (natd/ipfw deprecated in El Capitan) — <https://apple.stackexchange.com/questions/219261>
- FreeBSD bug 287462 (a not-yet-existing interface in a PF rule is accepted by design) — <https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=287462>
- Mike Wilson, "Notes on MacOS pfctl" (translation rules cannot match `user`/`group`; DNS attributed to `_mdnsresponder`) — <https://amikewilson.com/2023/09/11/notes-on-pfctl>
- zenn.dev report on `set skip` inside an anchor and dynamic utun numbering — <https://zenn.dev/i0/articles/c59917b9270925>
- "macOS Sequoia Network Changes: An Updated Guide" — <https://ova.productdevbook.com/blog/macos-sequoia-network-changes>
- Apple Support, "Reset the DNS cache" (body not fetchable) — <https://support.apple.com/en-us/101481>

### A.9 Sources identified but NOT retrievable

Apple Developer Forums served an anti-bot verification page for every thread attempted during this
research, and the GitHub API rate-limited from this runner. **Nothing is attributed to these beyond
their existence and titles; their content is `UNVERIFIED`.**

- <https://developer.apple.com/forums/thread/813148> — failing XPC connection to an `SMAppService`-based LaunchDaemon on some macOS 26 Macs.
- <https://developer.apple.com/forums/thread/816877> — approval process for the Network Extension entitlement.
- <https://developer.apple.com/forums/thread/786886> — entitlement request support / `-systemextension` suffixes.
- <https://developer.apple.com/forums/thread/812271> — "macOS Tahoe: IPMonitor incorrectly re-ranks interfaces causing VPN DNS leaks".
- <https://developer.apple.com/forums/thread/744791> — `SecCodeCopyGuestWithAttributes` + audit token returning `100001`.
- <https://developer.apple.com/forums/thread/724969> — App Translocation notes.
- <https://developer.apple.com/forums/thread/812190> — component package and notarization of helper executables.

## Appendix B — Explicit `UNVERIFIED` register

Items 1, 8, 9 (partly), 11, 12, 13, 15, 16, 17, 19 from the first draft have been **retired** with
primary sources. What remains, in priority order:

**Blocking — must be closed on real hardware before shipping**
1. **Universal build `deps.json`/`runtimeconfig.json`.** A self-contained `deps.json` embeds the RID in
   `runtimeTarget`; no supported merge was found and the host's tolerance for a mismatch is unknown.
   *Highest-risk unknown in the packaging plan.* Mitigation: ship two app bundles.
2. **Whether raw utun creation truly needs no entitlement.** Apple documents no positive statement;
   the gate observed in XNU source is Unix privilege (`CTL_FLAG_PRIVILEGED`, `kauth_cred_issuser`).
   Verify on a Developer ID build on a stock machine.
3. **Which utun operations remain permitted for a non-root process holding an fd created by root**
   (reading/writing the control socket, `ioctl(SIOCSIFADDR)`, MTU). Central to the fd-handoff design.
4. **Whether a folder-based .NET helper can be installed by `SMJobBless`** (single-executable copy +
   synthesized `ProgramArguments`). If not, SMAppService is the only viable path for a .NET helper.
5. **Whether the `/Library/PrivilegedHelperTools/` copy is accepted offline** (standalone binaries
   cannot be stapled; verification depends on the online notary lookup).
6. **`.NET` under launchd**: `HOME`/`TMPDIR`/`PATH`/cwd/`DOTNET_ROOT`, `launchctl bootstrap/bootout/
   kickstart` semantics, and whether `PublishSingleFile` loads an unsigned Mach-O at runtime (which
   would force `disable-library-validation`).
7. **PF `user`-scoped `route-to` as a per-process routing mechanism.** Syntactically possible and
   documented, but directional-only, no source-address rewrite, needs a valid point-to-point next hop,
   and unproven. This is the Phase-0 spike whose default outcome is "rejected".
8. **Whether writing `State:/Network/Service/<arbitrary-id>/DNS` with only `ServerAddresses`, on a
   non-primary service and with no `SupplementalMatchDomains`, is ever consulted.** Strong inference
   from `dns-configuration.c` that it is not.

**Important — affects design details**
9. Whether a manual Apple approval step is required, beyond capability enablement + provisioning
   profile, to obtain `com.apple.developer.networking.networkextension` for Developer ID.
10. Whether the app-extension form of `NEPacketTunnelProvider` is still accepted for Developer ID on
    macOS 15/26, or whether the system-extension form is mandatory.
11. Whether `SMAppService` registration from a *translocated* path is refused.
12. Whether PF states the exact wording/behaviour of `pfctl -sr` round-tripping, and whether reloading
    `/etc/pf.conf` disrupts a service that had dynamically inserted anchors.
13. Whether `com.apple/<name>` anchor evaluation is guaranteed on all in-scope macOS versions (the
    anchor-based kill-switch alternative's fail-open risk).
14. Whether `SCNetworkServiceSetPrimaryRank`/`kSCNetworkServicePrimaryRankFirst` is public API
    (it lives in `SCNetworkConfigurationPrivate.h`).
15. Whether `SCNetworkProtocolCreate` exists at all (not found in Apple's open-source headers).
16. `/etc/resolver/<domain>` vs dynamic-store `SupplementalMatchDomains` precedence for the same
    domain; and whether macOS 26 ignores `/etc/resolver` for non-standard TLDs.
17. Exact `networksetup` behaviour for clearing DNS/servers (documented tokens are lowercase `empty`
    for DNS and `Empty` for bypass domains; case-insensitivity is unverified), the sentence printed by
    `-getdnsservers` when empty, and link-local IPv6 nameserver syntax (scope id).
18. Deprecation status of `dscacheutil -flushcache` and the current wording of Apple's "Reset the DNS
    cache" article.
19. `xpc_fd_create`/`xpc_dictionary_set_fd` exact man-page reference (the API family is public; the
    specific page was not fetched). `xpc_connection_get_audit_token` is **SPI**.
20. Whether `PublishReadyToRun` output can be merged for a universal build (R2R is native code, so
    per-architecture; assumed not mergeable).
21. Exact macOS release in which the `ipfw` binary was removed (deprecation in 10.11 and absence from
    current XNU are verified).
22. `file://` PAC reliability across Safari/Chrome/Electron and sandboxed apps — recommend serving PAC
    over loopback HTTP instead.
23. Firefox/Java/Electron system-proxy behaviour against their own current documentation.
24. Whether `NSPrincipalClass` is needed at all for an Avalonia app (Avalonia's own template omits it).
25. The exact modern `spctl` output string (`source=Notarized Developer ID`) and the first-launch
    dialog wording.
26. `Content Caching`'s use of PF — no evidence found; the common claim is unsupported.
27. Exactly which utun/`UTUN_OPT_*` privileges apply when the device was created by root and used by
    another uid, and `UTUN_FLAGS_ENABLE_PROC_UUID`'s practical usefulness (NECP is internal).
28. macOS 26 `SMAppService` daemon XPC stability (forum report, unread).
29. Whether a user-installed (non-MDM) configuration profile can enable per-app VPN on an unmanaged
    Mac.

