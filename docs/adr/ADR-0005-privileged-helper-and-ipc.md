# ADR-0005 — Privileged helper and local IPC

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —
- **Implementation status:** Planned. `MyVpn.Service`, `MyVpn.Ipc`, and the
  platform projects contain no source yet. The architectural rule is already
  stated in `src/MyVpn.Service/MyVpn.Service.csproj` and
  `src/MyVpn.Ipc/MyVpn.Ipc.csproj`.

## Context

Every privileged operation MyVpn needs — creating the TUN device, installing
routes, configuring DNS, arming the kill switch, moving processes into a cgroup
— requires elevation on all three platforms:

* **Linux:** `CAP_NET_ADMIN` to create network devices
  (`Documentation/networking/tuntap.txt` §2), to load nftables rules and to
  change routes; `CAP_NET_RAW` for `SO_BINDTODEVICE`. Creating
  `/sys/fs/cgroup/myvpn.slice` requires write access to a root-owned cgroup
  directory.
* **Windows:** `FwpmFilterAdd0` and the other WFP management calls require
  `FWPM_ACTRL_*` rights; `CreateIpForwardEntry2`, `SetIpInterfaceEntry` and
  `CreateUnicastIpAddressEntry` are Administrators-only; creating a Wintun
  adapter and registering its rings requires elevation (the device DACL is
  reported to admit only `S-1-5-18` and `S-1-5-32-544` — **UNVERIFIED**, derived
  by decoding the shipped binary rather than from documentation, but
  design-critical and to be confirmed in a hardware spike).
* **macOS:** creating a utun requires root — XNU registers the
  `com.apple.net.utun_control` kernel control with `CTL_FLAG_PRIVILEGED`
  (`bsd/net/if_utun.c`), and the privileged `UTUN_OPT_*` setopts are gated by
  `kauth_cred_issuser(...) == 0`.

The prior art shows two failure modes to avoid. v2rayN (a) elevates the whole
flow by elevating the GUI on Windows, and (b) on Linux/macOS writes a shell
script into a **user-writable** config directory and pipes the sudo password to
it, holding that password in a process-wide singleton. Its own fix for issue
#9765 interpolates `KEY="VALUE"` into that script with a quoting helper that
does not escape `"`, backtick, `$`, `\` or `$( )` — a root command injection
primitive reachable from a path containing those characters, and macOS state
paths contain spaces.

The design constraint is therefore: **the GUI must never be elevated, and the
privileged surface must be narrow, typed, authenticated and auditable.**

## Decision

### The UI never runs elevated

`MyVpn.UI` performs no privileged or network-mutating operation. It talks only
to `IMyVpnServiceFacade`, which is either an in-process facade (proxy-only,
unprivileged mode) or the IPC-backed facade (TUN / kill-switch mode). The
privileged work lives in `MyVpn.Service`: a system service on Windows, a systemd
system unit on Linux, a privileged launchd daemon on macOS.

### The IPC surface is a closed, typed command set

The wire contract carries **commands, not capabilities**. There is no
"run this command", no "apply this raw config", no "install this route with
these raw parameters", no arbitrary file path, no shell string, and no
`argv` passthrough. Concretely, the service exposes things like *connect profile
X under plan Y*, *disconnect*, *status*, *set kill-switch mode*, *set
split-tunnel destination list*; the service re-derives the full plan from the
typed request. A compromised or spoofed client therefore cannot obtain code
execution or an arbitrary firewall payload from the service.

Every request is validated against its schema before it reaches a kernel call,
message sizes are capped, and every operation has a timeout and a
`CancellationToken`. `MyVpn.Ipc` is deliberately dependency-free (Core only) so
the contract is auditable in isolation.

### Authentication is per connection and peer-credential-based

**Windows.** Named pipe created with an **explicit DACL** via
`NamedPipeServerStreamAcl.Create` — `PipeSecurity` cannot be passed to a
`NamedPipeServerStream` constructor on .NET Core (that overload is
Framework-only), and `PipeOptions.CurrentUserOnly` **silently ignores** a
supplied `PipeSecurity`, so exactly one of the two strategies is used per side
and it is documented. The DACL grants `SYSTEM` and `BUILTIN\Administrators`
full control and the interactive user read/write **without**
`FILE_CREATE_PIPE_INSTANCE` (note `FILE_GENERIC_WRITE` implies that bit, so
individual rights are granted rather than generic write); there is no
`Everyone`/`ANONYMOUS` ACE. The first instance is created at service start with
`FILE_FLAG_FIRST_PIPE_INSTANCE` (`PipeOptions.FirstPipeInstance`) and
`PIPE_REJECT_REMOTE_CLIENTS`, and a name-squatting failure is a hard, logged
failure rather than silent fallback.

On **every** new connection — never cached for the life of a long-lived
connection — the service runs the documented sequence:

1. `GetNamedPipeClientProcessId` to obtain a PID (a PID, not a handle).
2. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` **immediately**, and hold
   the handle; all later checks use the handle, never the PID, because PIDs are
   reused by the system.
3. `QueryFullProcessImageNameW` to obtain the image path; compare against an
   allow-list of exactly the signed install directory (canonicalised, symlinks
   and junctions rejected, case-insensitive).
4. `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`, `WTD_UI_NONE`,
   `WTD_REVOKE_WHOLECHAIN`, `WTD_CHOICE_FILE`; success is exactly `== 0`.
5. `OpenProcessToken` + `GetTokenInformation` for `TokenUser`,
   `TokenSessionId`, `TokenIntegrityLevel`, `TokenElevationType`.
6. Compare `TokenSessionId` against an active session
   (`WTSEnumerateSessionsW` / `WTSGetActiveConsoleSessionId`) so a fast-user-switch
   or RDP session cannot drive another user's tunnel.

`ALE_APP_ID` is a **path**, not an identity, so the Authenticode check and the
restrictive install-directory ACL are what make the path check meaningful.
The service account is `LocalSystem` with
`SERVICE_SID_TYPE_UNRESTRICTED`: `SERVICE_SID_TYPE_RESTRICTED` adds the
write-restricted SID `S-1-5-33`, which is very likely absent from the Wintun
device DACL and would therefore break `TUN_IOCTL_REGISTER_RINGS` (premise
**UNVERIFIED**; confirmed in the hardware spike before the account decision is
frozen). Compensating controls: the typed command set, the per-connection gate,
a locked-down SCM descriptor via `sc sdset`, and an install directory ACL'd to
Administrators/SYSTEM.

**Linux.** A systemd **system** service plus D-Bus plus polkit, not `pkexec`
(see alternatives). The service owns `org.mylvpn.Helper1` on the system bus; an
`/etc/dbus-1/system.d` policy file grants `send_destination` only to the
intended group and denies others (coarse gate), and every **mutating** method is
additionally gated by a polkit action check inside the daemon, using the
caller's **unique bus name** as the subject so the UID comes from the bus daemon
and never from a method argument. Read-only methods (`Status`, `GetStats`) are
allowed without authorization so the tray can poll cheaply. The unit sets:

```ini
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RuntimeDirectory=myvpn
StateDirectory=myvpn
ReadWritePaths=/run/myvpn /var/lib/myvpn
```

`ProtectControlGroups=no` is a deliberate, documented hole: the helper must
create a cgroup and move processes into it (ADR-0007). `ProtectSystem=strict`
plus explicit `ReadWritePaths=` keeps the daemon from writing anywhere but its
own runtime and state directories. Xray runs as its own unit so the helper's
sandbox is not inherited by the core.

**macOS.** `SMAppService` (macOS 13+) rather than `SMJobBless` (deprecated at
13.0). The helper executable lives **inside** the app bundle at
`Contents/Resources/`, with the launchd plist at
`Contents/Library/LaunchDaemons/` using `BundleProgram` (bundle-relative)
instead of `Program`, and `MachServices` publishing the XPC service name;
`KeepAlive` restarts the helper. The helper is signed with the **same Team ID**
as the app, and registration requires a user approval step
(`SMAppService.Status.requiresApproval` →
`openSystemSettingsLoginItems()`; never silently degrade).

The helper validates **every** inbound peer connection with the modern XPC peer
requirement APIs:
`xpc_connection_set_peer_team_identity_requirement(peer, "<TEAMID>")` and/or
`xpc_connection_set_peer_code_signing_requirement(...)`. Failures arrive as
`XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT`. Peer PID/EUID/ASID checking is
**rejected**: the man page states the legacy credential APIs are "inherently
insecure and should be avoided" (a client can pass its connection port to a
process with different credentials), and "PIDs on macOS roll over when they
reach a relatively small value, and a given PID cannot be assumed to be unique
for a given boot session".

Because a .NET process cannot act as an XPC **listener** without synthesising a
global block (ABI-fragile and unsupported), the decision is: ship a small native
helper (Swift/ObjC/C) that owns the XPC listener and the privileged syscalls,
with the Avalonia/.NET app as a pure XPC **client** using the documented
`xpc_connection_create_mach_service` +
`xpc_connection_send_message_with_reply_sync` C API — neither of which needs a
block. A second option (UNIX-domain socket + `LOCAL_PEERTOKEN` audit token +
`SecCodeCopyGuestWithAttributes`/`SecCodeCheckValidity`) is the documented
fallback if XPC proves unstable (macOS 26 `SMAppService` daemon XPC failures
have been reported by developers, **UNVERIFIED**).

### Every privileged mutation is journaled and idempotent

Before each mutation the helper writes a state journal to disk
(`/run/myvpn` on Linux, the service's state directory on Windows, the daemon's
state directory on macOS) and, on start, replays restore **before** accepting
commands. On Linux, `ExecStopPost=` runs a `--cleanup` pass and a companion
oneshot unit provides a `PartOf=` teardown for the SIGKILL case. On macOS,
launchd's `KeepAlive` plus the start-up replay covers a crash. On Windows,
routes and interface DNS have no OS rollback, so the journal is the only
recovery mechanism. The kill switch is fail-closed by construction, so a crash
loses connectivity rather than leaking (ADR-0006).

### No shell, ever

Privileged launches pass an `argv` array and an explicit environment through
`ProcessStartInfo.ArgumentList` / `execve`-style APIs. No generated scripts, no
`sudo -E`, no string interpolation of paths, no password on stdin. The elevated
Xray process is a child of the service (Windows: Job Object kill-on-close;
Linux/macOS: a supervised unit, not a GUI child).

## Consequences

**Positive**

* One auditable privilege boundary per platform; the GUI, the config parser that
  consumes untrusted subscription data, and the core are unprivileged.
* The typed command set makes "the client asked for something dangerous" a
  compile-time/schema-time error rather than a runtime policy question.
* Per-connection, peer-credential-based authentication removes the PID-reuse,
  connection-passing and stale-authorisation classes.
* Journaled, idempotent cleanup is the only way to survive SIGKILL/crash on
  three platforms with no common rollback API.

**Negative / costs**

* More moving parts than "run Xray as root": a service, an IPC contract, an
  installer that registers the service, and per-platform peer authentication.
* The Windows service account decision carries an **UNVERIFIED** dependency on
  the Wintun device DACL; the hardware spike is a prerequisite, not a nicety.
* A native macOS helper means a second language/toolchain in the repository and
  an inside-out signing procedure.
* `ProtectControlGroups=no` on Linux is an intentional weakening of the sandbox.

**Deliberately not promised**

* That the client process is "not injected". With documented APIs we can verify
  owning user, session, image path, Authenticode signature and integrity level;
  in-memory tampering cannot be ruled out. This is stated in the code comments
  and in the security model in `README.md`.
* That a consumer/preview Windows build has `FwpmConnectionPolicyAdd0`
  (ADR-0007).

## Alternatives considered

* **Run the GUI elevated (v2rayN on Windows).** Rejected: the entire UI, every
  config parser and the whole dependency tree become a root attack surface, and
  a UI bug becomes a privilege bug.
* **`pkexec` as the runtime mechanism.** Rejected: `pkexec` is a one-shot
  privilege *launcher*, not a service. It execs a program and waits for exit;
  the privileged program's lifetime is not supervised, there is no restart
  policy, the GUI cannot reconnect, a new authentication prompt is needed per
  invocation, and it deliberately strips `$DISPLAY`/`$XAUTHORITY` so a GUI
  child is impossible. A tunnel + firewall owner must live across
  connect/disconnect/reconnect and own crash cleanup. `pkexec` remains
  acceptable only as an optional bootstrap to install/enable the service.
  (That it is unsuitable for long-running operations is **inferred** from the
  one-shot exec model; the man page does not say so verbatim.)
* **`sudo` with a password on stdin, driving a generated script (v2rayN on
  Linux/macOS).** Rejected: root command injection via unescaped path
  interpolation, a user-writable script executed as root, a password held in a
  process-wide singleton, and no cleanup guarantee.
* **`sudo -E` / `env_keep`.** Rejected: policy-dependent, and Mac/Linux
  maintainers reject it for exactly that reason.
* **ALPC (Windows).** Rejected. ALPC is not documented for third-party use:
  Win32's interprocess communications overview does not list it;
  `NtCreatePort`/`NtConnectPort`/`NtRequestPort`/`NtReplyPort`/… have no
  Learn API pages and are absent from the `winternl.h` header page; and
  Microsoft's standing warning is that `winternl.h` structures are "internal to
  the operating system and subject to change". A named pipe with an explicit
  DACL (or first-party gRPC over a named pipe) is supported and sufficient.
* **A setuid-root helper binary on Linux.** Rejected: setuid root is a far
  larger attack surface and requires defending the environment
  (`LD_PRELOAD`, `PATH`, inherited fds, `argv`) in the privileged process
  itself. A systemd-sandboxed daemon with a typed D-Bus interface plus polkit
  validation is strictly better.
* **Authenticate the Linux client by a UID passed as a method argument.**
  Rejected: forgeable. The UID is derived from the bus daemon's credentials for
  the caller's unique name.
* **`PipeOptions.CurrentUserOnly` *and* a custom `PipeSecurity`.** Rejected:
  mutually exclusive in practice — `CurrentUserOnly` silently ignores the
  supplied `PipeSecurity`. One strategy is chosen per side and documented.
* **Cache the Windows client-identity decision for the connection's lifetime.**
  Rejected: PID reuse and long-lived connections make it unsound; the gate
  re-runs per connection.
* **gRPC over a UNIX socket / named pipe.** Viable and first-party supported
  (`ListenNamedPipe`, `SocketsHttpHandler.ConnectCallback`,
  `UseNamedPipes(o => o.PipeSecurity = …)`). Kept as an implementation option for
  Windows (with the documented caveat that gRPC client-side load balancing and
  `GrpcChannel.State` cannot be used over named pipes, so readiness is tracked at
  the application level). Not required for Linux/macOS.

## References

* `docs/research/06-windows-networking.md` — §1.1 (WFP privileges and why not
  `INetFwPolicy2`), §1.3 (service hosting, named-pipe SD/DACL,
  `NamedPipeServerStreamAcl.Create`, the full peer-verification sequence, the
  PID-reuse warning, `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`,
  ALPC rejection, gRPC-over-pipes, `SERVICE_SID_TYPE_RESTRICTED` vs Wintun),
  §2.2 (service account decision and its UNVERIFIED premise).
* `docs/research/07-linux-networking.md` — §1.1 (TUN + `CAP_NET_ADMIN`), §1.4
  (cgroup v2 delegation), §1.6 (`pkexec` facts and its one-shot model), §2.5
  (D-Bus + polkit + systemd hardening, the polkit policy XML and the D-Bus
  policy file), §2.8 (FHS layout and the AppImage constraint), §3 R-6
  (privileged-helper attack surface).
* `docs/research/08-macos-networking.md` — §1.1 (`SMAppService` vs `SMJobBless`,
  bundle layout, `BundleProgram`, code-signing requirements,
  `xpc_connection_create` peer-requirement APIs and the PID caveat, the
  native-helper recommendation and the three alternatives), §1.2.1 (XNU
  `CTL_FLAG_PRIVILEGED` and `kauth_cred_issuser`), §2.1–§2.3 (process model,
  helper lifecycle, bring-up/tear-down state machine).
* `docs/research/02-issue-9765-geodata.md` §2.8 rule 3 and R1 — no shell, argv
  arrays, `IPrivilegedProcessLauncher`.
* Existing architecture: `src/MyVpn.Service/MyVpn.Service.csproj`,
  `src/MyVpn.Ipc/MyVpn.Ipc.csproj`, `src/MyVpn.UI/MyVpn.UI.csproj`
  (the UI-never-privileged rule),
  `src/MyVpn.Core/Results/ErrorCodes.cs` (`ipc.*`, `privilege.*`).
* Primary sources: `man 3 xpc_connection_create`
  (<https://keith.github.io/xcode-man-pages/xpc_connection_create.3.html>);
  `SMAppService` and `SMJobBless` documentation
  (<https://developer.apple.com/documentation/servicemanagement>);
  `fwpmu.h` / `Fwpuclnt.dll` and `netioapi.h` / `iphlpapi.dll` WFP and NetIO
  references (<https://learn.microsoft.com/windows/win32/fwp/>);
  `Documentation/networking/tuntap.txt`; `systemd.exec(5)`, `pkexec(1)`,
  `dbus-daemon(1)`, `polkit(8)`.
* ADR-0006 (kill switch), ADR-0007 (process routing), ADR-0009 (licensing).
