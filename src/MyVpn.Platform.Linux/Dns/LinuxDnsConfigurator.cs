using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Linux.Execution;

namespace MyVpn.Platform.Linux.Dns;

/// <summary>Which resolver mechanism MyVpn is actually driving on this machine.</summary>
public enum LinuxDnsBackend
{
    /// <summary>Not probed yet. A property getter must not spawn a process, so the probe is explicit.</summary>
    Unknown = 0,

    /// <summary>Probed: this machine has no mechanism MyVpn can configure.</summary>
    None = 1,

    /// <summary><c>systemd-resolved</c>, configured per link through <c>resolvectl</c>.</summary>
    SystemdResolved = 2,

    /// <summary>An interface-scoped record registered with <c>resolvconf</c> (Debian, openresolv).</summary>
    ResolvConf = 3,

    /// <summary><c>/etc/resolv.conf</c> written directly, as a last resort.</summary>
    DirectResolvConf = 4,
}

/// <summary>
/// Applies DNS configuration on Linux by detecting the resolver that is actually running.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why detection rather than <c>resolvectl</c> alone.</b> <c>systemd-resolved</c> is the default
/// on Ubuntu 21.10+ and Fedora 33+, but Debian does not install it at all and Arch installs the
/// package without enabling the service. An implementation that only calls <c>resolvectl</c>
/// therefore <i>silently does nothing</i> on those systems while appearing to succeed — the DNS
/// keeps going to the physical link's resolver, which is a leak, not a cosmetic bug. So the backend
/// is probed at runtime, in order, and reported:
/// </para>
/// <list type="number">
/// <item><description>
/// <c>systemd-resolved</c> — only when <c>resolvectl status</c> actually succeeds. A present but
/// dead <c>resolvectl</c> is not a backend.
/// </description></item>
/// <item><description><c>resolvconf</c> — when the tool exists.</description></item>
/// <item><description>
/// <c>/etc/resolv.conf</c> directly — only when it is a regular file, never through a symlink.
/// </description></item>
/// </list>
/// <para>
/// <b>Reading back.</b> Every apply is followed by <see cref="InspectAsync"/>, and the apply fails
/// if the servers did not take. Trusting the exit code of a configuration command is how a client
/// ends up reporting "protected" while the queries still leave through the uplink.
/// </para>
/// <para>
/// <b>What is not portable.</b> Per-link <c>resolvectl</c> is configured through the stable
/// <c>dns</c>/<c>domain</c> verbs, but "make this link the primary one" has no release-independent
/// spelling; MyVpn promotes the tunnel with <c>resolvectl default-route</c> and never demotes the
/// physical link. Per-link DoT/DoH is deliberately not attempted (the option set grew across
/// systemd releases), and <c>resolv.conf</c>/<c>resolvconf</c> records cannot express a
/// non-default port or an encrypted protocol at all — that is refused rather than silently
/// degraded to plaintext on port 53.
/// </para>
/// </remarks>
public sealed class LinuxDnsConfigurator : IDnsConfigurator
{
    /// <summary>Ownership marker written into every file this executor creates.</summary>
    public const string ManagedMarker = "# myvpn: managed resolver configuration";

    public const string DefaultResolvConfPath = "/etc/resolv.conf";

    /// <summary>State directory of <c>resolvconf</c>; per-interface records live in <c>interfaces/</c>.</summary>
    public const string DefaultResolvConfStateDirectory = "/run/resolvconf";

    /// <summary>Where the pre-MyVpn <c>resolv.conf</c> is kept so a restore after a crash is possible.</summary>
    public const string DefaultStateDirectory = "/var/lib/myvpn/dns";

    /// <summary>Record name suffix. `<c>iface</c>.myvpn` is interface-scoped, so nothing else owns it.</summary>
    private const string RecordSuffix = ".myvpn";

    private const string BackupFileName = "resolv.conf.backup";

    /// <summary>The TUN naming convention shared with the Kill Switch and the TUN planner.</summary>
    private const string TunnelLinkPrefix = "myvpn";

    private const string LeakIpv6Resolver = "error.dns.leak.ipv6_resolver";
    private const string LeakPlainResolverPresent = "error.dns.leak.plain_resolver_present";
    private const string LeakBackendUnknown = "error.dns.leak.backend_unknown";

    private readonly ICommandRunner _runner;
    private readonly Func<bool> _isElevated;
    private readonly string _resolvConfPath;
    private readonly string _resolvConfStateDirectory;
    private readonly string _stateDirectory;
    private readonly object _gate = new();

    private LinuxDnsBackend _backend = LinuxDnsBackend.Unknown;
    private string? _lastInterface;
    private CapturedState? _captured;

    public LinuxDnsConfigurator(
        ICommandRunner? runner = null,
        Func<bool>? isElevated = null,
        string? resolvConfPath = null,
        string? resolvConfStateDirectory = null,
        string? stateDirectory = null)
    {
        _runner = runner ?? new ProcessCommandRunner();
        _isElevated = isElevated ?? DefaultElevationCheck;
        _resolvConfPath = string.IsNullOrWhiteSpace(resolvConfPath) ? DefaultResolvConfPath : resolvConfPath;
        _resolvConfStateDirectory = string.IsNullOrWhiteSpace(resolvConfStateDirectory)
            ? DefaultResolvConfStateDirectory
            : resolvConfStateDirectory;
        _stateDirectory = string.IsNullOrWhiteSpace(stateDirectory) ? DefaultStateDirectory : stateDirectory;
    }

    /// <summary>
    /// True when a backend exists <i>and</i> this process may use it.
    /// </summary>
    /// <remarks>
    /// Deliberately a cheap check: tool presence and file existence only. The authoritative test —
    /// whether <c>systemd-resolved</c> is actually answering — needs a command run, and a property
    /// getter must not spawn a process; that probe happens in <see cref="ApplyAsync"/> and
    /// <see cref="InspectAsync"/>. Reporting <c>true</c> without privileges would make the session
    /// believe DNS was pinned and then fail at the last moment, after the tunnel was already up.
    /// </remarks>
    public bool IsSupported
    {
        get
        {
            if (!_isElevated())
            {
                return false;
            }

            return _runner.Exists("resolvectl")
                   || _runner.Exists("resolvconf")
                   || EntryExists(_resolvConfPath);
        }
    }

    /// <summary>The backend chosen by the last probe, for diagnostics.</summary>
    public LinuxDnsBackend Backend
    {
        get
        {
            lock (_gate)
            {
                return _backend;
            }
        }
    }

    /// <summary>Diagnostic label for <see cref="Backend"/>; a mechanism name, never a user message.</summary>
    public string BackendName => Describe(Backend);

    /// <summary>Resolvers observed immediately before the last successful apply.</summary>
    public IReadOnlyList<string> RecordedPreviousServers
    {
        get
        {
            lock (_gate)
            {
                return _captured?.Servers ?? Array.Empty<string>();
            }
        }
    }

    /// <summary>Name of the manager that owned DNS immediately before the last successful apply.</summary>
    public string? RecordedPreviousManager
    {
        get
        {
            lock (_gate)
            {
                return _captured?.Manager;
            }
        }
    }

    /// <summary>
    /// Probes the machine and returns the backend that will be used.
    /// </summary>
    /// <remarks>
    /// Read-only: it runs no privileged command. Exposed so diagnostics can report why MyVpn chose
    /// a particular mechanism, and so a caller can decide before bringing a tunnel up.
    /// </remarks>
    public async Task<LinuxDnsBackend> DetectBackendAsync(CancellationToken cancellationToken)
    {
        // 1. systemd-resolved, but only when it answers. `resolvectl` exists on Arch even when the
        //    service was never enabled, and on Debian it is simply absent; in both cases falling
        //    through is the difference between a working resolver and a silent no-op.
        if (_runner.Exists("resolvectl"))
        {
            var status = await _runner
                .RunAsync("resolvectl", new[] { "status" }, cancellationToken)
                .ConfigureAwait(false);

            if (status.Succeeded)
            {
                return SetBackend(LinuxDnsBackend.SystemdResolved);
            }
        }

        // 2. resolvconf — Debian's default manager, or openresolv on Arch.
        if (_runner.Exists("resolvconf"))
        {
            return SetBackend(LinuxDnsBackend.ResolvConf);
        }

        // 3. /etc/resolv.conf itself. Last resort: on many systems it is a symlink owned by
        //    somebody else (which Apply refuses), and where it is a static file NetworkManager and
        //    dhclient consider it theirs and will eventually rewrite it.
        if (EntryExists(_resolvConfPath))
        {
            return SetBackend(LinuxDnsBackend.DirectResolvConf);
        }

        return SetBackend(LinuxDnsBackend.None);
    }

    /// <summary>
    /// Returns a copy of <paramref name="plan"/> with the state MyVpn recorded before changing
    /// anything filled into <see cref="DnsPlan.PreviousServers"/> and
    /// <see cref="DnsPlan.PreviousManager"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="DnsPlan"/> is immutable and <see cref="ApplyAsync"/> returns no value, so the
    /// executor cannot write the captured state back into the caller's instance; it keeps it
    /// internally (see <see cref="RecordedPreviousServers"/>) and offers this copy so a session can
    /// persist a fully populated plan. An interface returning <c>Result&lt;DnsPlan&gt;</c> from the
    /// apply would remove the need for both.
    /// </remarks>
    public DnsPlan MergeRecordedState(DnsPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        CapturedState? captured;
        lock (_gate)
        {
            captured = _captured;
        }

        if (captured is null || !string.Equals(captured.Interface, plan.TunnelInterface, StringComparison.Ordinal))
        {
            return plan;
        }

        return plan with
        {
            PreviousServers = captured.Servers,
            PreviousManager = captured.Manager,
        };
    }

    public async Task<Result<DnsPlan>> ApplyAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return Result<DnsPlan>.Fail(validation.Error!);
        }

        if (!_isElevated())
        {
            return Result<DnsPlan>.Fail(NotElevated());
        }

        if (!IsSafeLinkName(plan.TunnelInterface))
        {
            return Result<DnsPlan>.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.invalid_link_name",
                ErrorSeverity.Error,
                $"'{plan.TunnelInterface}' is not a usable Linux interface name, so it can never be "
                + "handed to resolvectl or resolvconf.",
                "dns.reapply"));
        }

        if (plan.Servers.Count == 0)
        {
            // A plan with no resolver is "let the system decide"; there is nothing to configure and
            // nothing to read back. The leak blocking itself is the Kill Switch's and the DNS
            // guard's job, not this executor's.
            return Result<DnsPlan>.Ok(plan);
        }

        var backend = await DetectBackendAsync(cancellationToken).ConfigureAwait(false);

        var applied = backend switch
        {
            LinuxDnsBackend.SystemdResolved =>
                await ApplySystemdResolvedAsync(plan, cancellationToken).ConfigureAwait(false),
            LinuxDnsBackend.ResolvConf =>
                await ApplyResolvConfAsync(plan, cancellationToken).ConfigureAwait(false),
            LinuxDnsBackend.DirectResolvConf =>
                await ApplyDirectResolvConfAsync(plan, cancellationToken).ConfigureAwait(false),
            _ => Result.Fail(NoBackend()),
        };

        // The caller needs the prior state in order to undo this, and it must be able to get it
        // through the interface rather than by knowing this type.
        return applied.IsSuccess
            ? Result<DnsPlan>.Ok(MergeRecordedState(plan))
            : Result<DnsPlan>.Fail(applied.Error!);
    }

    public async Task<Result> RestoreAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        if (!IsSafeLinkName(plan.TunnelInterface))
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.invalid_link_name",
                ErrorSeverity.Error,
                $"'{plan.TunnelInterface}' is not a usable Linux interface name.",
                "dns.reapply"));
        }

        CapturedState? captured;
        lock (_gate)
        {
            captured = _captured;
        }

        if (captured is null)
        {
            // A fresh process — the crash case. Nothing was recorded here, so undo every backend that
            // could be holding state for this interface rather than guessing which one applied it.
            return await RestoreInterfaceEverywhereAsync(plan, cancellationToken).ConfigureAwait(false);
        }

        var backend = Backend;
        if (backend == LinuxDnsBackend.Unknown)
        {
            backend = await DetectBackendAsync(cancellationToken).ConfigureAwait(false);
        }

        // Undo on the backend that was used, not on the one that happens to be detected now: a
        // service that started or stopped in between must not change what gets cleaned up.
        if (string.Equals(captured.Interface, plan.TunnelInterface, StringComparison.Ordinal))
        {
            backend = captured.Backend;
        }

        switch (backend)
        {
            case LinuxDnsBackend.SystemdResolved:
                return await RestoreSystemdResolvedAsync(plan, captured, cancellationToken).ConfigureAwait(false);

            case LinuxDnsBackend.ResolvConf:
                return await RestoreResolvConfAsync(plan, cancellationToken).ConfigureAwait(false);

            case LinuxDnsBackend.DirectResolvConf:
                if (IsSymlink(_resolvConfPath))
                {
                    // MyVpn never writes through a symlink, so there is nothing of ours in there.
                    return Result.Ok();
                }

                var servers = plan.PreviousServers.Count > 0
                    ? plan.PreviousServers
                    : captured?.Servers ?? Array.Empty<string>();
                var search = plan.SearchDomains.Count > 0
                    ? plan.SearchDomains
                    : captured?.SearchDomains ?? Array.Empty<string>();

                return await RestoreDirectResolvConfAsync(servers, search, cancellationToken).ConfigureAwait(false);

            default:
                // No backend was ever configured on this machine, so there is nothing to undo.
                // Reporting failure here would leave the session unable to reach a clean state.
                return Result.Ok();
        }
    }

    /// <summary>
    /// Undoes every mechanism that could hold DNS state for one interface.
    /// </summary>
    /// <remarks>
    /// Used when a restore has no record of which backend was applied — a crash, or a caller that
    /// only kept a plan. It is the plan-scoped half of <see cref="RemoveAllOwnedAsync"/>, and it is
    /// deliberately idempotent: a link that no longer exists, a record that is already gone and a
    /// file without our marker are all "already clean", not failures.
    /// </remarks>
    private async Task<Result> RestoreInterfaceEverywhereAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        var iface = plan.TunnelInterface;
        var recordName = iface + RecordSuffix;
        var failures = new List<MyVpnError>();

        if (_runner.Exists("resolvectl"))
        {
            var reverted = await _runner
                .RunAsync("resolvectl", new[] { "revert", iface }, cancellationToken)
                .ConfigureAwait(false);

            if (!reverted.Succeeded && LinkExists(iface))
            {
                failures.Add(RestoreFailed($"resolvectl revert {iface}", reverted));
            }
        }

        if (_runner.Exists("resolvconf"))
        {
            var removed = await _runner
                .RunAsync("resolvconf", new[] { "-f", "-d", recordName }, cancellationToken)
                .ConfigureAwait(false);

            if (removed.Succeeded)
            {
                TryDeleteFile(RecordPathIn(recordName));
            }
            else
            {
                failures.Add(RestoreFailed($"resolvconf -d {recordName}", removed));
            }
        }

        var current = await ReadTextOrNullAsync(_resolvConfPath, cancellationToken).ConfigureAwait(false);
        if (current is not null
            && current.Contains(ManagedMarker, StringComparison.Ordinal)
            && !IsSymlink(_resolvConfPath))
        {
            var restored = await RestoreDirectResolvConfAsync(
                plan.PreviousServers,
                plan.SearchDomains,
                cancellationToken).ConfigureAwait(false);

            if (restored.IsFailure)
            {
                failures.Add(restored.Error!);
            }
        }

        if (failures.Count > 0)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsRestoreFailed,
                "error.dns.restore_failed",
                ErrorSeverity.Critical,
                string.Join("; ", failures.Select(f => f.TechnicalDetail ?? f.MessageKey)),
                "network.restore"));
        }

        return Result.Ok();
    }

    public async Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
    {
        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        var failures = new List<MyVpnError>();

        // 1. systemd-resolved. Per-link state lives in the service, so every link MyVpn could own
        //    is reverted, found by our own naming convention rather than by a remembered plan.
        if (_runner.Exists("resolvectl"))
        {
            var listed = await _runner
                .RunAsync("resolvectl", new[] { "dns" }, cancellationToken)
                .ConfigureAwait(false);

            if (!listed.Succeeded)
            {
                // The service is not answering. Its per-link DNS state died with it, so there is
                // genuinely nothing to revert — as opposed to "we could not be bothered to try".
            }
            else
            {
                var links = ParseResolvectlDns(listed.StandardOutput);
                var live = links
                    .Select(l => l.Name)
                    .Where(n => n is not null)
                    .Select(n => n!)
                    .ToArray();

                var candidates = new List<string>();

                // A link resolvectl no longer reports is gone, and it took its per-link DNS with it.
                // Reverting it would only produce a spurious failure on a machine that is already
                // clean, which is exactly what makes this safe to run blind after a crash.
                if (_lastInterface is not null && live.Contains(_lastInterface, StringComparer.Ordinal))
                {
                    candidates.Add(_lastInterface);
                }

                candidates.AddRange(live.Where(IsOwnedLinkName));

                foreach (var iface in candidates.Distinct(StringComparer.Ordinal))
                {
                    var reverted = await _runner
                        .RunAsync("resolvectl", new[] { "revert", iface }, cancellationToken)
                        .ConfigureAwait(false);

                    if (!reverted.Succeeded)
                    {
                        failures.Add(RestoreFailed($"resolvectl revert {iface}", reverted));
                    }
                }
            }
        }

        // 2. resolvconf. Only records carrying our suffix are removed, which is exactly the set
        //    MyVpn registered — never another daemon's record.
        if (_runner.Exists("resolvconf"))
        {
            var recordNames = OwnedRecordNames().ToList();
            if (_lastInterface is not null)
            {
                recordNames.Add(_lastInterface + RecordSuffix);
            }

            foreach (var recordName in recordNames.Distinct(StringComparer.Ordinal))
            {
                // -f makes the deletion idempotent: a record that is not there is already removed.
                var removed = await _runner
                    .RunAsync("resolvconf", new[] { "-f", "-d", recordName }, cancellationToken)
                    .ConfigureAwait(false);

                if (!removed.Succeeded)
                {
                    failures.Add(RestoreFailed($"resolvconf -d {recordName}", removed));
                }
                else
                {
                    TryDeleteFile(RecordPathIn(recordName));
                }
            }
        }

        // 3. A directly written /etc/resolv.conf, recognised by our own marker. Without the marker
        //    the file is somebody else's and must not be touched.
        var current = await ReadTextOrNullAsync(_resolvConfPath, cancellationToken).ConfigureAwait(false);
        if (current is not null
            && current.Contains(ManagedMarker, StringComparison.Ordinal)
            && !IsSymlink(_resolvConfPath))
        {
            var restored = await RestoreDirectResolvConfAsync(
                Array.Empty<string>(),
                Array.Empty<string>(),
                cancellationToken).ConfigureAwait(false);

            if (restored.IsFailure)
            {
                failures.Add(restored.Error!);
            }
        }

        if (failures.Count > 0)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsRestoreFailed,
                "error.dns.restore_failed",
                ErrorSeverity.Critical,
                string.Join("; ", failures.Select(f => f.TechnicalDetail ?? f.MessageKey)),
                "network.restore"));
        }

        return Result.Ok();
    }

    public async Task<DnsState> InspectAsync(CancellationToken cancellationToken)
    {
        var snapshot = ParseResolvConf(
            await ReadTextOrNullAsync(_resolvConfPath, cancellationToken).ConfigureAwait(false) ?? string.Empty);

        var backend = Backend;
        if (backend == LinuxDnsBackend.Unknown)
        {
            backend = await DetectBackendAsync(cancellationToken).ConfigureAwait(false);
        }

        var active = new List<string>();
        var outsideTunnel = new List<string>();
        string? interfaceName = null;
        var tunnelLinkFound = false;

        if (backend == LinuxDnsBackend.SystemdResolved)
        {
            var listed = await _runner
                .RunAsync("resolvectl", new[] { "dns" }, cancellationToken)
                .ConfigureAwait(false);

            if (listed.Succeeded)
            {
                var links = ParseResolvectlDns(listed.StandardOutput);
                var chosen = ChooseTunnelLink(links);
                if (chosen is not null)
                {
                    tunnelLinkFound = true;
                    interfaceName = chosen.Name;
                    active.AddRange(chosen.Servers);
                }

                outsideTunnel.AddRange(links
                    .Where(l => !string.Equals(l.Name, interfaceName, StringComparison.Ordinal))
                    .SelectMany(l => l.Servers));
            }
        }

        if (active.Count == 0)
        {
            // Nothing per-link: report what libc would actually read, which is the honest answer to
            // "which resolver is in use" when no tunnel-specific configuration is present.
            active.AddRange(snapshot.Servers);
            interfaceName ??= _lastInterface;
        }

        var hasIpv6 = active.Any(IsNonLoopbackIpv6);

        // Best effort and strictly local: a resolver outside the tunnel is "configured" when the
        // libc-visible file names one that is not a loopback stub, or when systemd-resolved has
        // servers on other links while MyVpn never managed to configure ours. No network I/O.
        var plainOutside = snapshot.Servers.Any(IsNonLoopbackAddress)
                           || (backend == LinuxDnsBackend.SystemdResolved
                               && !tunnelLinkFound
                               && outsideTunnel.Any(IsNonLoopbackAddress));

        var leaks = new List<string>();
        if (hasIpv6)
        {
            leaks.Add(LeakIpv6Resolver);
        }

        if (plainOutside)
        {
            leaks.Add(LeakPlainResolverPresent);
        }

        if (backend == LinuxDnsBackend.None)
        {
            // No mechanism at all: whatever the machine is using, MyVpn cannot pin it.
            leaks.Add(LeakBackendUnknown);
        }

        return new DnsState
        {
            ActiveServers = active,
            InterfaceName = interfaceName,
            PlainDnsReachableOutsideTunnel = plainOutside,
            HasIpv6Resolver = hasIpv6,
            PotentialLeaks = leaks,
        };
    }

    // ------------------------------------------------------------------ systemd-resolved

    private async Task<Result> ApplySystemdResolvedAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        var iface = plan.TunnelInterface;

        await CaptureAsync(LinuxDnsBackend.SystemdResolved, plan, null, cancellationToken).ConfigureAwait(false);
        RememberInterface(iface);

        // Per-link DNS on the tunnel interface only. /etc/resolv.conf is deliberately not touched:
        // systemd-resolved treats a foreign file there as its *upstream* configuration, and
        // NetworkManager, resolvconf and dhclient all consider the file theirs.
        var servers = plan.Servers.Select(FormatResolver).ToArray();
        var dns = await _runner
            .RunAsync("resolvectl", new[] { "dns", iface }.Concat(servers).ToArray(), cancellationToken)
            .ConfigureAwait(false);

        if (!dns.Succeeded)
        {
            return Result.Fail(ToolFailed("error.dns.resolvectl_dns_failed", "resolvectl dns", dns));
        }

        var domains = RoutingDomains(plan);
        var domain = await _runner
            .RunAsync("resolvectl", new[] { "domain", iface }.Concat(domains).ToArray(), cancellationToken)
            .ConfigureAwait(false);

        if (!domain.Succeeded)
        {
            return Result.Fail(ToolFailed("error.dns.resolvectl_domain_failed", "resolvectl domain", domain));
        }

        // Per-link resolvers alone are not enough: the link that owns the default route keeps
        // answering, so the tunnel has to be promoted explicitly.
        //
        // What cannot be done portably: there is no systemd-release-independent way to *demote* the
        // physical link (the pre-239 `systemd-resolve --set-dns` spelling and the per-link
        // DefaultRoute property differ between releases), so MyVpn promotes the tunnel rather than
        // demoting the uplink. A failure here is fatal on purpose: if the tunnel is not the default
        // DNS route, queries can still leave through the physical link's resolver, which is exactly
        // the leak this class exists to prevent. Per-link DoT/DoH is not attempted either — see the
        // class remarks.
        var route = await _runner
            .RunAsync("resolvectl", new[] { "default-route", iface, "yes" }, cancellationToken)
            .ConfigureAwait(false);

        if (!route.Succeeded)
        {
            return Result.Fail(
                ToolFailed("error.dns.resolvectl_default_route_failed", "resolvectl default-route", route));
        }

        return await VerifyAsync(plan, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Result> RestoreSystemdResolvedAsync(
        DnsPlan plan,
        CapturedState? captured,
        CancellationToken cancellationToken)
    {
        var iface = plan.TunnelInterface;

        if (!_runner.Exists("resolvectl"))
        {
            // The only place per-link state lives is gone, and it took the state with it.
            return Result.Ok();
        }

        var previous = plan.PreviousServers.Count > 0
            ? plan.PreviousServers
            : captured?.Servers ?? Array.Empty<string>();

        if (previous.Count > 0)
        {
            // The link had resolvers of its own before MyVpn: put those back rather than dropping
            // the link to DHCP-configured DNS, which is not what it had.
            var set = await _runner
                .RunAsync("resolvectl", new[] { "dns", iface }.Concat(previous).ToArray(), cancellationToken)
                .ConfigureAwait(false);

            return set.Succeeded
                ? Result.Ok()
                : Result.Fail(RestoreFailed($"resolvectl dns {iface}", set));
        }

        // The documented undo for per-link configuration: hand the link back to DHCP-provided DNS.
        var reverted = await _runner
            .RunAsync("resolvectl", new[] { "revert", iface }, cancellationToken)
            .ConfigureAwait(false);

        if (reverted.Succeeded)
        {
            return Result.Ok();
        }

        // A TUN link that no longer exists took its per-link DNS with it, so a failed revert on a
        // link the kernel does not have is genuinely "already clean" — which is what makes restore
        // safe to call after a crash.
        return LinkExists(iface) ? Result.Fail(RestoreFailed($"resolvectl revert {iface}", reverted)) : Result.Ok();
    }

    /// <summary>Routing domains for the tunnel link, or the catch-all when no split DNS was asked for.</summary>
    private static string[] RoutingDomains(DnsPlan plan)
    {
        var requested = new List<string>(plan.SplitDnsDomains);
        foreach (var server in plan.Servers)
        {
            requested.AddRange(server.Domains);
        }

        var domains = requested
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Trim().TrimStart('~'))
            .Where(IsSafeRoutingDomain)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(d => "~" + d)
            .ToArray();

        // `~.` is the catch-all routing domain: "prefer the resolvers on this link for every name".
        // Without it the tunnel link is only consulted for names it happens to own, and the
        // physical link keeps answering everything else — the leak, in one missing argument.
        return domains.Length > 0 ? domains : new[] { "~." };
    }

    // ------------------------------------------------------------------ resolvconf

    private async Task<Result> ApplyResolvConfAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        var capability = ValidateForFileBackend(plan);
        if (capability.IsFailure)
        {
            return capability;
        }

        var iface = plan.TunnelInterface;
        var recordName = iface + RecordSuffix;

        var captured = await CaptureAsync(LinuxDnsBackend.ResolvConf, plan, null, cancellationToken)
            .ConfigureAwait(false);
        RememberInterface(iface);

        var installed = await InstallResolvConfRecordAsync(
            recordName,
            RenderManagedResolvConf(plan, captured.SearchDomains),
            cancellationToken).ConfigureAwait(false);

        if (installed.IsFailure)
        {
            return installed;
        }

        var updated = await _runner
            .RunAsync("resolvconf", new[] { "-u" }, cancellationToken)
            .ConfigureAwait(false);

        if (!updated.Succeeded)
        {
            return Result.Fail(ToolFailed("error.dns.resolvconf_update_failed", "resolvconf -u", updated));
        }

        return await VerifyAsync(plan, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Installs an interface-scoped resolvconf record.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this is not <c>resolvconf -a &lt;iface&gt;.myvpn</c> fed from stdin.</b>
    /// <c>resolvconf(8)</c> accepts its record only on stdin — its synopsis is
    /// <c>resolvconf [-m metric] [-p] [-x] -a interface[.protocol] &lt;file</c> — and there is no
    /// file-path argument, while <see cref="ICommandRunner"/> has no stdin. Feeding the record
    /// through a pipe would need a shell, and there is deliberately no <c>sh -c</c> in this
    /// assembly. Calling <c>-a</c> anyway would read whatever the process happens to have on stdin
    /// and register an empty record while exiting zero: a silent no-op, which is the leak failure
    /// mode this executor exists to avoid.
    /// </para>
    /// <para>
    /// So the record is written as a file into the tool's own state directory (the documented
    /// <c>/run/resolvconf</c> layout, where each record <i>is</i> a file) and <c>resolvconf -u</c>
    /// is invoked to make the tool regenerate <c>/etc/resolv.conf</c> from it. The <c>-m metric</c>
    /// and <c>-x exclusive</c> flags cannot be applied this way, because they are properties of the
    /// <c>-a</c> invocation; the record uses the tool's default metric. Adding stdin support to
    /// <see cref="ICommandRunner"/> would let the conventional <c>-a</c> form be used instead.
    /// </para>
    /// <para>
    /// The content is staged in a private 0600 file in the same directory and moved into place, so
    /// a reader never sees a half-written record.
    /// </para>
    /// <para>
    /// The per-record directory is the tool's documented state directory (<c>&lt;state&gt;/interfaces</c>),
    /// with the older Debian <c>/etc/resolvconf/run/interfaces</c> as a fallback. If an
    /// implementation keeps its records elsewhere, the directory is not found and the apply fails
    /// with a clear error instead of writing a file nobody reads; if it reads a different file
    /// after <c>-u</c>, the read-back verification fails the apply. Neither case can be a silent
    /// no-op.
    /// </para>
    /// </remarks>
    private async Task<Result> InstallResolvConfRecordAsync(
        string recordName,
        string content,
        CancellationToken cancellationToken)
    {
        var directory = FindRecordDirectory();
        if (directory is null)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.resolvconf_state_missing",
                ErrorSeverity.Error,
                "'resolvconf' is installed but none of its state directories exist "
                + $"({string.Join(", ", RecordDirectories())}), so no interface-scoped record can be "
                + "registered. MyVpn will not write its resolver into a file resolvconf does not read.",
                "dns.reapply"));
        }

        var path = Path.Combine(directory, recordName);
        var staging = Path.Combine(directory, $".myvpn-{Guid.NewGuid():N}.tmp");

        try
        {
            await File.WriteAllTextAsync(staging, content, cancellationToken).ConfigureAwait(false);
            SetMode(staging, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(staging, path, overwrite: true);

            return Result.Ok();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.resolvconf_record_failed",
                ErrorSeverity.Error,
                $"The resolvconf record '{path}' could not be written: {ex.Message}",
                "dns.reapply"));
        }
        finally
        {
            TryDeleteFile(staging);
        }
    }

    private async Task<Result> RestoreResolvConfAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        var recordName = plan.TunnelInterface + RecordSuffix;

        if (_runner.Exists("resolvconf"))
        {
            // Idempotent: -f ignores an interface it does not have a record for. Removing our
            // record is the correct restore — NetworkManager and dhclient re-register their own
            // records, so re-creating their resolvers from a remembered list would be wrong.
            var removed = await _runner
                .RunAsync("resolvconf", new[] { "-f", "-d", recordName }, cancellationToken)
                .ConfigureAwait(false);

            if (!removed.Succeeded)
            {
                return Result.Fail(RestoreFailed($"resolvconf -d {recordName}", removed));
            }
        }

        // resolvconf deletes the record itself; this covers the case where the package was removed
        // while MyVpn was up, and stops the stale record being resurrected if it comes back.
        TryDeleteFile(RecordPathIn(recordName));

        return Result.Ok();
    }

    // ------------------------------------------------------------------ /etc/resolv.conf

    private async Task<Result> ApplyDirectResolvConfAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        // Writing through a symlink replaces the *target*, not the link. For the common
        // /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf case that means overwriting
        // systemd-resolved's generated file, which resolved then regenerates at the next link
        // event. Deliberately following the link and writing the target only is not correct
        // either: the target belongs to whoever created the link, and after a crash MyVpn could not
        // tell which of the four supported resolved modes to put back. So a symlink is refused.
        if (IsSymlink(_resolvConfPath))
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.resolv_conf_symlink",
                ErrorSeverity.Error,
                $"{_resolvConfPath} is a symbolic link (to '{LinkTargetOf(_resolvConfPath) ?? "unknown"}'), "
                + "so it is managed by another resolver. MyVpn configures per-link DNS instead of "
                + "replacing a file somebody else owns.",
                "dns.reapply"));
        }

        var capability = ValidateForFileBackend(plan);
        if (capability.IsFailure)
        {
            return capability;
        }

        var original = await ReadTextOrNullAsync(_resolvConfPath, cancellationToken).ConfigureAwait(false);
        if (original is null)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.resolv_conf_missing",
                ErrorSeverity.Error,
                $"{_resolvConfPath} disappeared between detection and apply, so there is nothing to "
                + "back up and nothing to restore.",
                "dns.reapply"));
        }

        var captured = await CaptureAsync(LinuxDnsBackend.DirectResolvConf, plan, original, cancellationToken)
            .ConfigureAwait(false);
        RememberInterface(plan.TunnelInterface);

        // Back up before touching anything. Losing the original configuration is the failure mode
        // that leaves a machine with no working DNS long after the VPN is gone.
        var backedUp = await BackUpResolvConfAsync(original, cancellationToken).ConfigureAwait(false);
        if (backedUp.IsFailure)
        {
            return backedUp;
        }

        var written = await WriteResolvConfAsync(
            RenderManagedResolvConf(plan, captured.SearchDomains),
            cancellationToken).ConfigureAwait(false);

        if (written.IsFailure)
        {
            return written;
        }

        return await VerifyAsync(plan, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Result> RestoreDirectResolvConfAsync(
        IReadOnlyList<string> previousServers,
        IReadOnlyList<string> searchDomains,
        CancellationToken cancellationToken)
    {
        // The exact prior bytes — comments, options and all — when the backup survived.
        var backup = await ReadTextOrNullAsync(BackupPath, cancellationToken).ConfigureAwait(false);
        if (backup is not null)
        {
            var restored = await WriteResolvConfAsync(backup, cancellationToken).ConfigureAwait(false);
            if (restored.IsSuccess)
            {
                // Consumed: keeping a stale copy of somebody's resolv.conf around invites a later
                // restore over a newer configuration.
                TryDeleteFile(BackupPath);
            }

            return restored;
        }

        if (previousServers.Count > 0)
        {
            return await WriteResolvConfAsync(
                RenderRestoredResolvConf(previousServers, searchDomains),
                cancellationToken).ConfigureAwait(false);
        }

        // Nothing to put back. Writing an empty resolv.conf would leave the machine unable to
        // resolve anything, so the file is left exactly as it is.
        return Result.Ok();
    }

    private async Task<Result> BackUpResolvConfAsync(string content, CancellationToken cancellationToken)
    {
        try
        {
            Directory.CreateDirectory(_stateDirectory);
            SetMode(
                _stateDirectory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            await File.WriteAllTextAsync(BackupPath, content, cancellationToken).ConfigureAwait(false);
            SetMode(BackupPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            return Result.Ok();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.backup_failed",
                ErrorSeverity.Critical,
                $"{_resolvConfPath} could not be backed up to '{BackupPath}', so it was left "
                + $"untouched: {ex.Message}",
                "diagnostics.run"));
        }
    }

    private async Task<Result> WriteResolvConfAsync(string content, CancellationToken cancellationToken)
    {
        var existed = File.Exists(_resolvConfPath);

        try
        {
            // Written through the existing file rather than replaced by rename, so ownership, mode
            // and (on SELinux systems) the security context are preserved.
            await File.WriteAllTextAsync(_resolvConfPath, content, cancellationToken).ConfigureAwait(false);

            if (!existed)
            {
                SetMode(
                    _resolvConfPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite
                    | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            }

            return Result.Ok();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.resolv_conf_write_failed",
                ErrorSeverity.Error,
                $"'{_resolvConfPath}' could not be written: {ex.Message}",
                "dns.reapply"));
        }
    }

    // ------------------------------------------------------------------ verification

    /// <summary>
    /// Reads the configuration back and fails when the servers did not take.
    /// </summary>
    /// <remarks>
    /// This is the check that turns "resolvectl exited zero" into a caught error. On a machine
    /// where the command existed but changed nothing — the Arch-with-the-service-disabled case, or
    /// a tool talking to a different bus — the exit code is zero and the resolvers are not there.
    /// </remarks>
    private async Task<Result> VerifyAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        if (plan.Servers.Count == 0)
        {
            return Result.Ok();
        }

        var observed = await InspectAsync(cancellationToken).ConfigureAwait(false);
        var active = observed.ActiveServers
            .Select(NormalizeServerToken)
            .Where(v => v is not null)
            .Select(v => v!)
            .ToHashSet(StringComparer.Ordinal);

        var missing = plan.Servers
            .Where(s => !active.Contains(NormalizeAddress(s.Address)))
            .Select(s => s.Address)
            .ToArray();

        if (missing.Length == 0)
        {
            return Result.Ok();
        }

        return Result.Fail(new MyVpnError(
            ErrorCodes.DnsConfigureFailed,
            "error.dns.verify_failed",
            ErrorSeverity.Critical,
            "The resolver configuration was reported as applied, but reading the system back shows "
            + $"different servers. Missing: {string.Join(", ", missing)}; observed: "
            + $"{(observed.ActiveServers.Count == 0 ? "none" : string.Join(", ", observed.ActiveServers))}.",
            "dns.reapply"));
    }

    // ------------------------------------------------------------------ capture

    private async Task<CapturedState> CaptureAsync(
        LinuxDnsBackend backend,
        DnsPlan plan,
        string? resolvConfText,
        CancellationToken cancellationToken)
    {
        var previous = new List<string>();
        var search = new List<string>();

        if (backend == LinuxDnsBackend.SystemdResolved)
        {
            // Link-scoped only: whatever the tunnel link itself had, which for a freshly created TUN
            // is normally nothing — and then `revert` is the correct undo. Falling back to the
            // host's resolv.conf here would make restore put the physical link's resolvers onto the
            // tunnel link.
            var read = await _runner
                .RunAsync("resolvectl", new[] { "dns", plan.TunnelInterface }, cancellationToken)
                .ConfigureAwait(false);

            if (read.Succeeded)
            {
                previous.AddRange(ParseBareServerList(read.StandardOutput));
            }
        }
        else
        {
            var snapshot = ParseResolvConf(
                resolvConfText ?? await ReadTextOrNullAsync(_resolvConfPath, cancellationToken).ConfigureAwait(false)
                ?? string.Empty);

            previous.AddRange(snapshot.Servers);
            search.AddRange(snapshot.SearchDomains);
        }

        // A plan that already carries the previous state was captured by the caller before the
        // tunnel existed, which is at least as good as what is visible now.
        if (plan.PreviousServers.Count > 0)
        {
            previous.Clear();
            previous.AddRange(plan.PreviousServers);
        }

        var captured = new CapturedState(
            plan.TunnelInterface,
            backend,
            previous,
            search,
            plan.PreviousManager ?? Describe(backend));

        lock (_gate)
        {
            _captured = captured;
        }

        return captured;
    }

    // ------------------------------------------------------------------ rendering

    /// <summary>
    /// Renders the file MyVpn owns while the tunnel is up.
    /// </summary>
    /// <remarks>
    /// The host's own search domains are carried over when the plan does not name any: dropping
    /// them would silently change how single-label names resolve for as long as the tunnel is up.
    /// </remarks>
    private static string RenderManagedResolvConf(DnsPlan plan, IReadOnlyList<string> previousSearchDomains)
    {
        var builder = new StringBuilder();
        builder.Append(ManagedMarker).Append('\n');
        builder.Append("# MyVpn wrote this while the tunnel was up. The previous contents were backed up and\n");
        builder.Append("# are restored on disconnect; edits made here are lost when the tunnel goes down.\n");

        AppendResolvers(
            builder,
            plan.Servers.Select(s => s.Address.Trim()),
            plan.SearchDomains.Count > 0 ? plan.SearchDomains : previousSearchDomains);

        return builder.ToString();
    }

    /// <summary>Renders the recorded servers back as a plain, unmanaged resolv.conf.</summary>
    private static string RenderRestoredResolvConf(
        IReadOnlyList<string> servers,
        IReadOnlyList<string> searchDomains)
    {
        var builder = new StringBuilder();
        AppendResolvers(builder, servers, searchDomains);
        return builder.ToString();
    }

    private static void AppendResolvers(
        StringBuilder builder,
        IEnumerable<string> servers,
        IReadOnlyList<string> searchDomains)
    {
        foreach (var server in servers)
        {
            builder.Append("nameserver ").Append(server).Append('\n');
        }

        var search = searchDomains.Where(d => !string.IsNullOrWhiteSpace(d)).ToArray();
        if (search.Length > 0)
        {
            builder.Append("search ").Append(string.Join(' ', search)).Append('\n');
        }
    }

    /// <summary>
    /// Rejects a resolver the file-based backends cannot express.
    /// </summary>
    /// <remarks>
    /// A <c>resolv.conf</c> line carries no port and no transport, so a resolver on port 5353 or an
    /// encrypted one would either be ignored by glibc or quietly downgraded to plaintext on port
    /// 53. Both are worse than refusing.
    /// </remarks>
    private static Result ValidateForFileBackend(DnsPlan plan)
    {
        foreach (var server in plan.Servers)
        {
            if (server.Port != 53)
            {
                return Result.Fail(new MyVpnError(
                    ErrorCodes.DnsConfigureFailed,
                    "error.dns.resolv_conf_port_unsupported",
                    ErrorSeverity.Error,
                    $"Resolver '{server.Address}' uses port {server.Port.ToString(CultureInfo.InvariantCulture)}. "
                    + "A resolv.conf entry has no port field, so this resolver would silently be "
                    + "ignored; use the systemd-resolved backend or the default port.",
                    "dns.reapply"));
            }

            var protocol = string.IsNullOrWhiteSpace(server.Protocol) ? "udp" : server.Protocol.Trim();
            if (!string.Equals(protocol, "udp", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(protocol, "tcp", StringComparison.OrdinalIgnoreCase))
            {
                return Result.Fail(new MyVpnError(
                    ErrorCodes.DnsConfigureFailed,
                    "error.dns.resolv_conf_protocol_unsupported",
                    ErrorSeverity.Error,
                    $"Resolver '{server.Address}' uses '{protocol}'. A resolv.conf entry cannot carry an "
                    + "encrypted transport, so applying it here would silently downgrade the resolver "
                    + "to plaintext.",
                    "dns.reapply"));
            }
        }

        return Result.Ok();
    }

    private static string FormatResolver(DnsServerEntry entry)
    {
        var address = entry.Address.Trim();
        if (entry.Port == 53)
        {
            return address;
        }

        // resolvectl accepts a port as `address:port`, and an IPv6 literal has to be bracketed.
        return IPAddress.TryParse(address, out var parsed) && parsed.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{parsed}]:{entry.Port.ToString(CultureInfo.InvariantCulture)}"
            : $"{address}:{entry.Port.ToString(CultureInfo.InvariantCulture)}";
    }

    // ------------------------------------------------------------------ parsing

    /// <summary>Reads the servers and search domains a resolv.conf-style file declares.</summary>
    private static ResolvConfSnapshot ParseResolvConf(string text)
    {
        var servers = new List<string>();
        var search = new List<string>();

        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or ';')
            {
                continue;
            }

            if (line.StartsWith("nameserver", StringComparison.Ordinal)
                && (line.Length == 10 || char.IsWhiteSpace(line[10])))
            {
                var value = line[10..].Trim();
                if (value.Length > 0)
                {
                    servers.Add(value);
                }
            }
            else if (line.StartsWith("search", StringComparison.Ordinal)
                     && (line.Length == 6 || char.IsWhiteSpace(line[6])))
            {
                search.AddRange(line[6..].Split(
                    new[] { ' ', '\t' },
                    StringSplitOptions.RemoveEmptyEntries));
            }
            else if (line.StartsWith("domain", StringComparison.Ordinal)
                     && (line.Length == 6 || char.IsWhiteSpace(line[6])))
            {
                var value = line[6..].Trim();
                if (value.Length > 0)
                {
                    search.Add(value);
                }
            }
        }

        return new ResolvConfSnapshot(servers, search);
    }

    /// <summary>Parses the output of <c>resolvectl dns</c> without an interface argument.</summary>
    private static IReadOnlyList<ResolvectlLink> ParseResolvectlDns(string output)
    {
        var links = new List<ResolvectlLink>();
        var bare = new List<string>();
        var structured = false;

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith("Link ", StringComparison.Ordinal))
            {
                structured = true;

                var open = line.IndexOf('(');
                var close = line.IndexOf(')');
                var name = open >= 0 && close > open ? line[(open + 1)..close] : null;

                links.Add(new ResolvectlLink(name, ServersAfterColon(line)));
                continue;
            }

            if (line.StartsWith("Global:", StringComparison.Ordinal))
            {
                structured = true;
                links.Add(new ResolvectlLink(null, ServersAfterColon(line)));
                continue;
            }

            bare.AddRange(ParseBareServerList(line));
        }

        if (!structured && bare.Count > 0)
        {
            links.Add(new ResolvectlLink(null, bare));
        }

        return links;
    }

    /// <summary>
    /// Collects the IP literals out of a server list, dropping everything that is not one.
    /// </summary>
    /// <remarks>
    /// Used for <c>resolvectl dns &lt;iface&gt;</c>, whose output is a bare list. Tokens that are not
    /// addresses (a <c>Link 2 (eth0):</c> header, for instance) are ignored, so the same parser is
    /// safe for both output shapes.
    /// </remarks>
    private static IReadOnlyList<string> ParseBareServerList(string output)
    {
        var servers = new List<string>();

        foreach (var raw in output.Split('\n'))
        {
            foreach (var token in raw.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var normalized = NormalizeServerToken(token);
                if (normalized is not null)
                {
                    servers.Add(normalized);
                }
            }
        }

        return servers;
    }

    private static IReadOnlyList<string> ServersAfterColon(string line)
    {
        var colon = line.IndexOf(':');
        return colon < 0 ? Array.Empty<string>() : ParseBareServerList(line[(colon + 1)..]);
    }

    /// <summary>Normalizes one server token to a canonical IP literal, or null when it is not one.</summary>
    private static string? NormalizeServerToken(string token)
    {
        var value = token.Trim();
        if (value.Length == 0)
        {
            return null;
        }

        if (IPAddress.TryParse(value, out var direct))
        {
            return direct.ToString();
        }

        // `1.2.3.4:5353` and `[2001:db8::1]:5353`, the forms resolvectl prints for a non-default port.
        if (value[0] == '[')
        {
            var close = value.IndexOf(']');
            if (close > 1 && IPAddress.TryParse(value[1..close], out var bracketed))
            {
                return bracketed.ToString();
            }

            return null;
        }

        var colon = value.LastIndexOf(':');
        if (colon > 0
            && IPAddress.TryParse(value[..colon], out var withPort)
            && int.TryParse(value[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out _))
        {
            return withPort.ToString();
        }

        return null;
    }

    private static string NormalizeAddress(string address)
    {
        var value = address.Trim();
        return IPAddress.TryParse(value, out var parsed) ? parsed.ToString() : value;
    }

    private static bool IsNonLoopbackAddress(string value) =>
        IPAddress.TryParse(value.Trim().Trim('[', ']'), out var parsed) && !IPAddress.IsLoopback(parsed);

    private static bool IsNonLoopbackIpv6(string value) =>
        IPAddress.TryParse(value.Trim().Trim('[', ']'), out var parsed)
        && parsed.AddressFamily == AddressFamily.InterNetworkV6
        && !IPAddress.IsLoopback(parsed);

    private static string Describe(LinuxDnsBackend backend) => backend switch
    {
        LinuxDnsBackend.SystemdResolved => "systemd-resolved",
        LinuxDnsBackend.ResolvConf => "resolvconf",
        LinuxDnsBackend.DirectResolvConf => "resolv.conf",
        LinuxDnsBackend.None => "none",
        _ => "unknown",
    };

    private static bool IsSafeLinkName(string? name)
    {
        // Linux interface names are at most 15 characters and cannot contain whitespace or '/'.
        // Rejecting a leading '-' matters as well: an interface field must never reach a tool as
        // something that looks like an option.
        if (string.IsNullOrWhiteSpace(name) || name.Length > 15 || name[0] == '-')
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('_' or '-' or '.' or ':' or '@'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSafeRoutingDomain(string? domain) =>
        !string.IsNullOrWhiteSpace(domain)
        && domain.Length <= 253
        && domain[0] != '-'
        && !domain.Any(c => char.IsWhiteSpace(c) || c is '/' or '~');

    // ------------------------------------------------------------------ filesystem

    private static bool EntryExists(string path) =>
        !string.IsNullOrWhiteSpace(path) && (File.Exists(path) || IsSymlink(path));

    private static bool IsSymlink(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    private static string? LinkTargetOf(string path)
    {
        try
        {
            return new FileInfo(path).LinkTarget;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    private static async Task<string?> ReadTextOrNullAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            return await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void SetMode(string path, UnixFileMode mode)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, mode);
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A leftover private file in a root-only directory is harmless.
        }
    }

    private static bool LinkExists(string interfaceName) =>
        Directory.Exists(Path.Combine("/sys/class/net", interfaceName));

    private static bool IsOwnedLinkName(string interfaceName) =>
        interfaceName.StartsWith(TunnelLinkPrefix, StringComparison.Ordinal) && IsSafeLinkName(interfaceName);

    private IEnumerable<string> RecordDirectories() =>
        new[]
        {
            Path.Combine(_resolvConfStateDirectory, "interfaces"),

            // Older Debian resolvconf kept its state below /etc instead of /run.
            "/etc/resolvconf/run/interfaces",
        }.Distinct(StringComparer.Ordinal);

    private string? FindRecordDirectory() => RecordDirectories().FirstOrDefault(Directory.Exists);

    private string RecordPathIn(string recordName)
    {
        var directory = FindRecordDirectory() ?? Path.Combine(_resolvConfStateDirectory, "interfaces");
        return Path.Combine(directory, recordName);
    }

    private IEnumerable<string> OwnedRecordNames()
    {
        foreach (var directory in RecordDirectories())
        {
            string[] files;
            try
            {
                files = Directory.Exists(directory)
                    ? Directory.GetFiles(directory, "*" + RecordSuffix)
                    : Array.Empty<string>();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                yield return Path.GetFileName(file);
            }
        }
    }

    private string BackupPath => Path.Combine(_stateDirectory, BackupFileName);

    // ------------------------------------------------------------------ state

    private void RememberInterface(string interfaceName)
    {
        lock (_gate)
        {
            _lastInterface = interfaceName;
        }
    }

    private LinuxDnsBackend SetBackend(LinuxDnsBackend backend)
    {
        lock (_gate)
        {
            _backend = backend;
        }

        return backend;
    }

    private ResolvectlLink? ChooseTunnelLink(IReadOnlyList<ResolvectlLink> links)
    {
        var named = links.Where(l => l.Name is not null).ToArray();

        var remembered = _lastInterface is null
            ? null
            : named.FirstOrDefault(l => string.Equals(l.Name, _lastInterface, StringComparison.Ordinal));

        // Falling back to the naming convention keeps diagnostics useful in a fresh process, where
        // no apply has run yet — the TUN interface is always called myvpn* by this project.
        return remembered ?? named.FirstOrDefault(
            l => l.Name!.StartsWith(TunnelLinkPrefix, StringComparison.Ordinal));
    }

    // ------------------------------------------------------------------ errors

    private static MyVpnError NotElevated() =>
        new(
            ErrorCodes.PrivilegeDenied,
            "error.dns.not_elevated",
            ErrorSeverity.Error,
            "Configuring the system resolver requires root. MyVpn needs its privileged helper "
            + "installed; the UI must never run as root itself.",
            "privilege.install_helper");

    private static MyVpnError NoBackend() =>
        new(
            ErrorCodes.PlatformToolMissing,
            "error.dns.no_backend",
            ErrorSeverity.Error,
            "No usable DNS backend was found: 'resolvectl' is absent or systemd-resolved is not "
            + "answering, 'resolvconf' is not installed, and /etc/resolv.conf is not a regular file "
            + "MyVpn may write. MyVpn will not report a resolver as configured when it cannot reach "
            + "one.",
            "diagnostics.run");

    private static MyVpnError ToolFailed(string messageKey, string tool, CommandResult result) =>
        new(
            ErrorCodes.DnsConfigureFailed,
            messageKey,
            ErrorSeverity.Error,
            $"{tool} failed with exit code {result.ExitCode.ToString(CultureInfo.InvariantCulture)}: "
            + $"{Trim(result.Combined)}",
            "dns.reapply");

    private static MyVpnError RestoreFailed(string action, CommandResult result) =>
        new(
            ErrorCodes.DnsRestoreFailed,
            "error.dns.restore_failed",
            ErrorSeverity.Critical,
            $"{action} failed with exit code {result.ExitCode.ToString(CultureInfo.InvariantCulture)}: "
            + $"{Trim(result.Combined)}",
            "network.restore");

    private static string Trim(string value) => value.Length <= 300 ? value : value[..300] + "…";

    private static bool DefaultElevationCheck()
    {
        if (OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            return GetEffectiveUserId() == 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint GetEffectiveUserId();

    // ------------------------------------------------------------------ private types

    private sealed record CapturedState(
        string Interface,
        LinuxDnsBackend Backend,
        IReadOnlyList<string> Servers,
        IReadOnlyList<string> SearchDomains,
        string Manager);

    private sealed record ResolvConfSnapshot(IReadOnlyList<string> Servers, IReadOnlyList<string> SearchDomains);

    private sealed record ResolvectlLink(string? Name, IReadOnlyList<string> Servers);
}
