using System.Globalization;
using System.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Linux.Tun;

namespace MyVpn.Platform.Linux.Network;

/// <summary>
/// Detects the network artefacts a previous run left behind on Linux and removes all of them.
/// </summary>
/// <remarks>
/// <para>
/// This class backs two features that must never fail silently: the startup "leftovers" check and
/// the "Restore network" button. The button is a required feature rather than a convenience — if a
/// crash, a power loss or a bug leaves firewall rules, routes or DNS in a broken state, a single
/// action has to get the user back online without editing firewall rules by hand.
/// </para>
/// <para>
/// <b>Resilience is the design, not a nicety.</b> <see cref="EmergencyCleanupAsync"/> attempts
/// every step even when an earlier one fails and reports each one separately, because stopping at
/// the first error is exactly the situation the user is trying to escape. It is also idempotent:
/// running it on a clean machine succeeds, and running it twice is safe. A cancelled token does
/// not abort the remaining steps either; a half-restored network is worse than a delayed one.
/// </para>
/// <para>
/// For its collaborators it depends on the abstractions only — <see cref="IKillSwitch"/>,
/// <see cref="IRouteManager"/>, <see cref="IDnsConfigurator"/> and <see cref="ISystemProxy"/> —
/// never on the concrete Linux implementations, so any of them can be absent (a platform that has
/// no system proxy, a trimmed build, a diagnostics-only host) without making cleanup impossible.
/// Every collaborator is optional and every probe tolerates null. Kernel state is observed through
/// the same <c>ip</c> argv calls and the same parser the TUN manager uses, so both agree on what
/// the interface holds.
/// </para>
/// </remarks>
public sealed class LinuxNetworkStateManager : INetworkStateManager
{
    /// <summary>Default tunnel interface name; must match the Xray TUN inbound's <c>name</c> field.</summary>
    public const string DefaultTunnelInterfaceName = "myvpn0";

    /// <summary>Default Kill Switch identifier; matches the nftables table name.</summary>
    public const string DefaultIdentifier = "myvpn_ks";

    /// <summary>Process name of the Xray core as it appears in <c>/proc/&lt;pid&gt;/comm</c>.</summary>
    public const string CoreProcessName = "xray";

    private const string IpTool = "ip";

    // DetailKey values are localization keys rendered by the UI; TechnicalDetail is raw log text
    // for the diagnostics bundle. No user-facing English sentence is ever returned as a key.
    private const string CompletedKey = "cleanup.step.completed";
    private const string NothingToDoKey = "cleanup.step.nothing_to_do";
    private const string NoManagerKey = "cleanup.step.no_manager";
    private const string StepFailedKey = "error.network.cleanup_step_failed";
    private const string CancelledKey = "error.operation.cancelled";
    private const string ProxyFailedKey = "error.proxy.restore_failed";
    private const string DnsFailedKey = "error.dns.restore_failed";
    private const string KillSwitchFailedKey = "error.killswitch.remove_failed";
    private const string RoutesFailedKey = "error.route.remove_failed";
    private const string InterfaceFailedKey = "error.tun.remove_failed";

    private readonly ICommandRunner _runner;
    private readonly IKillSwitch? _killSwitch;
    private readonly IRouteManager? _routes;
    private readonly IDnsConfigurator? _dns;
    private readonly ISystemProxy? _systemProxy;
    private readonly string _tunnelInterfaceName;
    private readonly string _identifier;

    /// <summary>
    /// Creates the manager.
    /// </summary>
    /// <param name="runner">Command runner used for the <c>ip</c> and <c>pgrep</c> probes.</param>
    /// <param name="killSwitch">Kill Switch, or <c>null</c> when this host has none wired.</param>
    /// <param name="routes">Route manager, or <c>null</c>.</param>
    /// <param name="dns">DNS configurator, or <c>null</c>.</param>
    /// <param name="systemProxy">System-proxy configurator, or <c>null</c>.</param>
    /// <param name="tunnelInterfaceName">The interface MyVpn configures; the only one it will touch.</param>
    /// <param name="identifier">Kill Switch identifier (nftables table name) MyVpn owns.</param>
    /// <remarks>
    /// The collaborators are nullable so the manager can be constructed with nothing but a runner —
    /// which is what the leftover checks and the restore path need in order to keep working when a
    /// platform executor is unavailable.
    /// </remarks>
    public LinuxNetworkStateManager(
        ICommandRunner? runner = null,
        IKillSwitch? killSwitch = null,
        IRouteManager? routes = null,
        IDnsConfigurator? dns = null,
        ISystemProxy? systemProxy = null,
        string tunnelInterfaceName = DefaultTunnelInterfaceName,
        string identifier = DefaultIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tunnelInterfaceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        // The interface name reaches argv in this class too, so it gets the same defence in depth
        // the TUN manager applies rather than being trusted because it came from settings.
        LinuxTunDeviceManager.ValidateInterfaceName(tunnelInterfaceName);

        _runner = runner ?? new ProcessCommandRunner();
        _killSwitch = killSwitch;
        _routes = routes;
        _dns = dns;
        _systemProxy = systemProxy;
        _tunnelInterfaceName = tunnelInterfaceName;
        _identifier = identifier;
    }

    /// <summary>Cleanup step identifiers, in the order they are attempted.</summary>
    public static class StepName
    {
        public const string Proxy = "proxy";
        public const string Dns = "dns";
        public const string KillSwitch = "kill-switch";
        public const string Routes = "routes";
        public const string Interface = "interface";
    }

    // ------------------------------------------------------------------ detection

    /// <summary>
    /// Reports what a previous run left behind, without changing anything.
    /// </summary>
    /// <remarks>
    /// This is a best-effort diagnostic: a probe that cannot run records why in
    /// <see cref="NetworkLeftovers.Details"/> instead of throwing, and a null collaborator is
    /// reported as "unknown" rather than as "clean". Consumers must not treat the result as proof
    /// that the machine is clean when the corresponding detail line says it could not be checked.
    /// </remarks>
    public async Task<NetworkLeftovers> DetectLeftoversAsync(CancellationToken cancellationToken)
    {
        var details = new List<string>();

        var tunnel = await InspectTunnelInterfaceAsync(details, cancellationToken).ConfigureAwait(false);
        var killSwitch = await InspectKillSwitchAsync(details, cancellationToken).ConfigureAwait(false);
        var routes = await InspectRoutesAsync(details, cancellationToken).ConfigureAwait(false);
        var dns = await InspectDnsAsync(tunnel.Addresses, details, cancellationToken).ConfigureAwait(false);
        var proxy = await InspectSystemProxyAsync(details, cancellationToken).ConfigureAwait(false);
        var core = await InspectCoreProcessAsync(details, cancellationToken).ConfigureAwait(false);

        return new NetworkLeftovers
        {
            KillSwitchRulesPresent = killSwitch,
            TunnelInterfacePresent = tunnel.Present,
            RoutesPresent = routes,
            DnsOverridden = dns,
            SystemProxySet = proxy,
            CoreProcessRunning = core,
            Details = details,
        };
    }

    private async Task<(bool Present, IReadOnlyList<string> Addresses)> InspectTunnelInterfaceAsync(
        List<string> details,
        CancellationToken cancellationToken)
    {
        try
        {
            var link = await _runner
                .RunAsync(IpTool, new[] { "link", "show", _tunnelInterfaceName }, cancellationToken)
                .ConfigureAwait(false);

            if (!link.Succeeded)
            {
                details.Add(
                    $"tunnel interface '{_tunnelInterfaceName}': absent (ip link show exited {link.ExitCode})");
                return (false, Array.Empty<string>());
            }

            IReadOnlyList<string> addresses = Array.Empty<string>();

            var addressResult = await _runner
                .RunAsync(
                    IpTool,
                    new[] { "-brief", "address", "show", "dev", _tunnelInterfaceName },
                    cancellationToken)
                .ConfigureAwait(false);

            if (addressResult.Succeeded && !string.IsNullOrEmpty(addressResult.StandardOutput))
            {
                addresses = LinuxTunDeviceManager.ParseAddresses(_tunnelInterfaceName, addressResult.StandardOutput);
            }

            details.Add(addresses.Count == 0
                ? $"tunnel interface '{_tunnelInterfaceName}': present, no addresses assigned"
                : $"tunnel interface '{_tunnelInterfaceName}': present, addresses {string.Join(", ", addresses)}");

            return (true, addresses);
        }
        catch (Exception ex)
        {
            details.Add(
                $"tunnel interface probe failed ({ErrorCodes.TunMissing}): {ex.GetType().Name}: {ex.Message}");
            return (false, Array.Empty<string>());
        }
    }

    private async Task<bool> InspectKillSwitchAsync(List<string> details, CancellationToken cancellationToken)
    {
        if (_killSwitch is null)
        {
            details.Add(
                "kill switch: no IKillSwitch is wired on this host, so firewall rules cannot be inspected "
                + $"({ErrorCodes.KillSwitchVerificationFailed})");
            return false;
        }

        try
        {
            var state = await _killSwitch.InspectAsync(null, cancellationToken).ConfigureAwait(false);
            var present = state.IsArmed || state.IsDrifted || state.OrphanedRules.Count > 0;

            details.Add(
                $"kill switch ({state.MechanismName ?? _killSwitch.MechanismName}): armed={state.IsArmed} "
                + $"drifted={state.IsDrifted} orphaned={state.OrphanedRules.Count} supported={_killSwitch.IsSupported}");

            foreach (var orphan in state.OrphanedRules)
            {
                details.Add($"kill switch orphaned rule: {orphan}");
            }

            return present;
        }
        catch (Exception ex)
        {
            details.Add(
                $"kill switch inspection failed ({ErrorCodes.KillSwitchVerificationFailed}): "
                + $"{ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private async Task<bool> InspectRoutesAsync(List<string> details, CancellationToken cancellationToken)
    {
        var present = false;

        if (_routes is null)
        {
            details.Add(
                "routes: no IRouteManager is wired on this host, so only the kernel routing table is inspected");
        }
        else
        {
            try
            {
                var state = await _routes.InspectAsync(null, cancellationToken).ConfigureAwait(false);
                present = state.TunnelRoutesPresent || state.BypassRoutesPresent || state.OrphanedRoutes.Count > 0;

                details.Add(
                    $"routes ({(_routes.IsSupported ? "supported" : "unsupported")}): "
                    + $"tunnel={state.TunnelRoutesPresent} bypass={state.BypassRoutesPresent} "
                    + $"orphaned={state.OrphanedRoutes.Count}");

                foreach (var orphan in state.OrphanedRoutes)
                {
                    details.Add($"routes orphaned entry: {orphan}");
                }
            }
            catch (Exception ex)
            {
                details.Add(
                    $"route inspection failed ({ErrorCodes.RouteAddFailed}): {ex.GetType().Name}: {ex.Message}");
            }
        }

        // Independent cross-check from the kernel, which is also the only signal available when no
        // route manager is wired: any route that sends traffic at our interface name is ours.
        try
        {
            var kernelRoutes = await _runner
                .RunAsync(IpTool, new[] { "route", "show", "table", "all" }, cancellationToken)
                .ConfigureAwait(false);

            if (!kernelRoutes.Succeeded)
            {
                details.Add($"kernel routing table could not be read (ip route show exited {kernelRoutes.ExitCode})");
            }
            else
            {
                var viaTunnel = kernelRoutes.StandardOutput
                    .Split('\n')
                    .Where(line => line.Contains($"dev {_tunnelInterfaceName}", StringComparison.Ordinal))
                    .ToArray();

                if (viaTunnel.Length > 0)
                {
                    present = true;
                    details.Add(
                        $"kernel routing table: {viaTunnel.Length} route(s) via '{_tunnelInterfaceName}'");

                    foreach (var route in viaTunnel.Take(5))
                    {
                        details.Add($"kernel route: {route.Trim()}");
                    }
                }
                else
                {
                    details.Add($"kernel routing table: no route via '{_tunnelInterfaceName}'");
                }
            }
        }
        catch (Exception ex)
        {
            details.Add(
                $"kernel routing table probe failed ({ErrorCodes.RouteRemoveFailed}): {ex.GetType().Name}: {ex.Message}");
        }

        return present;
    }

    private async Task<bool> InspectDnsAsync(
        IReadOnlyList<string> tunnelAddresses,
        List<string> details,
        CancellationToken cancellationToken)
    {
        if (_dns is null)
        {
            details.Add(
                "dns: no IDnsConfigurator is wired on this host, so a resolver override can neither be "
                + "detected nor reverted");
            return false;
        }

        try
        {
            var state = await _dns.InspectAsync(cancellationToken).ConfigureAwait(false);

            var boundToTunnel = state.InterfaceName is not null
                                && string.Equals(state.InterfaceName, _tunnelInterfaceName, StringComparison.Ordinal);

            // Second, independent signal: a resolver that is one of the tunnel interface's own
            // addresses can only have been installed for MyVpn. It matters because an executor may
            // legitimately report no interface name while still having changed the resolver.
            var resolverOnTunnel = tunnelAddresses.Count > 0
                                   && state.ActiveServers.Any(server =>
                                       tunnelAddresses.Any(address => ResolverMatchesTunnelAddress(server, address)));

            details.Add(
                $"dns ({(_dns.IsSupported ? "supported" : "unsupported")}): {state.ActiveServers.Count} active "
                + $"resolver(s) [{string.Join(", ", state.ActiveServers)}], interface={state.InterfaceName ?? "(unknown)"}, "
                + $"tunnel_bound={boundToTunnel || resolverOnTunnel}, "
                + $"plain_dns_outside_tunnel={state.PlainDnsReachableOutsideTunnel}");

            foreach (var leak in state.PotentialLeaks)
            {
                details.Add($"dns potential leak: {leak}");
            }

            return boundToTunnel || resolverOnTunnel;
        }
        catch (Exception ex)
        {
            details.Add($"dns inspection failed ({ErrorCodes.DnsConfigureFailed}): {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private async Task<bool> InspectSystemProxyAsync(List<string> details, CancellationToken cancellationToken)
    {
        if (_systemProxy is null)
        {
            details.Add("system proxy: no ISystemProxy is wired on this host, so it cannot be inspected");
            return false;
        }

        try
        {
            var state = await _systemProxy.InspectAsync(cancellationToken).ConfigureAwait(false);

            details.Add(
                $"system proxy ({(_systemProxy.IsSupported ? "supported" : "unsupported")}): "
                + $"configured={state.IsConfigured} points_at_myvpn={state.PointsAtMyVpn} "
                + $"active={state.ActiveProxy ?? "(none)"} pac={state.PacUrl ?? "(none)"}");

            return state.IsConfigured;
        }
        catch (Exception ex)
        {
            details.Add(
                $"system proxy inspection failed ({ErrorCodes.SystemProxySetFailed}): "
                + $"{ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Checks whether an Xray core is still running.
    /// </summary>
    /// <remarks>
    /// Detection only. MyVpn never signals the core from here: a core that is still running is
    /// normally supervised by the service, which owns its shutdown path, and a stray signal from a
    /// recovery button would turn a partial failure into a crash loop. <c>/proc</c> is read
    /// directly, with <c>pgrep -x</c> as a fallback when <c>/proc</c> is not mounted. Nothing in
    /// this class ever calls <c>pkill</c>.
    /// </remarks>
    private async Task<bool> InspectCoreProcessAsync(List<string> details, CancellationToken cancellationToken)
    {
        try
        {
            var found = FindCoreProcessInProc();
            if (found is not null)
            {
                details.Add($"core process: '{found.Value.Name}' is running (pid {found.Value.Pid}, from /proc)");
                return true;
            }

            if (_runner.Exists("pgrep"))
            {
                var pgrep = await _runner
                    .RunAsync("pgrep", new[] { "-x", CoreProcessName }, cancellationToken)
                    .ConfigureAwait(false);

                var pids = pgrep.Succeeded
                    ? pgrep.StandardOutput
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                        .Select(line => line.Trim())
                        .Where(line => line.Length > 0)
                        .ToArray()
                    : Array.Empty<string>();

                if (pids.Length > 0)
                {
                    details.Add(
                        $"core process: '{CoreProcessName}' is running (pid {string.Join(", ", pids)}, from pgrep)");
                    return true;
                }

                details.Add(
                    $"core process: no '{CoreProcessName}' process found (/proc scan and pgrep -x both empty)");
            }
            else
            {
                details.Add($"core process: no '{CoreProcessName}' process found in /proc");
            }

            return false;
        }
        catch (Exception ex)
        {
            details.Add(
                $"core process probe failed ({ErrorCodes.DiagnosticsCheckFailed}): {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    /// <summary>Scans <c>/proc/&lt;pid&gt;/comm</c> for the core process.</summary>
    private static (int Pid, string Name)? FindCoreProcessInProc()
    {
        if (!Directory.Exists("/proc"))
        {
            return null;
        }

        foreach (var directory in Directory.EnumerateDirectories("/proc"))
        {
            var entry = Path.GetFileName(directory);
            if (!int.TryParse(entry, NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
            {
                continue;
            }

            try
            {
                var comm = File.ReadAllText(Path.Combine(directory, "comm")).Trim();
                if (string.Equals(comm, CoreProcessName, StringComparison.OrdinalIgnoreCase))
                {
                    return (pid, comm);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                // A process that exited mid-scan, or one this process may not inspect. Since Linux
                // 4.2 an unreadable comm under hidepid=2 is reported as EACCES, not as empty.
            }
        }

        return null;
    }

    private static bool ResolverMatchesTunnelAddress(string resolver, string tunnelAddress)
    {
        var candidate = resolver.Trim();

        // systemd-resolved renders "1.1.1.1#53"; the address itself is what has to match.
        var comment = candidate.IndexOf('#');
        if (comment > 0)
        {
            candidate = candidate[..comment];
        }

        var slash = tunnelAddress.IndexOf('/');
        var local = slash > 0 ? tunnelAddress[..slash] : tunnelAddress;

        if (IPAddress.TryParse(candidate, out var resolverAddress)
            && IPAddress.TryParse(local, out var tunnelIp))
        {
            return resolverAddress.Equals(tunnelIp);
        }

        return string.Equals(candidate, local, StringComparison.OrdinalIgnoreCase);
    }

    // ------------------------------------------------------------------ emergency cleanup

    /// <summary>
    /// Attempts every cleanup action in the documented order and reports each one.
    /// </summary>
    /// <remarks>
    /// Order: system proxy → DNS → Kill Switch → routes → tunnel interface. The proxy and DNS go
    /// first because they are what makes a machine with no working tunnel look completely broken —
    /// a proxy or resolver pointing at a listener that no longer exists. The Kill Switch is removed
    /// before the routes and interface so the machine is not left fail-closed against a tunnel that
    /// is about to disappear. Each step is attempted regardless of what happened before it.
    /// </remarks>
    public async Task<CleanupReport> EmergencyCleanupAsync(CancellationToken cancellationToken)
    {
        var steps = new List<CleanupStep>(5);

        steps.Add(await ResetSystemProxyAsync(cancellationToken).ConfigureAwait(false));
        steps.Add(await RevertDnsAsync(cancellationToken).ConfigureAwait(false));
        steps.Add(await RemoveKillSwitchAsync(cancellationToken).ConfigureAwait(false));
        steps.Add(await RemoveRoutesAsync(cancellationToken).ConfigureAwait(false));
        steps.Add(await RemoveTunnelInterfaceAsync(cancellationToken).ConfigureAwait(false));

        return CleanupReport.FromSteps(steps);
    }

    private async Task<CleanupStep> ResetSystemProxyAsync(CancellationToken cancellationToken)
    {
        if (_systemProxy is null)
        {
            return new CleanupStep(
                StepName.Proxy,
                true,
                NoManagerKey,
                "No ISystemProxy is wired on this host; the system proxy was left untouched.");
        }

        // ResetAsync, not RestoreAsync: emergency cleanup has no captured snapshot, and a proxy
        // pointing at a dead listener survives a reboot. Turning it off is the only action that
        // reliably returns the machine to a working state, so the original values are not guessed.
        return await AttemptAsync(
                StepName.Proxy,
                ProxyFailedKey,
                "system proxy reset",
                async () => CleanupOutcome.FromResult(
                    await _systemProxy.ResetAsync(cancellationToken).ConfigureAwait(false)))
            .ConfigureAwait(false);
    }

    private async Task<CleanupStep> RevertDnsAsync(CancellationToken cancellationToken)
    {
        if (_dns is null)
        {
            return new CleanupStep(
                StepName.Dns,
                true,
                NoManagerKey,
                "No IDnsConfigurator is wired on this host; the resolver configuration was left untouched.");
        }

        return await AttemptAsync(
                StepName.Dns,
                DnsFailedKey,
                "dns revert",
                async () => CleanupOutcome.FromResult(
                    await _dns.RemoveAllOwnedAsync(cancellationToken).ConfigureAwait(false)))
            .ConfigureAwait(false);
    }

    private async Task<CleanupStep> RemoveKillSwitchAsync(CancellationToken cancellationToken)
    {
        if (_killSwitch is null)
        {
            return new CleanupStep(
                StepName.KillSwitch,
                true,
                NoManagerKey,
                "No IKillSwitch is wired on this host; no firewall rules were removed.");
        }

        // IsSupported is deliberately not consulted: a mechanism that reports itself unsupported
        // can still have left rules behind from a previous run, and RemoveAsync is idempotent by
        // contract, so the honest thing is to ask it to clean up and report what it says.
        return await AttemptAsync(
                StepName.KillSwitch,
                KillSwitchFailedKey,
                $"kill switch removal ('{_identifier}')",
                async () => CleanupOutcome.FromKillSwitch(
                    await _killSwitch.RemoveAsync(_identifier, cancellationToken).ConfigureAwait(false)))
            .ConfigureAwait(false);
    }

    private async Task<CleanupStep> RemoveRoutesAsync(CancellationToken cancellationToken)
    {
        if (_routes is null)
        {
            return new CleanupStep(
                StepName.Routes,
                true,
                NoManagerKey,
                "No IRouteManager is wired on this host; no routes were removed.");
        }

        // RemoveAllOwnedAsync rather than RemoveAsync(plan): after a crash the settings may have
        // changed, and the whole point is to recover from a state the application no longer has a
        // coherent model of. Ownership is determined from the routes themselves.
        return await AttemptAsync(
                StepName.Routes,
                RoutesFailedKey,
                "route removal",
                async () => CleanupOutcome.FromResult(
                    await _routes.RemoveAllOwnedAsync(cancellationToken).ConfigureAwait(false)))
            .ConfigureAwait(false);
    }

    private async Task<CleanupStep> RemoveTunnelInterfaceAsync(CancellationToken cancellationToken)
    {
        var description = $"tunnel interface '{_tunnelInterfaceName}'";

        try
        {
            var probe = await _runner
                .RunAsync(IpTool, new[] { "link", "show", _tunnelInterfaceName }, cancellationToken)
                .ConfigureAwait(false);

            if (!probe.Succeeded)
            {
                return new CleanupStep(
                    StepName.Interface,
                    true,
                    NothingToDoKey,
                    $"{description}: does not exist (ip link show exited {probe.ExitCode}); nothing to delete");
            }

            // Ownership is by name. MyVpn only ever manages the one interface name it configured for
            // the Xray TUN inbound; it never enumerates interfaces and never touches another one.
            var down = await _runner
                .RunAsync(IpTool, new[] { "link", "set", "dev", _tunnelInterfaceName, "down" }, cancellationToken)
                .ConfigureAwait(false);

            var deleted = await _runner
                .RunAsync(IpTool, new[] { "link", "delete", "dev", _tunnelInterfaceName }, cancellationToken)
                .ConfigureAwait(false);

            var fallbackDetail = string.Empty;

            if (!deleted.Succeeded)
            {
                // A device created with `ip tuntap add` is also removable through the tuntap
                // subcommand, so a refused `ip link delete` gets one more honest attempt.
                deleted = await _runner
                    .RunAsync(
                        IpTool,
                        new[] { "tuntap", "del", "dev", _tunnelInterfaceName, "mode", "tun" },
                        cancellationToken)
                    .ConfigureAwait(false);

                fallbackDetail = deleted.Succeeded
                    ? " (removed with `ip tuntap del`)"
                    : $"; `ip tuntap del` also failed: {Trim(deleted.Combined)}";
            }

            // Read back rather than trusting the exit code. Xray owns the descriptor, so the device
            // can survive a "successful" delete while the core still holds it, and reporting a clean
            // state that is not clean is the one answer the user cannot act on.
            var verify = await _runner
                .RunAsync(IpTool, new[] { "link", "show", _tunnelInterfaceName }, cancellationToken)
                .ConfigureAwait(false);

            if (verify.Succeeded)
            {
                return new CleanupStep(
                    StepName.Interface,
                    false,
                    InterfaceFailedKey,
                    $"{description}: still present after down/delete (ip link show exited 0); "
                    + $"output '{Trim(verify.Combined)}'{fallbackDetail}".Trim());
            }

            var downDetail = down.Succeeded ? "down" : $"down failed ({Trim(down.Combined)})";

            return new CleanupStep(
                StepName.Interface,
                true,
                CompletedKey,
                $"{description}: removed ({downDetail}, then deleted){fallbackDetail}");
        }
        catch (OperationCanceledException)
        {
            return new CleanupStep(
                StepName.Interface,
                false,
                CancelledKey,
                $"{description}: cancelled before it completed");
        }
        catch (Exception ex)
        {
            return new CleanupStep(
                StepName.Interface,
                false,
                StepFailedKey,
                $"{description}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ------------------------------------------------------------------ internals

    /// <summary>
    /// One collaborator call, normalised across the two result shapes the abstractions use
    /// (<see cref="Result"/> for routing, DNS and the proxy, <see cref="KillSwitchApplyResult"/>
    /// for the firewall).
    /// </summary>
    private readonly record struct CleanupOutcome(bool Succeeded, MyVpnError? Error, string? Output)
    {
        public static CleanupOutcome FromResult(Result result) => new(result.IsSuccess, result.Error, null);

        public static CleanupOutcome FromKillSwitch(KillSwitchApplyResult result) =>
            new(result.Succeeded, result.Error, result.PlatformOutput);
    }

    private static async Task<CleanupStep> AttemptAsync(
        string stepName,
        string failureKey,
        string description,
        Func<Task<CleanupOutcome>> action)
    {
        try
        {
            var outcome = await action().ConfigureAwait(false);

            if (outcome.Succeeded)
            {
                return new CleanupStep(stepName, true, CompletedKey, $"{description}: completed");
            }

            var error = outcome.Error;

            // The collaborator's own key is more specific ("needs privileges", "tool missing") than
            // a single generic step key, so it wins when it is present.
            return new CleanupStep(
                stepName,
                false,
                string.IsNullOrWhiteSpace(error?.MessageKey) ? failureKey : error!.MessageKey,
                $"{description}: {Describe(error, outcome.Output, failureKey)}");
        }
        catch (OperationCanceledException)
        {
            // Best effort by design: a cancelled token must not stop the remaining steps, because a
            // half-restored network is precisely what this method exists to prevent.
            return new CleanupStep(stepName, false, CancelledKey, $"{description}: cancelled before it completed");
        }
        catch (Exception ex)
        {
            return new CleanupStep(
                stepName,
                false,
                StepFailedKey,
                $"{description}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static string Describe(MyVpnError? error, string? output, string fallbackKey)
    {
        var code = error?.Code ?? fallbackKey;
        var detail = error?.TechnicalDetail ?? error?.MessageKey ?? "failed without an error value";

        return output is null
            ? $"{code}: {detail}"
            : $"{code}: {detail} | platform output: {Trim(output)}";
    }

    /// <summary>Flattens platform output to a single bounded line for the diagnostics bundle.</summary>
    private static string Trim(string? value)
    {
        var text = (value ?? string.Empty)
            .Replace('\n', ' ')
            .Replace('\r', ' ')
            .Trim();

        return text.Length <= 300 ? text : text[..300] + "…";
    }
}
