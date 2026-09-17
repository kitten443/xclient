using System.Diagnostics;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.Platform.Windows.Execution;
using MyVpn.Platform.Windows.Routing;
using MyVpn.Platform.Windows.Tun;

namespace MyVpn.Platform.Windows.Network;

/// <summary>
/// Detects the network artefacts a previous run left behind on Windows and removes all of them.
/// </summary>
/// <remarks>
/// <para>
/// This class backs two features that must never fail silently: the startup "leftovers" check and
/// the "Restore network" button. The button is a required feature rather than a convenience — if a
/// crash, a power loss or a bug leaves firewall filters, routes or DNS in a broken state, one
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
/// never on the concrete Windows implementations, so any of them can be absent without making
/// cleanup impossible. Every collaborator is optional and every probe tolerates null.
/// </para>
/// <para>
/// <b>What cannot be restored.</b> There is no transactional rollback for routes, interface DNS
/// or WFP policy on Windows: only the persistent stores (<c>/p</c>, <c>store=persistent</c>) leave
/// a copy behind, which is exactly why MyVpn installs everything into the active store and keeps
/// its own record. And the Wintun adapter itself belongs to the core process — Windows removes it
/// when the core exits, so this class reports a surviving adapter rather than pretending to
/// delete something it does not own.
/// </para>
/// </remarks>
public sealed class WindowsNetworkStateManager : INetworkStateManager
{
    /// <summary>Default tunnel interface name; must match the Xray TUN inbound's <c>name</c> field.</summary>
    public const string DefaultTunnelInterfaceName = "myvpn0";

    /// <summary>Default Kill Switch identifier; matches the WFP provider/sub-layer identity.</summary>
    public const string DefaultIdentifier = "myvpn_ks";

    /// <summary>Process name of the Xray core, as <c>xray.exe</c> appears without its extension.</summary>
    public const string CoreProcessName = "xray";

    /// <summary>Prefix of every adapter MyVpn creates; the ownership marker.</summary>
    private const string OwnedInterfacePrefix = "myvpn";

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

    private readonly IKillSwitch? _killSwitch;
    private readonly IRouteManager? _routes;
    private readonly IDnsConfigurator? _dns;
    private readonly ISystemProxy? _systemProxy;
    private readonly string _tunnelInterfaceName;
    private readonly string _identifier;

    /// <summary>
    /// Creates the manager.
    /// </summary>
    /// <param name="killSwitch">Kill Switch, or <c>null</c> when this host has none wired.</param>
    /// <param name="routes">Route manager, or <c>null</c>.</param>
    /// <param name="dns">DNS configurator, or <c>null</c>.</param>
    /// <param name="systemProxy">System-proxy configurator, or <c>null</c>.</param>
    /// <param name="tunnelInterfaceName">The interface MyVpn configures; the only one it will touch.</param>
    /// <param name="identifier">Kill Switch identifier MyVpn owns.</param>
    /// <remarks>
    /// The collaborators are nullable so the manager can be constructed with nothing at all —
    /// which is what the leftover checks and the restore path need in order to keep working when a
    /// platform executor is unavailable.
    /// </remarks>
    public WindowsNetworkStateManager(
        IKillSwitch? killSwitch = null,
        IRouteManager? routes = null,
        IDnsConfigurator? dns = null,
        ISystemProxy? systemProxy = null,
        string tunnelInterfaceName = DefaultTunnelInterfaceName,
        string identifier = DefaultIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tunnelInterfaceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        // The name reaches netsh and route.exe argv from this class too, so it gets the same
        // defence in depth the TUN manager applies rather than being trusted because it came from
        // settings.
        WindowsTunDeviceManager.ValidateInterfaceName(tunnelInterfaceName);

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

        var tunnel = InspectTunnelInterface(details);
        var killSwitch = await InspectKillSwitchAsync(details, cancellationToken).ConfigureAwait(false);
        var routes = await InspectRoutesAsync(details, cancellationToken).ConfigureAwait(false);
        var dns = await InspectDnsAsync(details, cancellationToken).ConfigureAwait(false);
        var proxy = await InspectSystemProxyAsync(details, cancellationToken).ConfigureAwait(false);
        var core = InspectCoreProcess(details);

        return new NetworkLeftovers
        {
            KillSwitchRulesPresent = killSwitch,
            TunnelInterfacePresent = tunnel,
            RoutesPresent = routes,
            DnsOverridden = dns,
            SystemProxySet = proxy,
            CoreProcessRunning = core,
            Details = details,
        };
    }

    private bool InspectTunnelInterface(List<string> details)
    {
        if (!WindowsPlatform.IsWindows)
        {
            details.Add(
                $"tunnel interface '{_tunnelInterfaceName}': not probed (GetAdaptersAddresses requires "
                + $"Windows; {ErrorCodes.TunMissing})");
            return false;
        }

        try
        {
            var adapter = WindowsAdapters.FindByName(_tunnelInterfaceName);

            if (adapter is null)
            {
                details.Add($"tunnel interface '{_tunnelInterfaceName}': absent");
                return false;
            }

            details.Add($"tunnel interface '{_tunnelInterfaceName}': present, {WindowsTunDeviceManager.Describe(adapter)}");
            return true;
        }
        catch (Exception ex)
        {
            details.Add(
                $"tunnel interface probe failed ({ErrorCodes.TunMissing}): {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private async Task<bool> InspectKillSwitchAsync(List<string> details, CancellationToken cancellationToken)
    {
        if (_killSwitch is null)
        {
            details.Add(
                "kill switch: no IKillSwitch is wired on this host, so WFP filters cannot be inspected "
                + $"({ErrorCodes.KillSwitchVerificationFailed})");
            return false;
        }

        try
        {
            var state = await _killSwitch.InspectAsync(null, cancellationToken).ConfigureAwait(false);
            var present = state.IsArmed || state.IsDrifted || state.OrphanedRules.Count > 0;

            details.Add(
                $"kill switch ({state.MechanismName ?? _killSwitch.MechanismName}): armed={state.IsArmed} "
                + $"drifted={state.IsDrifted} orphaned={state.OrphanedRules.Count} "
                + $"supported={_killSwitch.IsSupported}");

            foreach (var orphan in state.OrphanedRules)
            {
                details.Add($"kill switch orphaned filter: {orphan}");
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
                "routes: no IRouteManager is wired on this host, so only the live routing table is inspected");
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

        // Independent cross-check from the live table, which is also the only signal available when
        // no route manager is wired: any route whose outgoing adapter is a MyVpn one is ours.
        if (!WindowsPlatform.IsWindows)
        {
            details.Add("kernel routing table: not probed (GetIpForwardTable2 requires Windows)");
            return present;
        }

        try
        {
            var rows = WindowsIpForwardTable.Read(ipv6: false, out var v4Error)
                .Concat(WindowsIpForwardTable.Read(ipv6: true, out var v6Error))
                .Where(row => row.InterfaceName is not null
                              && row.InterfaceName.StartsWith(OwnedInterfacePrefix, StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (rows.Length > 0)
            {
                present = true;
                details.Add($"kernel routing table: {rows.Length} route(s) on a MyVpn adapter");

                foreach (var row in rows.Take(5))
                {
                    details.Add(
                        $"kernel route: {row.Destination} via {row.NextHop ?? "on-link"} dev '{row.InterfaceName}'");
                }
            }
            else
            {
                details.Add("kernel routing table: no route on a MyVpn adapter");
            }

            if (v4Error is not null || v6Error is not null)
            {
                details.Add($"kernel routing table partially unreadable: {v4Error ?? v6Error}");
            }
        }
        catch (Exception ex)
        {
            details.Add(
                $"kernel routing table probe failed ({ErrorCodes.RouteRemoveFailed}): "
                + $"{ex.GetType().Name}: {ex.Message}");
        }

        return present;
    }

    private async Task<bool> InspectDnsAsync(List<string> details, CancellationToken cancellationToken)
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
                                && string.Equals(state.InterfaceName, _tunnelInterfaceName, StringComparison.OrdinalIgnoreCase);

            details.Add(
                $"dns ({(_dns.IsSupported ? "supported" : "unsupported")}): {state.ActiveServers.Count} "
                + $"active resolver(s) [{string.Join(", ", state.ActiveServers)}], "
                + $"interface={state.InterfaceName ?? "(unknown)"}, tunnel_bound={boundToTunnel}, "
                + $"plain_dns_outside_tunnel={state.PlainDnsReachableOutsideTunnel}");

            foreach (var leak in state.PotentialLeaks)
            {
                details.Add($"dns potential leak: {leak}");
            }

            return boundToTunnel;
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
    /// Detection only. MyVpn never kills the core from here: a core that is still running is
    /// normally supervised by the service, which owns its shutdown path, and a stray kill from a
    /// recovery button would turn a partial failure into a crash loop. The process list is read
    /// through the managed API, which needs no elevation and no external tool.
    /// </remarks>
    private static bool InspectCoreProcess(List<string> details)
    {
        if (!WindowsPlatform.IsWindows)
        {
            details.Add(
                $"core process: not probed (process enumeration by image name is Windows-only; "
                + $"{ErrorCodes.DiagnosticsCheckFailed})");
            return false;
        }

        try
        {
            var processes = Process.GetProcessesByName(CoreProcessName);

            try
            {
                if (processes.Length == 0)
                {
                    details.Add($"core process: no '{CoreProcessName}' process is running");
                    return false;
                }

                details.Add(
                    $"core process: '{CoreProcessName}' is running (pid "
                    + $"{string.Join(", ", processes.Select(p => p.Id))})");
                return true;
            }
            finally
            {
                foreach (var process in processes)
                {
                    process.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            details.Add(
                $"core process probe failed ({ErrorCodes.DiagnosticsCheckFailed}): {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    // ------------------------------------------------------------------ emergency cleanup

    /// <summary>
    /// Attempts every cleanup action in the documented order and reports each one.
    /// </summary>
    /// <remarks>
    /// Order: system proxy → DNS → Kill Switch → routes → tunnel interface. The proxy and DNS go
    /// first because they are what makes a machine with no working tunnel look completely broken —
    /// a proxy or resolver pointing at a listener that no longer exists. The Kill Switch is removed
    /// before the routes and the adapter so the machine is not left fail-closed against a tunnel
    /// that is about to disappear. Each step is attempted regardless of what happened before it.
    /// </remarks>
    public async Task<CleanupReport> EmergencyCleanupAsync(CancellationToken cancellationToken)
    {
        var steps = new List<CleanupStep>(5);

        steps.Add(await ResetSystemProxyAsync(cancellationToken).ConfigureAwait(false));
        steps.Add(await RevertDnsAsync(cancellationToken).ConfigureAwait(false));
        steps.Add(await RemoveKillSwitchAsync(cancellationToken).ConfigureAwait(false));
        steps.Add(await RemoveRoutesAsync(cancellationToken).ConfigureAwait(false));
        steps.Add(RemoveTunnelInterface());

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

        // ResetAsync, not RestoreAsync: emergency cleanup has no captured snapshot, and a WinINET
        // proxy pointing at a dead port survives a reboot. Turning it off is the only action that
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
                "No IKillSwitch is wired on this host; no WFP filters were removed.");
        }

        // IsSupported is deliberately not consulted: a mechanism that reports itself unsupported
        // can still have left objects behind from a previous run, and RemoveAsync is idempotent by
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
        // coherent model of.
        return await AttemptAsync(
                StepName.Routes,
                RoutesFailedKey,
                "route removal",
                async () => CleanupOutcome.FromResult(
                    await _routes.RemoveAllOwnedAsync(cancellationToken).ConfigureAwait(false)))
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Reports the state of the tunnel adapter, which MyVpn does not own.
    /// </summary>
    /// <remarks>
    /// The Wintun adapter is created and destroyed by the core process. Windows removes it when the
    /// last handle closes, so an adapter that is still present means the core is still running (or
    /// died without releasing its device). MyVpn cannot delete it from here — that needs
    /// <c>WintunDeleteAdapter</c> from <c>wintun.dll</c>, which only the owning process loads — and
    /// pretending to have removed it would leave the user believing the tunnel is gone.
    /// </remarks>
    private CleanupStep RemoveTunnelInterface()
    {
        var description = $"tunnel adapter '{_tunnelInterfaceName}'";

        if (!WindowsPlatform.IsWindows)
        {
            return new CleanupStep(
                StepName.Interface,
                true,
                NothingToDoKey,
                $"{description}: not probed (GetAdaptersAddresses requires Windows)");
        }

        try
        {
            var adapter = WindowsAdapters.FindByName(_tunnelInterfaceName);

            if (adapter is null)
            {
                return new CleanupStep(
                    StepName.Interface,
                    true,
                    NothingToDoKey,
                    $"{description}: does not exist; nothing to remove");
            }

            return new CleanupStep(
                StepName.Interface,
                false,
                InterfaceFailedKey,
                $"{description}: still present ({WindowsTunDeviceManager.Describe(adapter)}). The Wintun "
                + "adapter is owned by the core process and is removed by Windows when that process "
                + "exits; MyVpn does not delete an adapter it does not own. Stop the core or reboot to "
                + "remove it.");
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

            // The collaborator's own key is more specific ("needs privileges", "not available")
            // than a single generic step key, so it wins when it is present.
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
            : $"{code}: {detail} | platform output: {WindowsPlatform.Trim(output)}";
    }
}
