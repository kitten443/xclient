using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.Platform.MacOS.Dns;
using MyVpn.Platform.MacOS.Tun;

namespace MyVpn.Platform.MacOS.Network;

/// <summary>
/// Detects the network artefacts a previous run left behind on macOS and removes all of them.
/// </summary>
/// <remarks>
/// <para>
/// This class backs two features that must never fail silently: the startup "leftovers" check and the
/// <c>RESTORE NETWORK</c> button. The button is a required feature rather than a convenience — if a
/// crash, a power loss or a bug leaves PF rules, routes, DNS or a proxy in a broken state, one action
/// has to get the user back online without editing firewall rules by hand.
/// </para>
/// <para>
/// <b>Resilience is the design, not a nicety.</b> <see cref="EmergencyCleanupAsync"/> attempts every
/// step even when an earlier one fails and reports each separately, because stopping at the first error
/// is exactly the situation the user is trying to escape. It is also idempotent: running it on a clean
/// machine succeeds, running it twice is safe, and a cancelled token does not abort the remaining steps
/// — a half-restored network is worse than a delayed one.
/// </para>
/// <para>
/// <b>Order: system proxy → DNS → Kill Switch → routes → interface.</b> Proxy and DNS come first
/// because they are what makes a machine with no working tunnel look completely broken — a proxy or a
/// resolver pointing at a listener or an interface that no longer exists. The Kill Switch is removed
/// before the routes and the interface so the machine is not left fail-closed against a tunnel that is
/// about to disappear. Every step is attempted regardless of what happened before it.
/// </para>
/// <para>
/// <b>Collaborators come from the abstractions only</b> — <see cref="IKillSwitch"/>,
/// <see cref="IRouteManager"/>, <see cref="IDnsConfigurator"/>, <see cref="ISystemProxy"/> and
/// <see cref="ITunDeviceManager"/> — never from the concrete macOS classes, so any of them may be
/// absent (a trimmed build, a diagnostics-only host, a platform with no system proxy) without making
/// cleanup impossible. Every collaborator is optional and every probe tolerates <c>null</c>: the
/// manager must be constructible with nothing but a command runner, and it must not throw.
/// </para>
/// <para>
/// <b>The utun device is not MyVpn's to delete.</b> The core owns the control socket; closing it
/// removes the device and XNU removes its routes. The interface step therefore <i>observes</i> and
/// reports rather than destroying, which is also why this manager can honestly claim a clean result
/// when no utun is present.
/// </para>
/// </remarks>
public sealed class MacNetworkStateManager : INetworkStateManager
{
    /// <summary>Default tunnel interface name; must match what MyVpn asked the core for.</summary>
    public const string DefaultTunnelInterfaceName = MacTunDeviceManager.DefaultTunName;

    /// <summary>Default Kill Switch identifier.</summary>
    public const string DefaultIdentifier = "myvpn";

    /// <summary>Process name of the Xray core as <c>pgrep -x</c> would match it.</summary>
    public const string CoreProcessName = "xray";

    private const string IfconfigBinary = "ifconfig";
    private const string PgrepBinary = "pgrep";

    // DetailKey values are localization keys rendered by the UI; TechnicalDetail is raw log text for
    // the diagnostics bundle. No user-facing English sentence is ever returned as a key.
    private const string CompletedKey = "cleanup.step.completed";
    private const string NothingToDoKey = "cleanup.step.nothing_to_do";
    private const string NoManagerKey = "cleanup.step.no_manager";
    private const string StepFailedKey = "error.network.cleanup_step_failed";
    private const string CancelledKey = "error.operation.cancelled";
    private const string ProxyFailedKey = "error.proxy.restore_failed";
    private const string DnsFailedKey = "error.dns.restore_failed";
    private const string KillSwitchFailedKey = "error.killswitch.remove_failed";
    private const string RoutesFailedKey = "error.route.remove_failed";

    private readonly ICommandRunner _runner;
    private readonly IKillSwitch? _killSwitch;
    private readonly IRouteManager? _routes;
    private readonly IDnsConfigurator? _dns;
    private readonly ISystemProxy? _systemProxy;
    private readonly ITunDeviceManager? _tun;
    private readonly string _tunnelInterfaceName;
    private readonly string _identifier;
    private readonly string _coreProcessName;

    /// <summary>
    /// Creates the manager.
    /// </summary>
    /// <param name="runner">Command runner for the read-only macOS probes.</param>
    /// <param name="killSwitch">Kill Switch, or <c>null</c> when this host has none wired.</param>
    /// <param name="routes">Route manager, or <c>null</c>.</param>
    /// <param name="dns">DNS configurator, or <c>null</c>.</param>
    /// <param name="systemProxy">System-proxy configurator, or <c>null</c>.</param>
    /// <param name="tun">TUN observer, or <c>null</c>.</param>
    /// <param name="tunnelInterfaceName">The interface MyVpn configures; the only one it will touch.</param>
    /// <param name="identifier">Kill Switch identifier MyVpn owns.</param>
    /// <param name="coreProcessName">Process name used by the leftover probe.</param>
    /// <remarks>
    /// The collaborators are nullable so the manager can be constructed with nothing but a runner —
    /// which is what the leftover checks and the restore path need in order to keep working when a
    /// platform executor is unavailable.
    /// </remarks>
    public MacNetworkStateManager(
        ICommandRunner? runner = null,
        IKillSwitch? killSwitch = null,
        IRouteManager? routes = null,
        IDnsConfigurator? dns = null,
        ISystemProxy? systemProxy = null,
        ITunDeviceManager? tun = null,
        string tunnelInterfaceName = DefaultTunnelInterfaceName,
        string identifier = DefaultIdentifier,
        string coreProcessName = CoreProcessName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tunnelInterfaceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        ArgumentException.ThrowIfNullOrWhiteSpace(coreProcessName);

        // The interface name reaches argv here too, so it gets the same defence in depth the TUN
        // manager applies rather than being trusted because it came from settings.
        MacTunDeviceManager.ValidateInterfaceName(tunnelInterfaceName);

        _runner = runner ?? new ProcessCommandRunner();
        _killSwitch = killSwitch;
        _routes = routes;
        _dns = dns;
        _systemProxy = systemProxy;
        _tun = tun;
        _tunnelInterfaceName = tunnelInterfaceName;
        _identifier = identifier;
        _coreProcessName = coreProcessName;
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
    /// Best-effort by construction: a probe that cannot run records why in
    /// <see cref="NetworkLeftovers.Details"/> instead of throwing, and a null collaborator is reported
    /// as "unknown" rather than as "clean". Consumers must not read the result as proof that the machine
    /// is clean when the corresponding detail line says it could not be checked.
    /// </remarks>
    public async Task<NetworkLeftovers> DetectLeftoversAsync(CancellationToken cancellationToken)
    {
        var details = new List<string>();

        var killSwitch = await InspectKillSwitchAsync(details, cancellationToken).ConfigureAwait(false);
        var tunnel = await InspectTunnelInterfaceAsync(details, cancellationToken).ConfigureAwait(false);
        var routes = await InspectRoutesAsync(details, cancellationToken).ConfigureAwait(false);
        var dns = await InspectDnsAsync(details, cancellationToken).ConfigureAwait(false);
        var proxy = await InspectSystemProxyAsync(details, cancellationToken).ConfigureAwait(false);
        var core = await InspectCoreProcessAsync(details, cancellationToken).ConfigureAwait(false);

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

    private async Task<bool> InspectKillSwitchAsync(List<string> details, CancellationToken cancellationToken)
    {
        if (_killSwitch is null)
        {
            details.Add("kill switch: no IKillSwitch is wired on this host; state not checked");
            return false;
        }

        try
        {
            var state = await _killSwitch.InspectAsync(null, cancellationToken).ConfigureAwait(false);

            if (state.IsArmed || state.IsDrifted)
            {
                details.Add(
                    $"kill switch: armed={state.IsArmed} drifted={state.IsDrifted} "
                    + $"mechanism={state.MechanismName ?? "unknown"}");
            }

            foreach (var orphan in state.OrphanedRules)
            {
                details.Add($"kill switch: {orphan}");
            }

            return state.IsArmed;
        }
        catch (Exception ex)
        {
            details.Add($"kill switch: inspection failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private async Task<bool> InspectTunnelInterfaceAsync(List<string> details, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsMacOS())
        {
            details.Add($"tunnel interface: not macOS; '{_tunnelInterfaceName}' was not probed");
            return false;
        }

        var names = await ListTunnelInterfacesAsync(cancellationToken).ConfigureAwait(false);
        var exists = await TunnelInterfaceExistsAsync(names, cancellationToken).ConfigureAwait(false);

        if (!exists && names.Count == 0)
        {
            details.Add("tunnel interface: no utun device is present");
            return false;
        }

        details.Add($"tunnel interface: configured name '{_tunnelInterfaceName}' exists={exists}");
        details.Add($"tunnel interface: utun device(s) present: {string.Join(", ", names)}");

        if (!exists)
        {
            // The kernel assigns utun numbers dynamically, so a leftover tunnel can exist under a
            // different name than the one configured today. Saying so beats reporting "clean".
            details.Add(
                $"tunnel interface: '{_tunnelInterfaceName}' is not among them, but utun numbers are "
                + "assigned dynamically — another device may still be a leftover from this or another "
                + "VPN client");
        }

        return true;
    }

    private async Task<bool> InspectRoutesAsync(List<string> details, CancellationToken cancellationToken)
    {
        if (_routes is null)
        {
            details.Add("routes: no IRouteManager is wired on this host; state not checked");
            return false;
        }

        try
        {
            var state = await _routes.InspectAsync(null, cancellationToken).ConfigureAwait(false);

            if (state.TunnelRoutesPresent || state.BypassRoutesPresent)
            {
                details.Add(
                    $"routes: tunnel={state.TunnelRoutesPresent} bypass={state.BypassRoutesPresent}");
            }

            foreach (var orphan in state.OrphanedRoutes)
            {
                details.Add($"routes: possibly orphaned: {orphan}");
            }

            if (state.DisplacedDefaultRoute is not null)
            {
                details.Add($"routes: a displaced default route is recorded: {state.DisplacedDefaultRoute}");
            }

            return state.TunnelRoutesPresent || state.BypassRoutesPresent || state.OrphanedRoutes.Count > 0;
        }
        catch (Exception ex)
        {
            details.Add($"routes: inspection failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private async Task<bool> InspectDnsAsync(List<string> details, CancellationToken cancellationToken)
    {
        var overridden = false;

        if (_dns is not null)
        {
            try
            {
                var state = await _dns.InspectAsync(cancellationToken).ConfigureAwait(false);

                if (state.ActiveServers.Count > 0)
                {
                    details.Add(
                        $"dns: {state.ActiveServers.Count} resolver(s) active, primary interface "
                        + $"{(state.InterfaceName ?? "unknown")}");
                }

                foreach (var leak in state.PotentialLeaks)
                {
                    details.Add($"dns: {leak}");
                }

                // A resolver bound to a utun interface is the signature of MyVpn's override: the
                // resolvers MyVpn installs are reachable only through the tunnel.
                overridden = MacTunDeviceManager.IsTunnelInterfaceName(state.InterfaceName);
            }
            catch (Exception ex)
            {
                details.Add($"dns: inspection failed: {ex.GetType().Name}: {ex.Message}");
            }
        }
        else
        {
            details.Add("dns: no IDnsConfigurator is wired on this host; state not checked");
        }

        // MyVpn's own split-DNS files are a marker that survives a crash, and they are readable without
        // a collaborator. Ownership is decided by the file's marker comment.
        var ownedFiles = CountOwnedResolverFiles();
        if (ownedFiles > 0)
        {
            details.Add($"dns: {ownedFiles} split-DNS file(s) generated by MyVpn remain in /etc/resolver");
            overridden = true;
        }

        return overridden;
    }

    private async Task<bool> InspectSystemProxyAsync(List<string> details, CancellationToken cancellationToken)
    {
        if (_systemProxy is null)
        {
            details.Add("system proxy: no ISystemProxy is wired on this host; state not checked");
            return false;
        }

        try
        {
            var state = await _systemProxy.InspectAsync(cancellationToken).ConfigureAwait(false);

            if (state.IsConfigured && !state.PointsAtMyVpn)
            {
                // A proxy the user configured themselves is not a leftover and must not be reported as
                // one; it is recorded so a support bundle can distinguish the two cases.
                details.Add(
                    $"system proxy: configured ({state.ActiveProxy ?? state.PacUrl ?? "unknown"}) but "
                    + "not pointing at MyVpn");
            }

            return state.IsConfigured && state.PointsAtMyVpn;
        }
        catch (Exception ex)
        {
            details.Add($"system proxy: inspection failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private async Task<bool> InspectCoreProcessAsync(List<string> details, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsMacOS())
        {
            details.Add("core process: not macOS; the core process was not probed");
            return false;
        }

        var result = await _runner
            .RunAsync(PgrepBinary, new[] { "-x", _coreProcessName }, cancellationToken)
            .ConfigureAwait(false);

        if (result.Succeeded)
        {
            details.Add($"core process: '{_coreProcessName}' is running ({result.StandardOutput.Trim()})");
            return true;
        }

        return false;
    }

    // ------------------------------------------------------------------ cleanup

    /// <summary>
    /// Removes every MyVpn-owned artefact, attempting every step even after one fails.
    /// </summary>
    /// <remarks>
    /// The report is built with <see cref="CleanupReport.FromSteps"/>, so <c>FullyClean</c> is true only
    /// when every step succeeded. A step with a null collaborator is <i>not</i> a failure: reporting a
    /// failure for work that does not exist would send the user chasing a problem they do not have.
    /// </remarks>
    public async Task<CleanupReport> EmergencyCleanupAsync(CancellationToken cancellationToken)
    {
        var steps = new List<CleanupStep>(5)
        {
            await ResetSystemProxyAsync(cancellationToken).ConfigureAwait(false),
            await RevertDnsAsync(cancellationToken).ConfigureAwait(false),
            await RemoveKillSwitchAsync(cancellationToken).ConfigureAwait(false),
            await RemoveRoutesAsync(cancellationToken).ConfigureAwait(false),
            await RemoveTunnelInterfaceAsync(cancellationToken).ConfigureAwait(false),
        };

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

        // ResetAsync, not RestoreAsync: emergency cleanup has no captured snapshot, and a proxy pointing
        // at a dead listener survives a reboot. Turning it off is the only action that reliably returns
        // the machine to a working state.
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

        // IsSupported is deliberately not consulted: a mechanism that reports itself unsupported can
        // still have left rules behind from a previous run, and RemoveAsync is idempotent by contract,
        // so the honest thing is to ask it to clean up and report what it says.
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

        // RemoveAllOwnedAsync rather than RemoveAsync(plan): after a crash the settings may have changed,
        // and the whole point is to recover from a state the application no longer has a coherent model
        // of. Ownership is determined from the journal and the routes themselves.
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
        if (!OperatingSystem.IsMacOS())
        {
            return new CleanupStep(
                StepName.Interface,
                true,
                NothingToDoKey,
                $"Not macOS: the utun device '{_tunnelInterfaceName}' was not probed or touched.");
        }

        try
        {
            var names = await ListTunnelInterfacesAsync(cancellationToken).ConfigureAwait(false);
            var exists = await TunnelInterfaceExistsAsync(names, cancellationToken).ConfigureAwait(false);

            if (!exists && names.Count == 0)
            {
                return new CleanupStep(
                    StepName.Interface,
                    true,
                    NothingToDoKey,
                    "No utun device exists; the core removes its own device when it exits.");
            }

            // The device belongs to the core's control socket: closing the descriptor removes it, and
            // XNU removes its routes with it. Destroying it from here would mean taking a device apart
            // while its owner is still writing packets into it.
            return new CleanupStep(
                StepName.Interface,
                true,
                CompletedKey,
                $"tunnel interface '{_tunnelInterfaceName}' exists={exists}; utun device(s) present: "
                + $"{string.Join(", ", names)}. The core owns the control socket; stopping the core "
                + "removes the device and its routes. MyVpn does not destroy a device it did not create.");
        }
        catch (OperationCanceledException)
        {
            return new CleanupStep(
                StepName.Interface,
                false,
                CancelledKey,
                "tunnel interface probe: cancelled before it completed");
        }
        catch (Exception ex)
        {
            return new CleanupStep(
                StepName.Interface,
                false,
                StepFailedKey,
                $"tunnel interface probe: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ------------------------------------------------------------------ internals

    /// <summary>
    /// One collaborator call, normalised across the two result shapes the abstractions use
    /// (<see cref="Result"/> for routing, DNS and the proxy, <see cref="KillSwitchApplyResult"/> for the
    /// firewall).
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

            // The collaborator's own key is more specific ("needs privileges", "tool missing") than a
            // single generic step key, so it wins when it is present.
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

    private async Task<IReadOnlyList<string>> ListTunnelInterfacesAsync(CancellationToken cancellationToken)
    {
        var result = await _runner
            .RunAsync(IfconfigBinary, new[] { "-l" }, cancellationToken)
            .ConfigureAwait(false);

        return result.Succeeded
            ? MacTunDeviceManager.ParseInterfaceList(result.StandardOutput)
            : Array.Empty<string>();
    }

    /// <summary>
    /// Asks the wired TUN observer about the configured name, falling back to the device list.
    /// </summary>
    /// <remarks>
    /// The abstraction is preferred when it is present because it is the component that owns the
    /// platform's naming rules; the listing is the fallback so the probe still works on a host where
    /// no observer was wired.
    /// </remarks>
    private async Task<bool> TunnelInterfaceExistsAsync(
        IReadOnlyList<string> observedNames,
        CancellationToken cancellationToken)
    {
        if (_tun is not null)
        {
            return await _tun.ExistsAsync(_tunnelInterfaceName, cancellationToken).ConfigureAwait(false);
        }

        return observedNames.Contains(_tunnelInterfaceName, StringComparer.Ordinal);
    }

    private static int CountOwnedResolverFiles()
    {
        if (!OperatingSystem.IsMacOS() || !Directory.Exists(MacDnsConfigurator.ResolverDirectory))
        {
            return 0;
        }

        try
        {
            return Directory
                .EnumerateFiles(MacDnsConfigurator.ResolverDirectory)
                .Count(path =>
                {
                    try
                    {
                        return MacDnsConfigurator.ContainsOwnedMarker(File.ReadAllText(path));
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        return false;
                    }
                });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return 0;
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
