using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Routing;
using MyVpn.Platform.Abstractions.Execution;

namespace MyVpn.Platform.Linux.Routing;

/// <summary>
/// Applies a <see cref="RoutePlan"/> to the Linux routing table through <c>ip</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Ordering is a safety property, not a style choice.</b> <see cref="RoutePlan.BypassRoutes"/> are
/// uplink host routes that keep the core's own connection to the server off the tunnel. They are
/// installed <i>before</i> any route that captures the default prefix, and removed <i>after</i> those
/// routes. Reversing either half briefly routes the core's own connection to the server into a tunnel
/// that is being built or torn down. The tunnel cannot carry that packet — its own peer would have to
/// be reached through itself — so the connection dies and is retried: the user sees "connects, then
/// immediately stalls", with nothing in the logs to explain it. The ordering in
/// <see cref="ApplyAsync"/> and <see cref="RemoveAsync"/> is therefore explicit and must not be
/// "simplified" into one loop over both lists.
/// </para>
/// <para>
/// <b>Fail-closed.</b> If a bypass route cannot be installed, no default-capturing route is installed
/// at all. Capturing the default without the host route to the server sends the core's own traffic
/// into the tunnel that has not been established yet, which is the same loop from the other side.
/// Aborting leaves the caller in a state it can tear down cleanly.
/// </para>
/// <para>
/// <b>No shell, ever.</b> Every invocation is an argv vector handed to <see cref="ICommandRunner"/>.
/// Nothing is concatenated into a command string, so a hostile interface name or gateway cannot turn
/// into command execution; <see cref="RoutePlan.Validate"/> additionally rejects a gateway that is not
/// an IP literal.
/// </para>
/// <para>
/// <b>Ownership is read back from the kernel.</b> Cleanup after a crash cannot reconstruct a plan that
/// the dead process never saved, so <see cref="RemoveAllOwnedAsync"/> decides what to delete from the
/// routes and rules themselves.
/// </para>
/// </remarks>
public sealed class LinuxRouteManager : IRouteManager
{
    /// <summary>The tool this executor drives (<c>iproute2</c>).</summary>
    private const string IpBinary = "ip";

    /// <summary>
    /// Conventional absolute location. A privileged helper started by systemd or pkexec often runs
    /// with a minimal <c>PATH</c>, so the absolute path is preferred when it exists.
    /// </summary>
    private const string AbsoluteIpBinary = "/usr/sbin/ip";

    /// <summary>
    /// Every interface MyVpn creates is named with this prefix (<c>myvpn0</c> by default). It is the
    /// ownership marker for routes: the TUN device lives exactly as long as the core process, so the
    /// device name is the one piece of identity that survives in the kernel after a crash.
    /// </summary>
    private const string OwnedInterfacePrefix = "myvpn";

    /// <summary>
    /// Mark carried by MyVpn's policy-routing rules. Kept in sync with
    /// <c>KillSwitchPlan.FirewallMark</c> / <c>KillSwitchPlanBuilder</c>, whose default is
    /// <c>0x0CA6C</c>.
    /// </summary>
    private const int VpnFirewallMark = 0x0CA6C;

    /// <summary>
    /// Policy-routing table reserved for MyVpn (the same value as the
    /// <c>KillSwitchPlan.RoutingTableId</c> default). The table is ours by convention: the research
    /// notes in <c>docs/research/07-linux-networking.md</c> settle on it precisely so that "restore on
    /// crash" is a matter of deleting our own table rather than remembering the system's default.
    /// </summary>
    private const int VpnRoutingTableId = 100;

    private readonly ICommandRunner _runner;
    private readonly Func<bool> _isElevated;

    /// <summary>
    /// The physical default route seen immediately before a default-capturing route was installed,
    /// kept so <see cref="RemoveAsync"/> can put it back. It is deliberately not persisted: after a
    /// crash the live table is the better source of truth (see <see cref="RemoveAsync"/>).
    /// </summary>
    private ObservedRoute? _displacedDefault;

    public LinuxRouteManager(ICommandRunner? runner = null, Func<bool>? isElevated = null)
    {
        _runner = runner ?? new ProcessCommandRunner();
        _isElevated = isElevated ?? DefaultElevationCheck;
    }

    /// <summary>
    /// True when the tool is present <i>and</i> this process may change the routing table.
    /// </summary>
    /// <remarks>
    /// Reporting <c>true</c> without privileges would let the session believe routing will succeed and
    /// then fail after the core was already started. The honest answer here is what lets the connect
    /// flow decide before touching anything.
    /// </remarks>
    public bool IsSupported => _runner.Exists(IpBinary) && _isElevated();

    public async Task<Result> ApplyAsync(RoutePlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return validation;
        }

        if (!_runner.Exists(IpBinary))
        {
            return Result.Fail(ToolMissing());
        }

        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        // A stale capture from an earlier plan must never be restored for this one.
        _displacedDefault = null;

        if (plan.TunnelRoutes.Any(route => route.DisplacesDefaultRoute))
        {
            // Capture before the change. Once the tunnel's default route is in place the original
            // uplink route may no longer be discoverable, and an unrestorable default route is how a
            // VPN client leaves a machine with no network at all after it exits.
            var captured = await ProbeDefaultAsync(ipv6: false, physicalOnly: true, cancellationToken)
                .ConfigureAwait(false);

            if (captured.IsFailure)
            {
                captured = await ProbeDefaultAsync(ipv6: true, physicalOnly: true, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (captured.IsFailure)
            {
                return Result.Fail(NoDefaultToDisplace());
            }

            _displacedDefault = captured.Value;
        }

        // (1) Bypass (uplink host) routes first. These keep the core's own connection to the server on
        // the physical link, so every later step is reachable even if it captures the default prefix.
        foreach (var route in plan.BypassRoutes)
        {
            var added = await AddRouteAsync(route, replace: false, cancellationToken).ConfigureAwait(false);
            if (added.IsFailure)
            {
                // Fail closed: stop here rather than install a default-capturing route whose own
                // traffic would be routed into a tunnel that cannot carry it. The bypass routes that
                // were installed are left in place on purpose — they only pin the server to the
                // uplink, which is where the OS would send it anyway, and teardown removes them.
                return Result.Fail(BypassFailed(route, added.Error!));
            }
        }

        // (2) Only now may a route capture the default prefix.
        foreach (var route in plan.TunnelRoutes)
        {
            // "replace" is used only for an entry that is expected to already exist (the route it
            // displaces); everything else is an "add", whose EEXIST answer is treated as idempotent
            // success so that re-applying a plan is harmless.
            var added = await AddRouteAsync(route, route.DisplacesDefaultRoute, cancellationToken)
                .ConfigureAwait(false);

            if (added.IsFailure)
            {
                return added;
            }
        }

        return Result.Ok();
    }

    public async Task<Result> RemoveAsync(RoutePlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        // Teardown deliberately does not call plan.Validate(). A plan that fails validation still
        // describes routes that may exist in the kernel, and refusing to clean up because the plan is
        // incomplete is how a half-routed machine stays half-routed.
        if (!_runner.Exists(IpBinary))
        {
            // Apply refuses to run without the tool, so nothing was installed by us.
            return Result.Ok();
        }

        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        var displacing = plan.TunnelRoutes.Where(route => route.DisplacesDefaultRoute).ToList();

        var restore = _displacedDefault;
        if (displacing.Count > 0 && restore is null)
        {
            // Crash recovery: the previous process took the capture with it, so re-derive the
            // physical default from the live table *before* deleting anything.
            var probed = await ProbeDefaultAsync(ipv6: false, physicalOnly: true, cancellationToken)
                .ConfigureAwait(false);

            if (probed.IsFailure)
            {
                probed = await ProbeDefaultAsync(ipv6: true, physicalOnly: true, cancellationToken)
                    .ConfigureAwait(false);
            }

            restore = probed.IsSuccess ? probed.Value : null;
        }

        var failures = new List<string>();

        // (1) Tunnel routes first: they are the routes that capture the default prefix, and removing
        // them last would leave the core's own traffic pointed at a tunnel that is already going away.
        // Reverse order is the mirror image of installation.
        foreach (var route in plan.TunnelRoutes.Reverse())
        {
            var removed = await DeleteRouteAsync(route, cancellationToken).ConfigureAwait(false);
            if (removed.IsFailure)
            {
                failures.Add(Describe(removed.Error!));
            }
        }

        // (2) Only then the bypass routes.
        foreach (var route in plan.BypassRoutes.Reverse())
        {
            var removed = await DeleteRouteAsync(route, cancellationToken).ConfigureAwait(false);
            if (removed.IsFailure)
            {
                failures.Add(Describe(removed.Error!));
            }
        }

        // (3) Put the displaced default route back.
        if (displacing.Count > 0)
        {
            if (restore is null)
            {
                failures.Add(
                    "the plan displaces the default route but no physical default route could be "
                    + "identified to restore");
            }
            else
            {
                var restored = await RestoreDefaultAsync(restore, cancellationToken).ConfigureAwait(false);
                if (restored.IsFailure)
                {
                    failures.Add(Describe(restored.Error!));
                }
            }
        }

        _displacedDefault = null;

        return failures.Count == 0 ? Result.Ok() : Result.Fail(RemoveFailed(failures));
    }

    /// <summary>
    /// Removes every route and rule MyVpn owns, using the kernel state itself as the source of truth.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the panic-clear path. It cannot take a plan: the process that installed the routes may
    /// have been killed, its settings may since have changed, and the whole point is to recover from a
    /// state the application no longer has a coherent model of. Ownership is therefore judged from the
    /// route or rule itself:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// a route whose outgoing device starts with <c>myvpn</c> — the tunnel interface (and any address
    /// or policy route on it) is created by the core, and the kernel removes its routes when the core
    /// dies, so a survivor is ours by construction;
    /// </description></item>
    /// <item><description>
    /// any route left in table 100, which is MyVpn's policy table by convention;
    /// </description></item>
    /// <item><description>
    /// a rule carrying <c>fwmark 0xca6c</c>, the mark MyVpn stamps on the traffic it wants policy
    /// routed.
    /// </description></item>
    /// </list>
    /// <para>
    /// What it cannot recognise is a bypass host route sitting on the physical uplink: that route is
    /// indistinguishable from an ordinary OS route to the same destination, and deleting it on a guess
    /// would risk removing something MyVpn never created. Teardown with the plan removes those; a crash
    /// leaves at most a host route to the VPN server via the gateway the host already uses, which is
    /// harmless. Routes the kernel created for a device or address (<c>proto kernel</c>, such as the
    /// tunnel's IPv6 link-local route) are skipped for the same reason: they are not ours to manage and
    /// disappear with the interface.
    /// </para>
    /// </remarks>
    public async Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
    {
        if (!_runner.Exists(IpBinary))
        {
            // Nothing can have been installed by a process that never had the tool.
            return Result.Ok();
        }

        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        var failures = new List<string>();
        var tableId = VpnRoutingTableId.ToString(CultureInfo.InvariantCulture);

        foreach (var family in new[] { "-4", "-6" })
        {
            var isIpv6 = family == "-6";

            // (1) The main table: our tunnel's own routes.
            var main = await RunIpAsync(new[] { family, "route", "show" }, cancellationToken)
                .ConfigureAwait(false);

            if (main.Succeeded)
            {
                foreach (var route in ParseRoutes(main.StandardOutput, isIpv6))
                {
                    // Kernel-managed routes (proto kernel) belong to the interface or address that
                    // created them and are removed by the kernel with it. Deleting them while the
                    // tunnel is still alive would only strip its link-local route.
                    if (!IsOwnedDevice(route.Device) || IsKernelManaged(route))
                    {
                        continue;
                    }

                    var deleted = await RunIpAsync(
                        BuildDeleteArguments(route, table: null), cancellationToken).ConfigureAwait(false);

                    if (!deleted.Succeeded && !IsAlreadyGone(deleted))
                    {
                        failures.Add(Describe(deleted, $"route '{route.Text.Trim()}'"));
                    }
                }
            }
            else
            {
                failures.Add(Describe(main, $"listing {family} routes"));
            }

            // (2) MyVpn's own policy table. Any route still in it is ours, whatever device it names.
            var policy = await RunIpAsync(
                new[] { family, "route", "show", "table", tableId }, cancellationToken).ConfigureAwait(false);

            if (policy.Succeeded || IsMissingTable(policy))
            {
                foreach (var route in ParseRoutes(policy.StandardOutput, isIpv6))
                {
                    if (IsKernelManaged(route))
                    {
                        continue;
                    }

                    var deleted = await RunIpAsync(
                        BuildDeleteArguments(route, VpnRoutingTableId), cancellationToken).ConfigureAwait(false);

                    if (!deleted.Succeeded && !IsAlreadyGone(deleted))
                    {
                        failures.Add(Describe(deleted, $"route '{route.Text.Trim()}' in table 100"));
                    }
                }
            }
            else
            {
                failures.Add(Describe(policy, $"listing {family} routes in table 100"));
            }
        }

        // (3) Policy-routing rules carrying our mark, at any priority.
        var rules = await RunIpAsync(new[] { "rule", "show" }, cancellationToken).ConfigureAwait(false);

        if (rules.Succeeded)
        {
            foreach (var rule in ParseMyVpnRules(rules.StandardOutput))
            {
                var deleted = await RunIpAsync(
                    new[] { "rule", "del", "priority", rule.Priority.ToString(CultureInfo.InvariantCulture) },
                    cancellationToken).ConfigureAwait(false);

                if (!deleted.Succeeded && !IsAlreadyGone(deleted))
                {
                    failures.Add(Describe(deleted, $"rule priority {rule.Priority} ('{rule.Text.Trim()}')"));
                }
            }
        }
        else
        {
            failures.Add(Describe(rules, "listing policy rules"));
        }

        return failures.Count == 0 ? Result.Ok() : Result.Fail(RemoveFailed(failures));
    }

    public async Task<RouteState> InspectAsync(RoutePlan? expected, CancellationToken cancellationToken)
    {
        if (!_runner.Exists(IpBinary))
        {
            // Without the tool nothing can be observed. "Nothing present" is the only honest answer,
            // and it must not be read as "verified clean" — the caller has the error surface for that.
            return EmptyState();
        }

        // A null plan is a legitimate question ("is anything of ours still here?") and must not throw.
        var observed = new List<ObservedRoute>();

        var v4 = await RunIpAsync(new[] { "-4", "route", "show" }, cancellationToken).ConfigureAwait(false);
        if (v4.Succeeded)
        {
            observed.AddRange(ParseRoutes(v4.StandardOutput, isIpv6: false));
        }

        var v6 = await RunIpAsync(new[] { "-6", "route", "show" }, cancellationToken).ConfigureAwait(false);
        if (v6.Succeeded)
        {
            observed.AddRange(ParseRoutes(v6.StandardOutput, isIpv6: true));
        }

        var owned = observed.Where(route => IsOwnedDevice(route.Device)).ToList();

        var tunnelPresent = expected is null
            // With no plan, "a tunnel route is present" means an owned route that MyVpn itself would
            // have created. The kernel's link-local route on the tunnel does not count: it exists
            // whenever the device does, and the device is reported separately.
            ? owned.Any(route => !IsKernelManaged(route))
            : expected.TunnelRoutes.Count > 0
              && expected.TunnelRoutes.All(route => observed.Any(seen => Matches(route, seen)));

        // A bypass host route lives on the physical interface, so it can only be attributed to us via
        // the plan that asked for it. With no plan there is no honest way to claim it is present.
        var bypassPresent = expected is not null
            && expected.BypassRoutes.Count > 0
            && expected.BypassRoutes.All(route => observed.Any(seen => Matches(route, seen)));

        var orphans = new List<string>();
        if (expected is null)
        {
            // Kernel-managed routes are excluded here for the same reason as below: the tunnel's IPv6
            // link-local route is always present and is never a MyVpn leftover.
            orphans.AddRange(owned.Where(route => !IsKernelManaged(route)).Select(route => route.Text.Trim()));
        }
        else
        {
            var planned = expected.TunnelRoutes.Concat(expected.BypassRoutes).ToList();
            foreach (var route in owned)
            {
                // `proto kernel` routes are created by the kernel for the interface/address (an IPv6
                // link-local route on the tunnel is always there) and are not MyVpn's leftovers.
                if (!IsKernelManaged(route) && !planned.Any(entry => Matches(entry, route)))
                {
                    orphans.Add(route.Text.Trim());
                }
            }
        }

        var displaced = _displacedDefault?.Text.Trim();
        if (displaced is null
            && expected is not null
            && expected.TunnelRoutes.Any(route => route.DisplacesDefaultRoute))
        {
            // A default route that is not on our tunnel is the one MyVpn pushed aside; report it so a
            // session that was restarted can still tell the user what will be put back.
            displaced = observed
                .FirstOrDefault(route => route.Destination == "default" && !IsOwnedDevice(route.Device))
                ?.Text.Trim();
        }

        return new RouteState
        {
            TunnelRoutesPresent = tunnelPresent,
            BypassRoutesPresent = bypassPresent,
            DisplacedDefaultRoute = displaced,
            OrphanedRoutes = orphans,
        };
    }

    public async Task<Result<PhysicalUplink>> GetDefaultUplinkAsync(CancellationToken cancellationToken)
    {
        if (!_runner.Exists(IpBinary))
        {
            return Result<PhysicalUplink>.Fail(ToolMissing());
        }

        // IPv4 is preferred: it is what the tunnel and the bypass host route are normally built from,
        // and a dual-stack host's IPv6 default is frequently a link-local address that cannot be used
        // as a gateway for anything else.
        var v4 = await ProbeDefaultAsync(ipv6: false, physicalOnly: false, cancellationToken)
            .ConfigureAwait(false);

        if (v4.IsSuccess)
        {
            return Result<PhysicalUplink>.Ok(new PhysicalUplink(v4.Value.Device, v4.Value.Gateway));
        }

        var v6 = await ProbeDefaultAsync(ipv6: true, physicalOnly: false, cancellationToken)
            .ConfigureAwait(false);

        if (v6.IsSuccess)
        {
            return Result<PhysicalUplink>.Ok(new PhysicalUplink(v6.Value.Device, v6.Value.Gateway, IsIpv6: true));
        }

        // No default route is a normal state (an isolated host, a fresh network namespace) and is
        // reported as a failure value with the tool's own output, never as an exception.
        return Result<PhysicalUplink>.Fail(new MyVpnError(
            ErrorCodes.NotFound,
            "error.route.no_default_route",
            ErrorSeverity.Error,
            "No default route was found, so the physical uplink cannot be identified. "
            + $"'ip -4 route show default': {Trim(v4.Error?.TechnicalDetail)}; "
            + $"'ip -6 route show default': {Trim(v6.Error?.TechnicalDetail)}."));
    }

    // ------------------------------------------------------------------ internals

    /// <summary>
    /// Absolute path when it exists, the bare name otherwise, so the executor still works with a
    /// minimal <c>PATH</c>.
    /// </summary>
    private string IpTool => _runner.Exists(AbsoluteIpBinary) ? AbsoluteIpBinary : IpBinary;

    private Task<CommandResult> RunIpAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken) =>
        _runner.RunAsync(IpTool, arguments, cancellationToken);

    private async Task<Result> AddRouteAsync(
        RouteEntry route,
        bool replace,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(route.Interface))
        {
            // Defensive: RoutePlan.Validate covers the plan-level rules, but an empty device would
            // otherwise reach `ip` as an empty argv element and produce a confusing parser error.
            return Result.Fail(new MyVpnError(
                ErrorCodes.RouteAddFailed,
                "error.route.no_interface",
                ErrorSeverity.Error,
                $"Route '{route}' does not name an outgoing interface."));
        }

        var arguments = BuildAddArguments(replace ? "replace" : "add", route);

        var result = await RunIpAsync(arguments, cancellationToken).ConfigureAwait(false);
        if (result.Succeeded)
        {
            return Result.Ok();
        }

        if (IsAlreadyExists(result))
        {
            // EEXIST means the route is already exactly what the plan wants. That is the normal
            // re-apply case (a reconnect, or a second session), so it is success, not failure. There
            // is no logger in this layer: the caller can see the resulting state through
            // InspectAsync, which is the check that actually matters.
            return Result.Ok();
        }

        return Result.Fail(AddFailed(route, result));
    }

    private async Task<Result> DeleteRouteAsync(RouteEntry route, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(route.Interface))
        {
            // Apply refuses to install a route with no interface, so there is nothing to delete.
            return Result.Ok();
        }

        var arguments = new List<string>
        {
            FamilyFlag(route.Destination.IsIPv6),
            "route",
            "del",
            RenderDestination(route.Destination),
            "dev",
            route.Interface,
        };

        var result = await RunIpAsync(arguments, cancellationToken).ConfigureAwait(false);

        // A route that is not there is the desired end state, and this is the case crash recovery
        // depends on: when the core dies, the kernel deletes its interface *and its routes*, so every
        // deletion in the recorded plan legitimately finds nothing left.
        return result.Succeeded || IsAlreadyGone(result)
            ? Result.Ok()
            : Result.Fail(RemoveFailed(route, result));
    }

    private async Task<Result> RestoreDefaultAsync(ObservedRoute displaced, CancellationToken cancellationToken)
    {
        var arguments = new List<string>
        {
            FamilyFlag(displaced.IsIpv6),
            "route",
            "add",
            "default",
        };

        if (displaced.Gateway is not null)
        {
            arguments.Add("via");
            arguments.Add(displaced.Gateway);
        }

        arguments.Add("dev");
        arguments.Add(displaced.Device);

        if (displaced.Metric is not null)
        {
            arguments.Add("metric");
            arguments.Add(displaced.Metric.Value.ToString(CultureInfo.InvariantCulture));
        }

        var result = await RunIpAsync(arguments, cancellationToken).ConfigureAwait(false);

        // EEXIST is the good case here: it means the original default route was never actually lost
        // (the tunnel's route simply won on metric), so there is nothing left to repair.
        return result.Succeeded || IsAlreadyExists(result)
            ? Result.Ok()
            : Result.Fail(RestoreFailed(displaced, result));
    }

    /// <summary>
    /// Reads the default route of one address family.
    /// </summary>
    /// <param name="ipv6">Query the IPv6 table instead of the IPv4 one.</param>
    /// <param name="physicalOnly">
    /// When true, a default route on a MyVpn tunnel interface is not an acceptable answer. That is the
    /// distinction between "what does the host currently default to" (best-effort discovery) and "what
    /// must be put back when our route goes away" (restoration, where our own route is not an answer).
    /// </param>
    private async Task<Result<ObservedRoute>> ProbeDefaultAsync(
        bool ipv6,
        bool physicalOnly,
        CancellationToken cancellationToken)
    {
        var family = FamilyFlag(ipv6);
        var result = await RunIpAsync(
            new[] { family, "route", "show", "default" }, cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            return Result<ObservedRoute>.Fail(NoDefaultRoute(family, result));
        }

        var candidates = ParseRoutes(result.StandardOutput, ipv6)
            .Where(route => route.Destination == "default")
            .ToList();

        // Prefer the physical uplink: with the tunnel already up, the first line may be our own route,
        // and using it as "the uplink" would build a bypass route that points into the tunnel.
        var chosen = candidates.FirstOrDefault(route => !IsOwnedDevice(route.Device))
                     ?? (physicalOnly ? null : candidates.FirstOrDefault());

        return chosen is null
            ? Result<ObservedRoute>.Fail(NoDefaultRoute(family, result))
            : Result<ObservedRoute>.Ok(chosen);
    }

    private static IReadOnlyList<string> BuildAddArguments(string verb, RouteEntry route)
    {
        var arguments = new List<string>
        {
            // The family is explicit: `ip route` defaults to IPv4, so an IPv6 prefix would otherwise be
            // rejected outright.
            FamilyFlag(route.Destination.IsIPv6),
            "route",
            verb,
            RenderDestination(route.Destination),
        };

        if (route.Gateway is not null)
        {
            arguments.Add("via");
            arguments.Add(route.Gateway);
        }

        arguments.Add("dev");
        arguments.Add(route.Interface);
        arguments.Add("metric");
        arguments.Add(route.Metric.ToString(CultureInfo.InvariantCulture));

        return arguments;
    }

    private static List<string> BuildDeleteArguments(ObservedRoute route, int? table)
    {
        var arguments = new List<string>
        {
            FamilyFlag(route.IsIpv6),
            "route",
            "del",
            route.Destination,
        };

        if (!string.IsNullOrWhiteSpace(route.Device))
        {
            arguments.Add("dev");
            arguments.Add(route.Device);
        }

        if (table is not null)
        {
            arguments.Add("table");
            arguments.Add(table.Value.ToString(CultureInfo.InvariantCulture));
        }

        return arguments;
    }

    /// <summary>The kernel's spelling of "this route does not exist", in the forms <c>ip</c> reports.</summary>
    private static bool IsAlreadyGone(CommandResult result) =>
        ContainsAny(result.Combined, "No such process", "No such file or directory")
        || ContainsAny(result.Combined, "Cannot find device", "No such device");

    /// <summary>The kernel's spelling of "this route is already installed".</summary>
    private static bool IsAlreadyExists(CommandResult result) =>
        result.Combined.Contains("File exists", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(string text, params string[] needles) =>
        needles.Any(needle => text.Contains(needle, StringComparison.OrdinalIgnoreCase));

    private static bool IsOwnedDevice(string device) =>
        device.StartsWith(OwnedInterfacePrefix, StringComparison.Ordinal);

    /// <summary>
    /// True for a route the kernel created for the device or address itself (<c>proto kernel</c>),
    /// which is therefore not MyVpn's to create or delete.
    /// </summary>
    private static bool IsKernelManaged(ObservedRoute route) =>
        string.Equals(route.Protocol, "kernel", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// <c>ip route show table N</c> exits non-zero when table N has never been created. That is the
    /// strongest possible statement that the table is empty, not a failure to look at it.
    /// </summary>
    private static bool IsMissingTable(CommandResult result) =>
        result.Combined.Contains("FIB table does not exist", StringComparison.OrdinalIgnoreCase);

    private static string FamilyFlag(bool isIpv6) => isIpv6 ? "-6" : "-4";

    /// <summary>Renders a destination the way <c>ip</c> both accepts and prints it.</summary>
    private static string RenderDestination(CidrBlock destination) =>
        destination.PrefixLength == 0 ? "default" : destination.ToString();

    private static bool Matches(RouteEntry expected, ObservedRoute observed)
    {
        if (!string.Equals(observed.Device, expected.Interface, StringComparison.Ordinal))
        {
            return false;
        }

        if (!SameDestination(expected.Destination, observed.Destination))
        {
            return false;
        }

        if (expected.Gateway is not null && !SameAddress(observed.Gateway, expected.Gateway))
        {
            return false;
        }

        // A listing may omit the metric, in which case the destination and device already identify the
        // route; when it is printed it must agree with the plan.
        return observed.Metric is null || observed.Metric == expected.Metric;
    }

    /// <summary>
    /// Compares a planned prefix with the token <c>ip</c> printed.
    /// </summary>
    /// <remarks>
    /// Both sides are parsed as CIDR blocks rather than compared as text: the kernel prints a host
    /// route as a bare address (<c>203.0.113.7</c>, not <c>203.0.113.7/32</c>), and a text comparison
    /// would silently report every host route as missing. <c>default</c> is how the zero prefix is
    /// printed.
    /// </remarks>
    private static bool SameDestination(CidrBlock expected, string observed)
    {
        if (observed == "default")
        {
            return expected.PrefixLength == 0;
        }

        return CidrBlock.TryParse(observed, out var block) && block == expected;
    }

    private static bool SameAddress(string? left, string right)
    {
        if (left is null)
        {
            return false;
        }

        if (string.Equals(left, right, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(left, out var a)
               && IPAddress.TryParse(right, out var b)
               && a.Equals(b);
    }

    private static IEnumerable<ObservedRoute> ParseRoutes(string output, bool isIpv6)
    {
        foreach (var line in SplitLines(output))
        {
            var tokens = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 0)
            {
                continue;
            }

            var index = 0;
            var destination = tokens[index];

            // `ip route show` can also print local/broadcast/unreachable entries; their type keyword
            // comes first and the prefix second.
            if (IsRouteTypeKeyword(destination) && tokens.Length > 1)
            {
                index++;
                destination = tokens[index];
            }

            index++;

            string? gateway = null;
            var device = string.Empty;
            string? protocol = null;
            int? metric = null;

            var position = index;
            while (position < tokens.Length)
            {
                switch (tokens[position])
                {
                    case "via" when position + 1 < tokens.Length:
                        gateway = tokens[position + 1];
                        position += 2;
                        break;
                    case "dev" when position + 1 < tokens.Length:
                        device = tokens[position + 1];
                        position += 2;
                        break;
                    case "proto" when position + 1 < tokens.Length:
                        protocol = tokens[position + 1];
                        position += 2;
                        break;
                    case "metric" when position + 1 < tokens.Length:
                        metric = ParseInt(tokens[position + 1]);
                        position += 2;
                        break;
                    default:
                        position++;
                        break;
                }
            }

            yield return new ObservedRoute(line, destination, gateway, device, protocol, metric, isIpv6);
        }
    }

    private static IEnumerable<ObservedRule> ParseMyVpnRules(string output)
    {
        foreach (var line in SplitLines(output))
        {
            var separator = line.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0
                || !int.TryParse(
                    line[..separator].Trim(),
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var priority))
            {
                continue;
            }

            var tokens = line[(separator + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);

            int? mark = null;
            for (var i = 0; i + 1 < tokens.Length; i++)
            {
                if (tokens[i] == "fwmark")
                {
                    mark = ParseMark(tokens[i + 1]);
                    break;
                }
            }

            // The mark is the ownership marker: it is MyVpn's own value, and nothing else on the host
            // has a reason to use it.
            if (mark == VpnFirewallMark)
            {
                yield return new ObservedRule(priority, mark.Value, line);
            }
        }
    }

    /// <summary>Parses <c>0xca6c</c> and <c>0xca6c/0xca6c</c> alike.</summary>
    private static int? ParseMark(string text)
    {
        var slash = text.IndexOf('/', StringComparison.Ordinal);
        var value = slash >= 0 ? text[..slash] : text;

        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            value = value[2..];
        }

        return int.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var mark)
            ? mark
            : null;
    }

    private static int? ParseInt(string text) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : null;

    private static bool IsRouteTypeKeyword(string token) =>
        token is "local" or "broadcast" or "unreachable" or "blackhole" or "prohibit" or "throw" or "nat";

    private static IEnumerable<string> SplitLines(string output) =>
        output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => line.Length > 0);

    private static RouteState EmptyState() => new()
    {
        TunnelRoutesPresent = false,
        BypassRoutesPresent = false,
        OrphanedRoutes = Array.Empty<string>(),
    };

    private static MyVpnError NotElevated() =>
        new(
            ErrorCodes.PrivilegeDenied,
            "error.route.needs_privileges",
            ErrorSeverity.Error,
            "Changing the routing table requires CAP_NET_ADMIN. The UI must never run as root; this "
            + "step belongs to the privileged helper.",
            "privilege.install_helper");

    private static MyVpnError ToolMissing() =>
        new MyVpnError(
            ErrorCodes.PlatformToolMissing,
            "error.route.tool_missing",
            ErrorSeverity.Error,
            "The 'ip' tool (iproute2) is not installed, so routes cannot be applied or inspected.",
            "route.install_iproute2")
        .WithArg("tool", IpBinary);

    private static MyVpnError NoDefaultToDisplace() =>
        new(
            ErrorCodes.RouteAddFailed,
            "error.route.displace_without_capture",
            ErrorSeverity.Error,
            "The plan displaces the default route, but no physical default route could be captured "
            + "first, so there would be nothing to restore if the tunnel failed to come up.",
            "network.restore");

    private static MyVpnError NoDefaultRoute(string family, CommandResult result) =>
        new(
            ErrorCodes.NotFound,
            "error.route.no_default_route",
            ErrorSeverity.Error,
            $"'ip {family} route show default' returned no default route "
            + $"(exit {result.ExitCode}): {Trim(result.Combined)}");

    private static MyVpnError AddFailed(RouteEntry route, CommandResult result) =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.route.add_failed",
            ErrorSeverity.Error,
            $"'ip route add {route}' failed with exit code {result.ExitCode}: {Trim(result.Combined)}",
            "network.restore")
        .WithArg("route", route.ToString());

    /// <summary>
    /// The fail-closed abort: the bypass route failed, so nothing that captures the default prefix was
    /// installed. The detail says so explicitly, because "route add failed" alone would not explain why
    /// the session refused to continue.
    /// </summary>
    private static MyVpnError BypassFailed(RouteEntry route, MyVpnError cause) =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.route.bypass_failed",
            ErrorSeverity.Error,
            $"The uplink host route that keeps the core's own traffic off the tunnel could not be "
            + $"installed, so no default-capturing route was installed: 'ip route add {route}' failed "
            + $"with {cause.TechnicalDetail ?? cause.MessageKey}.",
            "network.restore")
        .WithArg("route", route.ToString());

    private static MyVpnError RemoveFailed(RouteEntry route, CommandResult result) =>
        new MyVpnError(
            ErrorCodes.RouteRemoveFailed,
            "error.route.remove_failed",
            ErrorSeverity.Critical,
            $"'ip route del {route}' failed with exit code {result.ExitCode}: {Trim(result.Combined)}",
            "network.restore")
        .WithArg("route", route.ToString());

    private static MyVpnError RestoreFailed(ObservedRoute displaced, CommandResult result) =>
        new(
            ErrorCodes.RouteRemoveFailed,
            "error.route.restore_failed",
            ErrorSeverity.Critical,
            $"The displaced default route ('{displaced.Text.Trim()}') could not be restored: exit code "
            + $"{result.ExitCode}: {Trim(result.Combined)}",
            "network.restore");

    private static MyVpnError RemoveFailed(IReadOnlyList<string> failures) =>
        new(
            ErrorCodes.RouteRemoveFailed,
            "error.route.remove_failed",
            ErrorSeverity.Critical,
            "Some MyVpn routing state could not be removed: " + Trim(string.Join(" | ", failures)),
            "network.restore");

    private static string Describe(MyVpnError error) =>
        error.TechnicalDetail ?? error.MessageKey;

    private static string Describe(CommandResult result, string what) =>
        $"{what} failed with exit code {result.ExitCode}: {Trim(result.Combined)}";

    private static string Trim(string? value) =>
        value switch
        {
            null => string.Empty,
            { Length: <= 300 } => value,
            _ => value[..300] + "…",
        };

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

    /// <summary>A route as the kernel printed it, parsed into the fields this executor reasons about.</summary>
    private sealed record ObservedRoute(
        string Text,
        string Destination,
        string? Gateway,
        string Device,
        string? Protocol,
        int? Metric,
        bool IsIpv6);

    /// <summary>A policy rule MyVpn owns, identified by its mark.</summary>
    private sealed record ObservedRule(int Priority, int Mark, string Text);
}
