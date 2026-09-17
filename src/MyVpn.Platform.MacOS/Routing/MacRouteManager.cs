using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.Routing;

namespace MyVpn.Platform.MacOS.Routing;

/// <summary>
/// The <c>route</c> and <c>netstat</c> argv vectors MyVpn can issue, as pure functions.
/// </summary>
/// <remarks>
/// <para>
/// The forms follow <c>route(8)</c> exactly: <c>route add -inet6 2001:db8::/32 2001:db8::1</c> for a
/// route through a gateway, and <c>route add -inet6 2001:db8:1234::/64 -interface en0</c> for a route
/// that is directly reachable on an interface — which is the form a point-to-point utun needs, and the
/// form WireGuard's Darwin script uses verbatim
/// (<c>route -q -n add -inet 0.0.0.0/1 -interface "$REAL_INTERFACE"</c>).
/// </para>
/// <para>
/// Two deliberate omissions, both documented rather than accidental:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b>No metric.</b> macOS <c>route(8)</c> has no per-route metric modifier.
/// <see cref="RouteEntry.Metric"/> is ignored; precedence comes from prefix specificity and interface
/// scope. The parameter is honoured on Linux, where <c>ip route</c> supports it, so a plan that
/// carries one is still valid here — it simply has nothing to apply it to.
/// </description></item>
/// <item><description>
/// <b>No <c>-static</c>.</b> It would mark our routes for identification, but <c>netstat</c> reports
/// the flag for every manually added route including the user's own, so it identifies nothing that
/// MyVpn can safely claim ownership of. Ownership is carried by the journal instead.
/// </description></item>
/// </list>
/// </remarks>
public static class MacRouteCommands
{
    /// <summary>The tool that modifies the routing table.</summary>
    public const string Binary = "route";

    /// <summary>The tool that reads the routing table.</summary>
    public const string NetstatBinary = "netstat";

    /// <summary>Builds the <c>route add</c> argv for a route entry.</summary>
    public static IReadOnlyList<string> Add(RouteEntry route)
    {
        ArgumentNullException.ThrowIfNull(route);

        var family = route.Destination.IsIPv6 ? "-inet6" : "-inet";
        var destination = RenderDestination(route.Destination);

        var arguments = new List<string>(6) { "-n", "add", family, destination };

        if (string.IsNullOrWhiteSpace(route.Gateway))
        {
            if (!IsSafeInterfaceName(route.Interface))
            {
                throw new ArgumentException(
                    $"'{route.Interface}' is not a usable interface name.", nameof(route));
            }

            arguments.Add("-interface");
            arguments.Add(route.Interface);
        }
        else
        {
            arguments.Add(route.Gateway!);
        }

        return arguments;
    }

    /// <summary>
    /// Builds the <c>route delete</c> argv for a route entry.
    /// </summary>
    /// <remarks>
    /// The destination alone identifies the route. The gateway is deliberately not repeated: after the
    /// tunnel interface disappears XNU's <c>if_rtdel()</c> removes the interface's routes anyway, and a
    /// destination-only delete is the form the man page documents and cannot fail because a gateway
    /// address changed.
    /// </remarks>
    public static IReadOnlyList<string> Delete(RouteEntry route)
    {
        ArgumentNullException.ThrowIfNull(route);

        var family = route.Destination.IsIPv6 ? "-inet6" : "-inet";
        return new[] { "-n", "delete", family, RenderDestination(route.Destination) };
    }

    /// <summary>Builds the argv that reads the current default route.</summary>
    public static IReadOnlyList<string> GetDefault(bool ipv6) =>
        ipv6
            ? new[] { "-n", "get", "-inet6", "default" }
            : new[] { "-n", "get", "default" };

    /// <summary>Builds the argv that dumps one address family's routing table.</summary>
    public static IReadOnlyList<string> ListRoutes(bool ipv6) =>
        new[] { "-rn", "-f", ipv6 ? "inet6" : "inet" };

    /// <summary>Every argv shape this class can produce.</summary>
    public static IReadOnlyList<IReadOnlyList<string>> AllShapes() => new[]
    {
        Add(new RouteEntry
        {
            Destination = CidrBlock.Parse("0.0.0.0/1"),
            Interface = "utun0",
            ReasonKey = "route.reason.tunnel",
        }),
        Add(new RouteEntry
        {
            Destination = CidrBlock.Parse("203.0.113.5/32"),
            Gateway = "192.0.2.1",
            Interface = "en0",
            ReasonKey = "route.reason.bypass",
        }),
        Delete(new RouteEntry
        {
            Destination = CidrBlock.Parse("128.0.0.0/1"),
            Interface = "utun0",
            ReasonKey = "route.reason.tunnel",
        }),
        GetDefault(ipv6: false),
        GetDefault(ipv6: true),
        ListRoutes(ipv6: false),
        ListRoutes(ipv6: true),
    };

    /// <summary>Renders a destination in the <c>net/bits</c> form <c>route(8)</c> documents.</summary>
    public static string RenderDestination(CidrBlock destination) => destination.ToString();

    /// <summary>
    /// True when a name may be handed to <c>route -interface</c>.
    /// </summary>
    /// <remarks>
    /// Interface names reach argv, so a name starting with <c>-</c> would be read as a flag and a
    /// control character could forge a log line. Arguments are passed as a vector with no shell, so
    /// this is defence in depth rather than the only protection.
    /// </remarks>
    public static bool IsSafeInterfaceName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 15)
        {
            return false;
        }

        if (name[0] is '-' or '.')
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.'))
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>
/// One route as <c>netstat -rn</c> reports it.
/// </summary>
/// <param name="Destination">The destination block.</param>
/// <param name="Gateway">Gateway address, or <c>null</c> for an on-link route.</param>
/// <param name="Interface">Outgoing interface name.</param>
/// <param name="Flags">The raw flags column, kept for diagnostics.</param>
/// <param name="Text">The raw line, for error messages.</param>
public sealed record ObservedRoute(
    CidrBlock Destination,
    string? Gateway,
    string Interface,
    string Flags,
    string Text);

/// <summary>One line of the on-disk route journal.</summary>
public sealed record JournalEntry(string Kind, RouteEntry Route);

/// <summary>What a planned routing-table operation does.</summary>
public enum RouteOperationKind
{
    Add = 1,
    Delete = 2,
}

/// <summary>
/// One step of an apply or teardown, in the order it must be executed.
/// </summary>
/// <param name="Kind">Whether the step adds or deletes the route.</param>
/// <param name="Route">The route the step acts on.</param>
/// <param name="FailClosed">
/// True when a failure of this step must abort the whole apply. Bypass routes are fail-closed: without
/// the uplink host route to the server, capturing the default prefix would route the core's own
/// transport into the tunnel that cannot carry it.
/// </param>
public sealed record RouteOperation(RouteOperationKind Kind, RouteEntry Route, bool FailClosed);

/// <summary>
/// Applies a <see cref="RoutePlan"/> to the macOS routing table through <c>route</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Half-routes, not a mutated default.</b> When a tunnel route captures the default prefix, this
/// class installs OpenVPN's "def1" pair — <c>0.0.0.0/1</c> and <c>128.0.0.0/1</c> (or <c>::/1</c> and
/// <c>8000::/1</c>) — instead of running <c>route change default</c>. The research is explicit about
/// why: the /1 routes are more specific than <c>0.0.0.0/0</c>, so they win for every address while the
/// original default stays installed; there is no <c>EEXIST</c> to work around, no interface-scope
/// juggling, teardown is a two-route delete, and XNU's <c>if_rtdel()</c> removes them by itself when
/// the utun disappears, which makes a crash far less likely to leave a machine with no default route.
/// Mutating the single real default entry has the opposite property: if configd does not republish one
/// after the tunnel goes away, the machine is offline until it does.
/// </para>
/// <para>
/// <b>Ordering is a safety property, not a style choice.</b> Bypass routes (the uplink host routes that
/// keep the core's own connection to the server off the tunnel) are installed <i>before</i> any
/// default-capturing route and removed <i>after</i> it. Reversing either half briefly routes the core's
/// transport into a tunnel that is being built or torn down, which presents as "connects, then
/// immediately stalls" with nothing in the logs.
/// </para>
/// <para>
/// <b>Fail closed.</b> If a bypass route cannot be installed, no tunnel route is installed at all, and
/// the bypass routes this call managed to add are rolled back. Capturing the default without the host
/// route to the server is the same loop from the other side.
/// </para>
/// <para>
/// <b>Ownership comes from a journal, not from a guess.</b> Cleanup after a crash cannot reconstruct a
/// plan the dead process never saved, and macOS offers nothing to mark a route as ours:
/// <c>netstat</c> shows <c>RTF_STATIC</c> for every manually added route, and half-routes on a
/// <c>utun</c> interface could equally belong to WireGuard or another VPN. Deleting another product's
/// routes would be worse than leaving ours behind, so <see cref="ApplyAsync"/> writes
/// <c>/var/run/myvpn.routes</c> before it changes anything (the research's route-journal
/// recommendation), and <see cref="RemoveAllOwnedAsync"/> deletes exactly what the journal lists.
/// A journal that is missing means "nothing can be proven to be ours", and that is reported rather
/// than guessed at.
/// </para>
/// <para>
/// <b>Per-process routing is not implemented here, by design</b> — see the remarks on
/// <c>MacPfKillSwitch</c> and <c>docs/research/08-macos-networking.md</c> §1.4.7 for the verdict and
/// the evidence behind it.
/// </para>
/// </remarks>
public sealed class MacRouteManager : IRouteManager
{
    /// <summary>
    /// Where the route journal is written. <c>/var/run</c> is root-writable and cleared at boot, which
    /// matches the lifetime of the routes it describes.
    /// </summary>
    public const string DefaultJournalPath = "/var/run/myvpn.routes";

    /// <summary>Journal line kinds.</summary>
    public const string TunnelKind = "tunnel";

    /// <summary>Journal line kind for an uplink host route.</summary>
    public const string BypassKind = "bypass";

    private readonly ICommandRunner _runner;
    private readonly Func<bool> _isElevated;
    private readonly string _journalPath;

    public MacRouteManager(
        ICommandRunner? runner = null,
        Func<bool>? isElevated = null,
        string? journalPath = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(journalPath ?? DefaultJournalPath);

        _runner = runner ?? new ProcessCommandRunner();
        _isElevated = isElevated ?? DefaultElevationCheck;
        _journalPath = journalPath ?? DefaultJournalPath;
    }

    /// <summary>
    /// True when this is macOS, <c>route</c> is present, and this process may change the routing table
    /// (<c>route(8)</c>: "only the super-user may modify the routing tables").
    /// </summary>
    public bool IsSupported =>
        OperatingSystem.IsMacOS()
        && _runner.Exists(MacRouteCommands.Binary)
        && _isElevated();

    public async Task<Result> ApplyAsync(RoutePlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return validation;
        }

        var guard = Guard();
        if (guard is not null)
        {
            return Result.Fail(guard);
        }

        // A bypass route that captures the default is a contradiction: it is supposed to pin the
        // server to the physical uplink, and a default route on the physical link would defeat the
        // tunnel entirely. Refuse rather than install something with the opposite meaning.
        var badBypass = plan.BypassRoutes.FirstOrDefault(r => r.Destination.PrefixLength == 0);
        if (badBypass is not null)
        {
            return Result.Fail(BypassCapturesDefault(badBypass));
        }

        var tunnelRoutes = ExpandRoutes(plan.TunnelRoutes);
        var bypassRoutes = plan.BypassRoutes.ToArray();

        // The journal is written before the first mutation. After a crash it is the only record of
        // what MyVpn owns; a failure to write it aborts the apply, because an unrecorded
        // default-capturing route is exactly the state emergency cleanup exists to recover from.
        var journal = await WriteJournalAsync(tunnelRoutes, bypassRoutes, cancellationToken)
            .ConfigureAwait(false);

        if (journal.IsFailure)
        {
            return journal;
        }

        // The sequence — bypass routes first, then the tunnel routes that may capture the default — is
        // produced by a pure function so its ordering can be asserted without a routing table.
        var operations = BuildApplySequence(plan);
        var installed = new List<RouteEntry>();

        for (var index = 0; index < operations.Count; index++)
        {
            var operation = operations[index];
            var added = await AddAsync(operation.Route, cancellationToken).ConfigureAwait(false);

            if (added.IsSuccess)
            {
                installed.Add(operation.Route);
                continue;
            }

            if (operation.FailClosed)
            {
                // Fail closed *and* clean up: the bypass routes added by this call are removed again,
                // because a half-installed uplink pin is a state nobody asked for.
                await RollbackAsync(installed, cancellationToken).ConfigureAwait(false);
                return Result.Fail(BypassFailed(operation.Route, added.Error!));
            }

            // The bypass routes and the journal stay in place: they describe what was installed, and
            // teardown uses them.
            return Result.Fail(added.Error!);
        }

        return Result.Ok();
    }

    public async Task<Result> RemoveAsync(RoutePlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        // Teardown deliberately does not validate the plan: a plan that fails validation still
        // describes routes that may exist, and refusing to clean up is how a half-routed machine stays
        // half-routed.
        var guard = Guard(allowMissingTool: true);
        if (guard is not null)
        {
            return Result.Fail(guard);
        }

        if (!_runner.Exists(MacRouteCommands.Binary))
        {
            return Result.Ok();
        }

        var failures = new List<string>();

        // Reverse order: tunnel routes first, then the bypass routes they depended on. The sequence is
        // pure so the mirror image of installation can be asserted by tests.
        foreach (var operation in BuildRemoveSequence(plan))
        {
            await DeleteAsync(operation.Route, failures, cancellationToken).ConfigureAwait(false);
        }

        DeleteJournal();

        return failures.Count == 0 ? Result.Ok() : Result.Fail(RemoveFailed(failures));
    }

    /// <summary>
    /// Removes exactly the routes the journal lists, then the journal itself.
    /// </summary>
    /// <remarks>
    /// This is the panic-clear path after a crash. It cannot take a plan, and it refuses to infer
    /// ownership from the routing table: a <c>0.0.0.0/1</c> route on a <c>utun</c> interface could
    /// belong to another VPN, and deleting it would break a product the user is relying on. A missing
    /// or unreadable journal therefore means "nothing provably ours", and the result says so.
    /// </remarks>
    public async Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
    {
        var guard = Guard(allowMissingTool: true);
        if (guard is not null)
        {
            return Result.Fail(guard);
        }

        if (!_runner.Exists(MacRouteCommands.Binary))
        {
            return Result.Ok();
        }

        var entries = ReadJournal();
        if (entries.Count == 0)
        {
            return Result.Ok();
        }

        var failures = new List<string>();

        foreach (var entry in entries.Reverse())
        {
            await DeleteAsync(entry.Route, failures, cancellationToken).ConfigureAwait(false);
        }

        if (failures.Count == 0)
        {
            DeleteJournal();
        }

        return failures.Count == 0 ? Result.Ok() : Result.Fail(RemoveFailed(failures));
    }

    public async Task<RouteState> InspectAsync(RoutePlan? expected, CancellationToken cancellationToken)
    {
        if (!IsSupported || !_runner.Exists(MacRouteCommands.NetstatBinary))
        {
            return EmptyState();
        }

        var observed = await ReadRoutesAsync(cancellationToken).ConfigureAwait(false);
        if (observed.Count == 0)
        {
            return EmptyState();
        }

        var tunnel = expected is not null
            ? ExpandRoutes(expected.TunnelRoutes)
            : ReadJournal().Where(e => e.Kind == TunnelKind).Select(e => e.Route).ToArray();

        var bypass = expected is not null
            ? expected.BypassRoutes
            : ReadJournal().Where(e => e.Kind == BypassKind).Select(e => e.Route).ToArray();

        // Orphans: routes that look exactly like MyVpn's half-routes on a utun interface but that the
        // journal does not know about — a crashed run whose journal was lost, or a leftover from a
        // build that predates the journal.
        var orphans = observed
            .Where(IsHalfRouteOnTunnel)
            .Where(o => !tunnel.Any(t => Matches(t, o)))
            .Select(o => o.Text.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return new RouteState
        {
            TunnelRoutesPresent = tunnel.Count > 0 && tunnel.All(r => observed.Any(o => Matches(r, o))),
            BypassRoutesPresent = bypass.Count > 0 && bypass.All(r => observed.Any(o => Matches(r, o))),

            // Always null: this implementation never mutates the system default route, which is the
            // whole point of the def1 pair. A non-null value here would mean the research's
            // recommendation had been abandoned.
            DisplacedDefaultRoute = null,
            OrphanedRoutes = orphans,
        };
    }

    public async Task<Result<PhysicalUplink>> GetDefaultUplinkAsync(CancellationToken cancellationToken)
    {
        var guard = Guard();
        if (guard is not null)
        {
            return Result<PhysicalUplink>.Fail(guard);
        }

        foreach (var ipv6 in new[] { false, true })
        {
            var result = await RunAsync(MacRouteCommands.GetDefault(ipv6), cancellationToken)
                .ConfigureAwait(false);

            if (!result.Succeeded)
            {
                continue;
            }

            var uplink = ParseDefaultRoute(result.StandardOutput, ipv6);
            if (uplink is not null)
            {
                return Result<PhysicalUplink>.Ok(uplink);
            }
        }

        return Result<PhysicalUplink>.Fail(NoDefaultRoute());
    }

    // ------------------------------------------------------------------ pure helpers

    /// <summary>
    /// The order in which a plan's routes must be installed.
    /// </summary>
    /// <remarks>
    /// Pure, because the ordering is a safety property rather than an implementation detail: every
    /// bypass (uplink host) route comes before any route that may capture the default prefix. A caller
    /// that "simplified" this into one loop over both lists would reintroduce the connect-then-stall
    /// loop the bypass routes exist to prevent, and a test asserts the order so that cannot happen
    /// quietly.
    /// </remarks>
    public static IReadOnlyList<RouteOperation> BuildApplySequence(RoutePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var operations = new List<RouteOperation>(plan.BypassRoutes.Count + plan.TunnelRoutes.Count);

        foreach (var route in plan.BypassRoutes)
        {
            // Fail-closed: if the server cannot be pinned to the physical uplink, nothing that captures
            // the default may be installed.
            operations.Add(new RouteOperation(RouteOperationKind.Add, route, FailClosed: true));
        }

        foreach (var route in ExpandRoutes(plan.TunnelRoutes))
        {
            operations.Add(new RouteOperation(RouteOperationKind.Add, route, FailClosed: false));
        }

        return operations;
    }

    /// <summary>
    /// The order in which a plan's routes must be removed: the exact mirror image of installation, so
    /// the tunnel routes go first and the bypass routes that carried them go last.
    /// </summary>
    public static IReadOnlyList<RouteOperation> BuildRemoveSequence(RoutePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var operations = new List<RouteOperation>(plan.BypassRoutes.Count + plan.TunnelRoutes.Count);

        foreach (var route in ExpandRoutes(plan.TunnelRoutes).Reverse())
        {
            operations.Add(new RouteOperation(RouteOperationKind.Delete, route, FailClosed: false));
        }

        foreach (var route in plan.BypassRoutes.Reverse())
        {
            operations.Add(new RouteOperation(RouteOperationKind.Delete, route, FailClosed: false));
        }

        return operations;
    }

    /// <summary>
    /// Translates a default-capturing route into OpenVPN's "def1" half-routes.
    /// </summary>
    /// <remarks>
    /// A route that is not a default is returned unchanged, so the function is safe to apply to every
    /// route in a plan and idempotent: a plan that already carries the half-routes passes through.
    /// </remarks>
    public static IReadOnlyList<RouteEntry> ExpandRoute(RouteEntry route)
    {
        ArgumentNullException.ThrowIfNull(route);

        if (route.Destination.PrefixLength != 0)
        {
            return new[] { route };
        }

        var halves = route.Destination.IsIPv6
            ? new[] { "::/1", "8000::/1" }
            : new[] { "0.0.0.0/1", "128.0.0.0/1" };

        return halves
            .Select(half => route with
            {
                Destination = CidrBlock.Parse(half),

                // The half-routes do not displace anything: the original default is untouched, which
                // is the reason for using them.
                DisplacesDefaultRoute = false,
            })
            .ToArray();
    }

    /// <summary>Expands every route in a sequence and removes exact duplicates.</summary>
    public static IReadOnlyList<RouteEntry> ExpandRoutes(IEnumerable<RouteEntry> routes)
    {
        ArgumentNullException.ThrowIfNull(routes);

        var expanded = new List<RouteEntry>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var route in routes)
        {
            foreach (var candidate in ExpandRoute(route))
            {
                var key = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{candidate.Destination}|{candidate.Gateway}|{candidate.Interface}");

                if (seen.Add(key))
                {
                    expanded.Add(candidate);
                }
            }
        }

        return expanded;
    }

    /// <summary>Renders the journal written before the routing table is touched.</summary>
    public static string RenderJournal(IEnumerable<RouteEntry> tunnelRoutes, IEnumerable<RouteEntry> bypassRoutes)
    {
        ArgumentNullException.ThrowIfNull(tunnelRoutes);
        ArgumentNullException.ThrowIfNull(bypassRoutes);

        var builder = new System.Text.StringBuilder(512);
        builder.Append("# MyVpn route journal — generated file, do not edit by hand.\n");
        builder.Append("# Written before the first route mutation and replayed by RemoveAllOwnedAsync after\n");
        builder.Append("# a crash. Only MyVpn's own routes are listed; the system default is never modified.\n");

        foreach (var route in tunnelRoutes)
        {
            AppendJournalLine(builder, TunnelKind, route);
        }

        foreach (var route in bypassRoutes)
        {
            AppendJournalLine(builder, BypassKind, route);
        }

        return builder.ToString();
    }

    /// <summary>Parses a journal, ignoring comments and anything unrecognisable.</summary>
    public static IReadOnlyList<JournalEntry> ParseJournal(string? contents)
    {
        var entries = new List<JournalEntry>();

        if (string.IsNullOrEmpty(contents))
        {
            return entries;
        }

        foreach (var rawLine in contents.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 5)
            {
                continue;
            }

            var kind = fields[0];
            if (kind != TunnelKind && kind != BypassKind)
            {
                continue;
            }

            if (!CidrBlock.TryParse(fields[2], out var destination))
            {
                continue;
            }

            var gateway = fields[3] == "-" ? null : fields[3];

            entries.Add(new JournalEntry(kind, new RouteEntry
            {
                Destination = destination,
                Gateway = gateway,
                Interface = fields[4],
                ReasonKey = kind == TunnelKind ? "route.reason.tunnel" : "route.reason.bypass",
            }));
        }

        return entries;
    }

    /// <summary>
    /// Parses <c>netstat -rn</c> output for one address family.
    /// </summary>
    /// <remarks>
    /// Both the CIDR form (<c>10.0.0.0/8</c>) and the classful shorthand <c>netstat</c> still prints
    /// for class A/B/C boundaries (<c>10</c>, <c>172.16</c>, <c>192.168.1</c>) are accepted, as is a
    /// bare host address. Unrecognised lines are skipped: the header, the section titles and the
    /// IPv6 link-local noise must not turn an inspection into a failure.
    /// </remarks>
    public static IReadOnlyList<ObservedRoute> ParseRoutes(string? output, bool isIpv6)
    {
        var routes = new List<ObservedRoute>();

        if (string.IsNullOrEmpty(output))
        {
            return routes;
        }

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("Routing tables", StringComparison.Ordinal))
            {
                continue;
            }

            var fields = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 4)
            {
                continue;
            }

            if (!TryParseDestination(fields[0], isIpv6, out var destination))
            {
                continue;
            }

            var flags = fields[2];
            if (flags.Length == 0 || !char.IsLetter(flags[0]))
            {
                continue;
            }

            var gateway = fields[1].StartsWith("link#", StringComparison.OrdinalIgnoreCase)
                ? null
                : fields[1];

            routes.Add(new ObservedRoute(destination, gateway, fields[3], flags, line));
        }

        return routes;
    }

    /// <summary>Parses <c>route -n get default</c> into the physical uplink.</summary>
    public static PhysicalUplink? ParseDefaultRoute(string? output, bool isIpv6 = false)
    {
        if (string.IsNullOrEmpty(output))
        {
            return null;
        }

        string? gateway = null;
        string? interfaceName = null;

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            var key = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();

            if (key.Equals("gateway", StringComparison.OrdinalIgnoreCase))
            {
                gateway = value;
            }
            else if (key.Equals("interface", StringComparison.OrdinalIgnoreCase))
            {
                interfaceName = value;
            }
        }

        if (string.IsNullOrWhiteSpace(interfaceName))
        {
            return null;
        }

        return new PhysicalUplink(interfaceName!, string.IsNullOrWhiteSpace(gateway) ? null : gateway, isIpv6);
    }

    /// <summary>
    /// Parses a <c>netstat</c> destination token into a block.
    /// </summary>
    public static bool TryParseDestination(string? token, bool isIpv6, out CidrBlock destination)
    {
        destination = default;

        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        if (token.Equals("default", StringComparison.OrdinalIgnoreCase))
        {
            destination = CidrBlock.Parse(isIpv6 ? "::/0" : "0.0.0.0/0");
            return true;
        }

        // Classful shorthand is checked *before* CidrBlock.TryParse: IPAddress.TryParse accepts "10" as
        // 0.0.0.10, so the CIDR path would silently turn netstat's "10" (meaning 10.0.0.0/8) into a host
        // route. "10" is 10.0.0.0/8, "172.16" is 172.16.0.0/16, "192.168.1" is 192.168.1.0/24. A
        // four-part token is a host address and falls through to the normal parser.
        if (!isIpv6
            && !token.Contains('/', StringComparison.Ordinal)
            && token.All(c => char.IsAsciiDigit(c) || c == '.'))
        {
            var parts = token.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length is >= 1 and <= 3)
            {
                var padded = parts.Concat(Enumerable.Repeat("0", 4 - parts.Length)).ToArray();
                if (IPAddress.TryParse(string.Join('.', padded), out var address))
                {
                    destination = new CidrBlock(address, parts.Length * 8);
                    return true;
                }

                return false;
            }
        }

        return CidrBlock.TryParse(token, out destination);
    }

    /// <summary>True when the command's failure means the route already exists (<c>EEXIST</c>).</summary>
    /// <remarks>
    /// <c>route(4)</c>: "The routing code returns <c>EEXIST</c> if requested to duplicate an existing
    /// entry." A duplicate add is idempotent success, which is what makes re-applying a plan safe.
    /// </remarks>
    public static bool IsAlreadyExists(CommandResult result) =>
        ContainsAny(result.Combined, "File exists", "EEXIST", "already in table");

    /// <summary>True when the command's failure means the route was not there to delete.</summary>
    public static bool IsAlreadyGone(CommandResult result) =>
        ContainsAny(result.Combined, "not in table", "No such process", "ESRCH", "bad address");

    /// <summary>True when a route is one of the def1 halves on a utun interface.</summary>
    public static bool IsHalfRouteOnTunnel(ObservedRoute route)
    {
        ArgumentNullException.ThrowIfNull(route);

        var isHalf = route.Destination.PrefixLength == 1
                     && (route.Destination.IsIPv6
                         ? route.Destination.Network.Equals(IPAddress.IPv6Any)
                           || route.Destination.Network.Equals(IPAddress.Parse("8000::"))
                         : route.Destination.Network.Equals(IPAddress.Any)
                           || route.Destination.Network.Equals(IPAddress.Parse("128.0.0.0")));

        return isHalf && IsTunnelInterfaceName(route.Interface);
    }

    /// <summary>True when an interface name is a utun device.</summary>
    public static bool IsTunnelInterfaceName(string? interfaceName) =>
        !string.IsNullOrEmpty(interfaceName)
        && interfaceName.StartsWith("utun", StringComparison.Ordinal)
        && interfaceName.Length > 4
        && interfaceName[4..].All(char.IsAsciiDigit);

    // ------------------------------------------------------------------ error mapping (pure)

    /// <summary>Error for a call made on a host that is not macOS.</summary>
    public static MyVpnError UnsupportedOnThisHost() =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.platform.macos_only",
            ErrorSeverity.Error,
            "The macOS route manager drives 'route', which only exists on macOS. This call is "
            + "refused before any process is started.",
            "diagnostics.run");

    /// <summary>Error for a mutating call without privileges.</summary>
    public static MyVpnError NotElevated() =>
        new MyVpnError(
            ErrorCodes.PrivilegeDenied,
            "error.route.needs_privileges",
            ErrorSeverity.Error,
            "Modifying the routing table requires root ('only the super-user may modify the routing "
            + "tables'). MyVpn needs its privileged helper installed.",
            "privilege.install_helper");

    /// <summary>Error for a missing <c>route</c>.</summary>
    public static MyVpnError ToolMissing() =>
        new MyVpnError(
            ErrorCodes.PlatformToolMissing,
            "error.platform.tool_missing",
            ErrorSeverity.Error,
            "The 'route' tool was not found, so routes cannot be applied.",
            "diagnostics.run")
            .WithArg("tool", MacRouteCommands.Binary);

    /// <summary>Error for a bypass route that captures the default prefix.</summary>
    public static MyVpnError BypassCapturesDefault(RouteEntry route) =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.route.bypass_captures_default",
            ErrorSeverity.Error,
            $"Bypass route '{route}' captures the default prefix. A bypass route exists to pin the "
            + "server to the physical uplink; a default route on that link would defeat the tunnel.",
            "diagnostics.run");

    /// <summary>Error for an add that failed for a reason other than "already there".</summary>
    public static MyVpnError AddFailed(RouteEntry route, CommandResult result) =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.route.add_failed",
            ErrorSeverity.Error,
            $"Adding route '{route}' failed: {Trim(result.Combined)}",
            "network.restore");

    /// <summary>
    /// Error for a bypass route that could not be installed; the apply stopped before capturing the
    /// default.
    /// </summary>
    public static MyVpnError BypassFailed(RouteEntry route, MyVpnError cause) =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.route.bypass_failed",
            ErrorSeverity.Critical,
            $"The uplink bypass route '{route}' could not be installed, so no default-capturing route "
            + "was installed either: the core's own connection to the server would have been routed "
            + $"into the tunnel. Cause: {cause.Code}: {cause.TechnicalDetail ?? cause.MessageKey}",
            "network.restore");

    /// <summary>Error for a teardown that could not delete every route.</summary>
    public static MyVpnError RemoveFailed(IReadOnlyList<string> failures) =>
        new MyVpnError(
            ErrorCodes.RouteRemoveFailed,
            "error.route.remove_failed",
            ErrorSeverity.Error,
            $"Not every MyVpn route could be removed: {string.Join("; ", failures)}",
            "network.restore");

    /// <summary>Error for a journal that could not be written.</summary>
    public static MyVpnError JournalWriteFailed(string detail) =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.route.journal_write_failed",
            ErrorSeverity.Critical,
            "The route journal could not be written, so the apply was refused: an unrecorded "
            + "default-capturing route is exactly the state emergency cleanup exists to recover "
            + $"from. {detail}",
            "network.restore");

    /// <summary>Error for a machine with no default route to report.</summary>
    public static MyVpnError NoDefaultRoute() =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.route.no_default_route",
            ErrorSeverity.Error,
            "No default route could be read for either address family, so the physical uplink is "
            + "unknown and the core's traffic cannot be kept off the tunnel.",
            "diagnostics.run");

    // ------------------------------------------------------------------ internals

    private MyVpnError? Guard(bool allowMissingTool = false)
    {
        if (!OperatingSystem.IsMacOS())
        {
            return UnsupportedOnThisHost();
        }

        if (!allowMissingTool && !_runner.Exists(MacRouteCommands.Binary))
        {
            return ToolMissing();
        }

        if (!_isElevated())
        {
            return NotElevated();
        }

        return null;
    }

    private async Task<Result> AddAsync(RouteEntry route, CancellationToken cancellationToken)
    {
        var arguments = MacRouteCommands.Add(route);
        var result = await _runner.RunAsync(MacRouteCommands.Binary, arguments, cancellationToken)
            .ConfigureAwait(false);

        // A duplicate add is EEXIST: idempotent success, which is what makes re-applying a plan safe
        // after a crash or a settings change.
        return result.Succeeded || IsAlreadyExists(result)
            ? Result.Ok()
            : Result.Fail(AddFailed(route, result));
    }

    private async Task RollbackAsync(IReadOnlyList<RouteEntry> installed, CancellationToken cancellationToken)
    {
        foreach (var route in installed.Reverse())
        {
            var arguments = MacRouteCommands.Delete(route);
            await _runner.RunAsync(MacRouteCommands.Binary, arguments, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task DeleteAsync(
        RouteEntry route,
        List<string> failures,
        CancellationToken cancellationToken)
    {
        var arguments = MacRouteCommands.Delete(route);
        var result = await _runner.RunAsync(MacRouteCommands.Binary, arguments, cancellationToken)
            .ConfigureAwait(false);

        if (!result.Succeeded && !IsAlreadyGone(result))
        {
            failures.Add($"'{route}' could not be deleted: {Trim(result.Combined)}");
        }
    }

    private async Task<IReadOnlyList<ObservedRoute>> ReadRoutesAsync(CancellationToken cancellationToken)
    {
        var routes = new List<ObservedRoute>();

        foreach (var ipv6 in new[] { false, true })
        {
            var result = await RunAsync(MacRouteCommands.ListRoutes(ipv6), cancellationToken)
                .ConfigureAwait(false);

            if (result.Succeeded)
            {
                routes.AddRange(ParseRoutes(result.StandardOutput, ipv6));
            }
        }

        return routes;
    }

    private async Task<Result> WriteJournalAsync(
        IReadOnlyList<RouteEntry> tunnelRoutes,
        IReadOnlyList<RouteEntry> bypassRoutes,
        CancellationToken cancellationToken)
    {
        try
        {
            var directory = Path.GetDirectoryName(_journalPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await File.WriteAllTextAsync(
                    _journalPath, RenderJournal(tunnelRoutes, bypassRoutes), cancellationToken)
                .ConfigureAwait(false);

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(_journalPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            return Result.Ok();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result.Fail(JournalWriteFailed($"{ex.GetType().Name}: {ex.Message}"));
        }
    }

    private IReadOnlyList<JournalEntry> ReadJournal()
    {
        try
        {
            return File.Exists(_journalPath)
                ? ParseJournal(File.ReadAllText(_journalPath))
                : Array.Empty<JournalEntry>();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Array.Empty<JournalEntry>();
        }
    }

    private void DeleteJournal()
    {
        try
        {
            if (File.Exists(_journalPath))
            {
                File.Delete(_journalPath);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A stale journal only means the next cleanup tries to delete routes that are already
            // gone, which is idempotent.
        }
    }

    private static void AppendJournalLine(System.Text.StringBuilder builder, string kind, RouteEntry route)
    {
        var family = route.Destination.IsIPv6 ? "inet6" : "inet";
        var gateway = string.IsNullOrWhiteSpace(route.Gateway) ? "-" : route.Gateway!;

        builder.Append(CultureInfo.InvariantCulture,
            $"{kind} {family} {route.Destination} {gateway} {route.Interface}\n");
    }

    private static bool Matches(RouteEntry expected, ObservedRoute observed) =>
        expected.Destination.Equals(observed.Destination)
        && (string.IsNullOrWhiteSpace(expected.Interface)
            || string.Equals(expected.Interface, observed.Interface, StringComparison.Ordinal))
        && (string.IsNullOrWhiteSpace(expected.Gateway)
            || string.Equals(expected.Gateway, observed.Gateway, StringComparison.OrdinalIgnoreCase));

    private static bool ContainsAny(string text, params string[] needles) =>
        needles.Any(n => text.Contains(n, StringComparison.OrdinalIgnoreCase));

    private static RouteState EmptyState() => new()
    {
        TunnelRoutesPresent = false,
        BypassRoutesPresent = false,
        DisplacedDefaultRoute = null,
    };

    private Task<CommandResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken) =>
        _runner.RunAsync(MacRouteCommands.Binary, arguments, cancellationToken);

    private static string Trim(string? value)
    {
        var text = (value ?? string.Empty)
            .Replace('\n', ' ')
            .Replace('\r', ' ')
            .Trim();

        return text.Length <= 300 ? text : text[..300] + "…";
    }

    private static bool DefaultElevationCheck()
    {
        if (!OperatingSystem.IsMacOS())
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
}
