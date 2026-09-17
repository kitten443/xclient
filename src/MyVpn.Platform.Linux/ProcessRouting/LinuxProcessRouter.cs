using System.Globalization;
using System.Runtime.InteropServices;
using MyVpn.Core.Domain;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Processes;

namespace MyVpn.Platform.Linux.ProcessRouting;

/// <summary>
/// Enforces per-process routing on Linux through cgroup v2, nftables and policy routing.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the one platform where per-application redirection is real.</b> A process is moved into
/// a cgroup v2 slice, nftables matches that slice's sockets with <c>socket cgroupv2</c> and stamps a
/// firewall mark, and an <c>ip rule fwmark</c> sends the marked traffic to a dedicated routing table
/// whose default route is the tunnel. The capability therefore reports
/// <see cref="ProcessRoutingCapability.FullRedirect"/>, not <c>BlockOnly</c> as on Windows or
/// <c>UidBlockList</c> as on macOS.
/// </para>
/// <para>
/// <b>Nothing is assumed.</b> Before a single rule is loaded this executor checks, in order, that the
/// tools exist, that it is allowed to use them, that a cgroup v2 unified hierarchy is mounted, that
/// the slice could be created, and — with <c>nft --check</c> against the real slice — that the running
/// kernel can actually resolve a <c>socket cgroupv2</c> match (Linux ≥ 5.13, nftables ≥ 0.99). A rule
/// that cannot match is worse than an error: it reports success while every packet takes the
/// unprotected path, which is exactly the failure this feature exists to prevent.
/// </para>
/// <para>
/// <b>Loop prevention.</b> The core's own connection to the VPN server must never carry the mark, or
/// the tunnel's packets would be routed into the tunnel they are building. Three independent guards:
/// the core is never moved into a slice (only selector-matched processes are); the ruleset refuses to
/// mark traffic already leaving through the tunnel interface; and the server's addresses are pinned
/// to the <c>main</c> table at a higher precedence than the mark rule
/// (<see cref="NftablesProcessRoutingRenderer.EndpointRulePriority"/>).
/// </para>
/// <para>
/// <b>Re-apply after the slice is recreated.</b> <c>socket cgroupv2</c> resolves a numeric cgroup ID
/// when the ruleset is loaded, so a slice that is destroyed and re-created gets a new ID and the
/// installed rules silently stop matching (research risk R-1). <see cref="ApplyAsync"/> is therefore
/// idempotent and must be called again after any event that can recreate the slice — a restart, a
/// fresh boot, systemd replacing the cgroup — and after the selected applications are (re)started,
/// because a process that was not running when the plan was applied is not a member of the slice.
/// The same rules hold for the bypass table's physical route, which must be re-probed when the uplink
/// changes.
/// </para>
/// <para>
/// <b>argv only, never a shell.</b> Every external action is an <see cref="ICommandRunner"/>
/// invocation with an argv vector; the ruleset is handed to <c>nft</c> through a private temporary
/// file rather than a pipe built by string concatenation.
/// </para>
/// </remarks>
public sealed class CgroupV2ProcessRouter : ProcessRouterBase, IProcessRouter
{
    /// <summary>Firewall tool. The kill switch uses the same binary and needs the same capability.</summary>
    public const string NftBinary = "nft";

    /// <summary>Routing tool (iproute2).</summary>
    public const string IpBinary = "ip";

    /// <summary>
    /// Conventional absolute locations. A privileged helper started by systemd or pkexec frequently
    /// runs with a minimal <c>PATH</c>, so the absolute path is preferred when it exists.
    /// </summary>
    private const string AbsoluteNftBinary = "/usr/sbin/nft";

    private const string AbsoluteIpBinary = "/usr/sbin/ip";

    /// <summary>
    /// Marker that must be present in the ruleset the kernel reports back: it proves the rules were
    /// loaded (and the cgroup match resolved) rather than merely accepted by a tool that wrote
    /// somewhere else.
    /// </summary>
    private const string OwnershipMarker = "socket cgroupv2";

    private readonly ICommandRunner _runner;
    private readonly Func<bool> _isElevated;
    private readonly CgroupV2Manager _cgroups;
    private readonly Func<int, int?> _parentReader;
    private readonly Func<CancellationToken, Task<IReadOnlyList<ProcessDescriptor>>> _enumerate;
    private readonly string _tunnelInterface;
    private readonly IReadOnlyList<string> _vpnServerEndpoints;

    /// <param name="runner">Command runner; the shared one is injected by the platform services.</param>
    /// <param name="isElevated">
    /// Privilege check. Replaced in tests; the default reads <c>geteuid()</c>, which is the honest
    /// answer on Linux (a capability-based check would let a helper with only <c>CAP_NET_ADMIN</c>
    /// through, but MyVpn's helper is a system service running as root).
    /// </param>
    /// <param name="cgroups">cgroup v2 manager; injectable so the file-system side is testable.</param>
    /// <param name="tunnelInterface">
    /// Interface the core's TUN inbound creates. Must match the core configuration; the research
    /// requires it to be set explicitly rather than left to a random <c>utunN</c> name.
    /// </param>
    /// <param name="vpnServerEndpoints">
    /// Resolved server addresses, used to keep the tunnel's own uplink on the physical route. Empty is
    /// allowed — the other two loop-prevention guards remain — but supplying them is what makes the
    /// protection independent of slice membership.
    /// </param>
    /// <param name="parentReader">
    /// Reads a process's parent PID; defaults to <c>/proc/&lt;pid&gt;/stat</c>. Injected in tests to
    /// exercise child-process tracking without depending on the host's process tree.
    /// </param>
    /// <param name="processEnumerator">
    /// Process source. Defaults to the enumeration inherited from <see cref="ProcessRouterBase"/>,
    /// which is the same list the picker UI shows; injectable so the membership pass can be tested
    /// against a synthetic process tree.
    /// </param>
    public CgroupV2ProcessRouter(
        ICommandRunner? runner = null,
        Func<bool>? isElevated = null,
        CgroupV2Manager? cgroups = null,
        string tunnelInterface = NftablesProcessRoutingRenderer.DefaultTunnelInterface,
        IReadOnlyList<string>? vpnServerEndpoints = null,
        Func<int, int?>? parentReader = null,
        Func<CancellationToken, Task<IReadOnlyList<ProcessDescriptor>>>? processEnumerator = null)
        : base(ProcessRoutingCapability.FullRedirect)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tunnelInterface);

        _runner = runner ?? new ProcessCommandRunner();
        _isElevated = isElevated ?? DefaultElevationCheck;
        _cgroups = cgroups ?? new CgroupV2Manager();
        _tunnelInterface = tunnelInterface;
        _vpnServerEndpoints = vpnServerEndpoints ?? Array.Empty<string>();
        _parentReader = parentReader ?? ReadParentProcessId;
        _enumerate = processEnumerator ?? EnumerateAsync;
    }

    /// <summary>The mechanism this executor drives, for diagnostics and the UI.</summary>
    public string MechanismName => "cgroup2+nftables+policy-routing";

    /// <summary>True when the tools are present <i>and</i> this process may use them.</summary>
    public bool IsSupported => _runner.Exists(NftBinary) && _runner.Exists(IpBinary) && _isElevated();

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// <b>Why the interface is re-implemented.</b> <see cref="ProcessRouterBase"/> implements
    /// <see cref="IProcessRouter"/> with non-virtual members, so this method hides the base class's
    /// "not implemented in this build" refusal rather than overriding it — and a base class's
    /// interface map is not replaced merely by hiding a member. The class therefore lists
    /// <see cref="IProcessRouter"/> again and implements its members explicitly, which is what makes
    /// an interface call reach <i>this</i> code. <c>LinuxPlatformServices</c> exposes the router as
    /// <see cref="IProcessRouter"/>, and a test asserts that dispatch path.
    /// </para>
    /// <para>
    /// The sequence is ordered so that everything that can refuse cheaply happens before anything is
    /// changed, and so that a failure after the first change is rolled back rather than left half
    /// applied:
    /// <list type="number">
    /// <item><description>validate the plan (refuses an unenforceable one before running anything);</description></item>
    /// <item><description>tools and privileges;</description></item>
    /// <item><description>cgroup v2 mounted, and the physical uplink known if anything bypasses the tunnel;</description></item>
    /// <item><description>create the slices without ever re-creating an existing one;</description></item>
    /// <item><description>render, then <c>nft --check</c> the real ruleset against the real slice — this is the kernel capability probe;</description></item>
    /// <item><description>load the ruleset and read it back to confirm the kernel holds it;</description></item>
    /// <item><description>install the routes and policy rules;</description></item>
    /// <item><description>move the selected processes into their slice.</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public new async Task<Result> ApplyAsync(ProcessRoutingPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (plan.Mode == ProcessRoutingMode.Off)
        {
            // "Off" is a request to remove enforcement, not a no-op.
            return await RemoveAsync(plan, cancellationToken).ConfigureAwait(false);
        }

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return validation;
        }

        if (!_runner.Exists(NftBinary))
        {
            return Result.Fail(ToolMissing(NftBinary, "killswitch.install_nftables"));
        }

        if (!_runner.Exists(IpBinary))
        {
            return Result.Fail(ToolMissing(IpBinary, "route.install_iproute2"));
        }

        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        var needsTunnel = plan.Selectors.Any(selector => selector.ThroughTunnel);
        var needsBypass = plan.Selectors.Any(selector => !selector.ThroughTunnel);

        // (1) cgroup v2 must be mounted; otherwise every rule below would be unenforceable.
        var mount = _cgroups.Detect();
        if (mount.IsFailure)
        {
            return Result.Fail(mount.Error!);
        }

        var normalized = CgroupV2Manager.NormalizeRelativePath(plan.CgroupPath);
        if (normalized.IsFailure)
        {
            return Result.Fail(normalized.Error!);
        }

        // (2) A bypass needs the physical uplink's own default route. Probing is read-only, so a
        //     failure here leaves the machine exactly as it was.
        PhysicalUplinkRoute? uplink = null;
        if (needsBypass)
        {
            var probed = await ProbePhysicalUplinkAsync(cancellationToken).ConfigureAwait(false);
            if (probed.IsFailure)
            {
                return Result.Fail(probed.Error!);
            }

            uplink = probed.Value;
        }

        // (3) The slices must exist before a ruleset referencing them can load at all: the match
        //     resolves the path to an ID at load time and fails outright if the cgroup is missing.
        //     Only slices this call actually created are remembered for cleanup, so an early failure
        //     can never destroy a slice that an already-installed ruleset is matching against.
        var createdSlices = new List<string>();

        if (needsTunnel)
        {
            var slice = _cgroups.EnsureSlice(normalized.Value);
            if (slice.IsFailure)
            {
                return Result.Fail(slice.Error!);
            }

            if (slice.Value.Created)
            {
                createdSlices.Add(slice.Value.Name);
            }
        }

        if (needsBypass)
        {
            var slice = _cgroups.EnsureSlice(CgroupV2Manager.BypassSliceName);
            if (slice.IsFailure)
            {
                RemoveSlices(createdSlices);
                return Result.Fail(slice.Error!);
            }

            if (slice.Value.Created)
            {
                createdSlices.Add(slice.Value.Name);
            }
        }

        var context = new ProcessRoutingRenderContext
        {
            TunnelInterface = _tunnelInterface,
            TunnelSlice = normalized.Value,
            BypassSlice = CgroupV2Manager.BypassSliceName,
            VpnServerEndpoints = _vpnServerEndpoints,
            PhysicalUplink = uplink,
        };

        ProcessRoutingRuleset ruleset;

        try
        {
            ruleset = NftablesProcessRoutingRenderer.Render(plan, context);
        }
        catch (ArgumentException ex)
        {
            RemoveSlices(createdSlices);
            return Result.Fail(RenderRefused(ex.Message));
        }

        // (4) Probe before anything is emitted: `nft --check` evaluates the ruleset against the
        //     kernel without committing it, so a kernel that cannot resolve `socket cgroupv2` is
        //     detected while the only state in existence is the slice directory itself.
        var probe = await ProbeRulesetAsync(ruleset.NftablesText, cancellationToken).ConfigureAwait(false);
        if (probe.IsFailure)
        {
            RemoveSlices(createdSlices);
            return probe;
        }

        // (5) Load it, then read back what the kernel actually holds.
        var applied = await ApplyNftablesAsync(ruleset.NftablesText, cancellationToken).ConfigureAwait(false);
        if (applied.IsFailure)
        {
            await RollbackAsync(plan, cancellationToken).ConfigureAwait(false);
            return applied;
        }

        // (6) Routes, then the policy rules that use them, then the fail-closed rule.
        var routed = await RunIpCommandsAsync(
            ruleset.InstallCommands,
            cancellationToken,
            tolerateAlreadyPresent: true,
            tolerateAlreadyGone: false).ConfigureAwait(false);

        if (routed.IsFailure)
        {
            await RollbackAsync(plan, cancellationToken).ConfigureAwait(false);
            return routed;
        }

        // (7) Membership last: the routing is now in place, so a selected process's next socket is
        //     matched and steered the moment it is moved in.
        var membership = await MoveSelectedProcessesAsync(
            plan, normalized.Value, needsTunnel, needsBypass, cancellationToken).ConfigureAwait(false);

        if (membership.IsFailure)
        {
            await RollbackAsync(plan, cancellationToken).ConfigureAwait(false);
            return membership;
        }

        return Result.Ok();
    }

    /// <inheritdoc />
    /// <remarks>
    /// Idempotent, and deliberately generous: the plan may have been edited since it was applied, so
    /// every removal command runs unconditionally and each one tolerates "nothing there". Removing
    /// what was never applied succeeds, which is what makes crash recovery safe to run blind.
    /// </remarks>
    public new async Task<Result> RemoveAsync(ProcessRoutingPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        // Teardown deliberately does not validate the plan: an incomplete plan still describes state
        // that may exist in the kernel, and refusing to clean up is how a machine stays half-routed.
        if (!_runner.Exists(NftBinary) && !_runner.Exists(IpBinary))
        {
            // Nothing can have been installed by a process that never had the tools.
            return Result.Ok();
        }

        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        var failures = new List<string>();
        var normalized = CgroupV2Manager.NormalizeRelativePath(plan.CgroupPath);
        var tunnelSlice = normalized.IsSuccess ? normalized.Value : CgroupV2Manager.DefaultSliceName;

        var context = new ProcessRoutingRenderContext
        {
            TunnelInterface = _tunnelInterface,
            TunnelSlice = tunnelSlice,
            BypassSlice = CgroupV2Manager.BypassSliceName,
            VpnServerEndpoints = _vpnServerEndpoints,
        };

        // Rendering in Off mode returns the teardown command list without needing an uplink or any
        // selectors, which is precisely the situation during crash recovery.
        var teardown = NftablesProcessRoutingRenderer.Render(
            plan with { Mode = ProcessRoutingMode.Off }, context);

        // (1) The ruleset first: once the marking chain is gone, no new packet can be marked, and the
        //     rules and routes below are only cleanup.
        if (_runner.Exists(NftBinary))
        {
            var removed = await RemoveNftablesAsync(
                NftablesProcessRoutingRenderer.RenderTeardown(), cancellationToken).ConfigureAwait(false);

            if (removed.IsFailure)
            {
                failures.Add(Describe(removed.Error!));
            }
        }

        // (2) Policy rules before the table's routes, mirroring installation in reverse.
        if (_runner.Exists(IpBinary))
        {
            var removed = await RunIpCommandsAsync(
                teardown.RemoveCommands,
                cancellationToken,
                tolerateAlreadyPresent: false,
                tolerateAlreadyGone: true).ConfigureAwait(false);

            if (removed.IsFailure)
            {
                failures.Add(Describe(removed.Error!));
            }
        }

        // (3) Membership, then the slices themselves.
        if (_cgroups.Detect().IsSuccess)
        {
            foreach (var slice in SliceNames(tunnelSlice))
            {
                var removed = _cgroups.RemoveSlice(slice);
                if (removed.IsFailure)
                {
                    failures.Add(Describe(removed.Error!));
                }
            }
        }

        return failures.Count == 0
            ? Result.Ok()
            : Result.Fail(RemoveFailed(failures));
    }

    // ------------------------------------------------------------------ internals

    /// <summary>
    /// Re-implements the interface so that an <see cref="IProcessRouter"/> call reaches this class
    /// rather than the base class's refusal. See the remarks on <see cref="ApplyAsync"/>.
    /// </summary>
    async Task<Result> IProcessRouter.ApplyAsync(ProcessRoutingPlan plan, CancellationToken cancellationToken) =>
        await ApplyAsync(plan, cancellationToken).ConfigureAwait(false);

    /// <summary>Re-implements the interface; see <see cref="ApplyAsync"/>.</summary>
    async Task<Result> IProcessRouter.RemoveAsync(ProcessRoutingPlan plan, CancellationToken cancellationToken) =>
        await RemoveAsync(plan, cancellationToken).ConfigureAwait(false);

    private string NftTool => _runner.Exists(AbsoluteNftBinary) ? AbsoluteNftBinary : NftBinary;

    private string IpTool => _runner.Exists(AbsoluteIpBinary) ? AbsoluteIpBinary : IpBinary;

    /// <summary>
    /// Evaluates the ruleset against the kernel without committing it.
    /// </summary>
    /// <remarks>
    /// This is the platform capability probe. It is deliberately run against the <i>real</i> rendered
    /// ruleset and the <i>real</i> slice rather than a synthetic snippet, because the kernel resolves
    /// the cgroup path at load time: a probe with any other path would prove nothing. The failures it
    /// distinguishes are "this kernel cannot match sockets by cgroup" (a missing capability the user
    /// must be told about) and "this ruleset is wrong" (a bug).
    /// </remarks>
    private async Task<Result> ProbeRulesetAsync(string ruleset, CancellationToken cancellationToken)
    {
        string path;

        try
        {
            path = WritePrivateRuleset(ruleset);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result.Fail(RulesetRejected(ex.Message));
        }

        try
        {
            var check = await _runner
                .RunAsync(NftTool, new[] { "--check", "--file", path }, cancellationToken)
                .ConfigureAwait(false);

            if (check.Succeeded)
            {
                return Result.Ok();
            }

            return Result.Fail(LooksLikeMissingCgroupMatchSupport(check.Combined)
                ? CgroupMatchUnsupported(check.Combined)
                : RulesetRejected(check.Combined));
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    /// <summary>
    /// Loads the ruleset and reads it back from the kernel.
    /// </summary>
    /// <remarks>
    /// The read-back is the point: an <c>nft</c> exit code is not evidence that the kernel holds what
    /// was asked for. Only the listing proves that the cgroup match resolved to a real cgroup ID,
    /// which is the one failure mode that is otherwise completely silent.
    /// </remarks>
    private async Task<Result> ApplyNftablesAsync(string ruleset, CancellationToken cancellationToken)
    {
        string path;

        try
        {
            path = WritePrivateRuleset(ruleset);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result.Fail(RulesetRejected(ex.Message));
        }

        try
        {
            var applied = await _runner
                .RunAsync(NftTool, new[] { "--file", path }, cancellationToken)
                .ConfigureAwait(false);

            if (!applied.Succeeded)
            {
                return Result.Fail(RulesetRejected(applied.Combined));
            }

            var listed = await _runner
                .RunAsync(
                    NftTool,
                    new[] { "list", "table", "inet", NftablesProcessRoutingRenderer.TableName },
                    cancellationToken)
                .ConfigureAwait(false);

            if (!listed.Succeeded
                || !listed.StandardOutput.Contains(OwnershipMarker, StringComparison.Ordinal))
            {
                return Result.Fail(VerifyFailed(listed.Combined));
            }

            return Result.Ok();
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    private async Task<Result> RemoveNftablesAsync(string teardown, CancellationToken cancellationToken)
    {
        string path;

        try
        {
            path = WritePrivateRuleset(teardown);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result.Fail(TeardownWriteFailed(ex.Message));
        }

        try
        {
            var removed = await _runner
                .RunAsync(NftTool, new[] { "--file", path }, cancellationToken)
                .ConfigureAwait(false);

            return removed.Succeeded
                ? Result.Ok()
                : Result.Fail(TeardownFailed(removed.Combined));
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    /// <summary>
    /// Runs the <c>ip</c> argv vectors in order, tolerating exactly the answers that mean "already in
    /// the desired state".
    /// </summary>
    private async Task<Result> RunIpCommandsAsync(
        IReadOnlyList<IpArgv> commands,
        CancellationToken cancellationToken,
        bool tolerateAlreadyPresent,
        bool tolerateAlreadyGone)
    {
        foreach (var command in commands)
        {
            var result = await _runner
                .RunAsync(IpTool, command.Arguments, cancellationToken)
                .ConfigureAwait(false);

            if (result.Succeeded)
            {
                continue;
            }

            if (tolerateAlreadyPresent && IsAlreadyPresent(result))
            {
                continue;
            }

            if (tolerateAlreadyGone && IsAlreadyGone(result))
            {
                continue;
            }

            return Result.Fail(RouteFailed(command, result));
        }

        return Result.Ok();
    }

    /// <summary>
    /// Reads the physical default route, skipping anything already on a MyVpn interface.
    /// </summary>
    /// <remarks>
    /// IPv4 is tried first because that is what the tunnel and its server address normally are; IPv6
    /// is the fallback for a v6-only uplink. A route on <c>myvpn*</c> is never an acceptable answer:
    /// using the tunnel as the "physical" uplink would build a bypass rule that points into the
    /// tunnel.
    /// </remarks>
    private async Task<Result<PhysicalUplinkRoute>> ProbePhysicalUplinkAsync(CancellationToken cancellationToken)
    {
        var detail = new List<string>();

        foreach (var family in new[] { "-4", "-6" })
        {
            var result = await _runner
                .RunAsync(IpTool, new[] { family, "route", "show", "default" }, cancellationToken)
                .ConfigureAwait(false);

            if (!result.Succeeded)
            {
                detail.Add($"'ip {family} route show default' exited {result.ExitCode}: {Trim(result.Combined)}");
                continue;
            }

            var parsed = ParsePhysicalDefault(result.StandardOutput);
            if (parsed is not null)
            {
                return Result<PhysicalUplinkRoute>.Ok(parsed);
            }

            detail.Add($"'ip {family} route show default' listed no route on a non-tunnel device");
        }

        return Result<PhysicalUplinkRoute>.Fail(BypassNeedsUplink(string.Join(" | ", detail)));
    }

    private static PhysicalUplinkRoute? ParsePhysicalDefault(string output)
    {
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var tokens = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            string? device = null;
            string? gateway = null;

            for (var i = 0; i + 1 < tokens.Length; i++)
            {
                if (tokens[i] == "dev")
                {
                    device = tokens[i + 1];
                }
                else if (tokens[i] == "via")
                {
                    gateway = tokens[i + 1];
                }
            }

            if (device is null || device.StartsWith("myvpn", StringComparison.Ordinal))
            {
                continue;
            }

            return new PhysicalUplinkRoute(device, gateway);
        }

        return null;
    }

    /// <summary>
    /// Enumerates processes, matches them against the plan's selectors and moves them into their
    /// slices.
    /// </summary>
    private async Task<Result> MoveSelectedProcessesAsync(
        ProcessRoutingPlan plan,
        string tunnelSlice,
        bool needsTunnel,
        bool needsBypass,
        CancellationToken cancellationToken)
    {
        var processes = await _enumerate(cancellationToken).ConfigureAwait(false);

        if (needsTunnel)
        {
            var ids = SelectProcessIds(
                processes, plan.Selectors.Where(selector => selector.ThroughTunnel).ToArray(), plan.TrackChildren);

            if (ids.Count > 0)
            {
                var moved = _cgroups.MoveProcesses(tunnelSlice, ids);
                if (moved.IsFailure)
                {
                    return Result.Fail(moved.Error!);
                }
            }
        }

        if (needsBypass)
        {
            var ids = SelectProcessIds(
                processes, plan.Selectors.Where(selector => !selector.ThroughTunnel).ToArray(), plan.TrackChildren);

            if (ids.Count > 0)
            {
                var moved = _cgroups.MoveProcesses(CgroupV2Manager.BypassSliceName, ids);
                if (moved.IsFailure)
                {
                    return Result.Fail(moved.Error!);
                }
            }
        }

        return Result.Ok();
    }

    /// <summary>
    /// Resolves selectors to PIDs, including already-running descendants when child tracking is on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why children work here and not on Windows.</b> Membership of a cgroup is inherited by every
    /// child a member forks, and the nftables match covers the whole subtree, so a process that
    /// spawns a worker (a browser starting a renderer, a shell running a tool) cannot escape the
    /// routing decision. Windows has no equivalent: WFP classifies the connecting process by its own
    /// image identity, so each child would have to be matched and blocked individually — which is why
    /// <c>BypassVpn</c>/<c>VpnOnly</c> can honour <see cref="ResolvedProcessSelector.IncludeChildren"/>
    /// faithfully on Linux.
    /// </para>
    /// <para>
    /// Processes that already exist when the plan is applied are not covered by inheritance — they
    /// were forked before their parent moved — so descendants are walked through
    /// <c>/proc/&lt;pid&gt;/stat</c> and moved in explicitly. Children born afterwards need no help.
    /// </para>
    /// </remarks>
    private IReadOnlyList<int> SelectProcessIds(
        IReadOnlyList<ProcessDescriptor> processes,
        IReadOnlyList<ResolvedProcessSelector> selectors,
        bool trackChildren)
    {
        var selected = new HashSet<int>();
        var childRoots = new HashSet<int>();

        foreach (var selector in selectors)
        {
            foreach (var process in processes)
            {
                if (!Matches(selector, process))
                {
                    continue;
                }

                selected.Add(process.ProcessId);

                if (trackChildren && selector.IncludeChildren)
                {
                    childRoots.Add(process.ProcessId);
                }
            }
        }

        if (childRoots.Count > 0)
        {
            var children = BuildChildMap(processes);
            var queue = new Queue<int>(childRoots);

            while (queue.Count > 0)
            {
                if (!children.TryGetValue(queue.Dequeue(), out var descendants))
                {
                    continue;
                }

                foreach (var child in descendants)
                {
                    if (selected.Add(child))
                    {
                        queue.Enqueue(child);
                    }
                }
            }
        }

        // Never move the process that is doing the routing into the slice it is configuring: the
        // helper's own traffic (the core's supervision channel, diagnostics) must keep using the
        // physical path, and PID 1 owns the whole machine.
        selected.Remove(Environment.ProcessId);
        selected.RemoveWhere(pid => pid <= 1);

        return selected.OrderBy(pid => pid).ToArray();
    }

    private Dictionary<int, List<int>> BuildChildMap(IReadOnlyList<ProcessDescriptor> processes)
    {
        var children = new Dictionary<int, List<int>>();

        foreach (var process in processes)
        {
            var parent = process.ParentProcessId ?? _parentReader(process.ProcessId);

            if (parent is null || parent <= 1)
            {
                continue;
            }

            if (!children.TryGetValue(parent.Value, out var siblings))
            {
                siblings = new List<int>();
                children[parent.Value] = siblings;
            }

            siblings.Add(process.ProcessId);
        }

        return children;
    }

    private static bool Matches(ResolvedProcessSelector selector, ProcessDescriptor process)
    {
        switch (selector.Kind)
        {
            case ProcessSelectorKind.ExecutableName:
                return !string.IsNullOrWhiteSpace(selector.ExecutableName)
                       && string.Equals(
                           process.ExecutableName, selector.ExecutableName, StringComparison.OrdinalIgnoreCase);

            case ProcessSelectorKind.ExecutablePath:
            {
                var target = NormalizeExecutablePath(selector.AbsolutePath);
                var candidate = NormalizeExecutablePath(process.ExecutablePath);

                return target is not null
                       && candidate is not null
                       && string.Equals(candidate, target, StringComparison.Ordinal);
            }

            case ProcessSelectorKind.Directory:
            {
                var directory = NormalizeExecutablePath(selector.AbsolutePath);
                var candidate = NormalizeExecutablePath(process.ExecutablePath);

                if (directory is null || candidate is null)
                {
                    return false;
                }

                // A directory selector must match a path *inside* the directory: comparing prefixes
                // without the separator would make "/opt/app" match "/opt/application".
                var prefix = directory.EndsWith('/') ? directory : directory + "/";
                return candidate.StartsWith(prefix, StringComparison.Ordinal);
            }

            default:
                return false;
        }
    }

    /// <summary>
    /// Normalizes an executable path for comparison, and strips the kernel's <c>" (deleted)"</c>
    /// suffix, which appears when a process keeps running after its binary was replaced on disk —
    /// routine after a package upgrade, and otherwise enough to make the selector silently stop
    /// matching.
    /// </summary>
    private static string? NormalizeExecutablePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        const string DeletedSuffix = " (deleted)";
        var value = path.EndsWith(DeletedSuffix, StringComparison.Ordinal)
            ? path[..^DeletedSuffix.Length]
            : path;

        try
        {
            return Path.GetFullPath(value).TrimEnd('/');
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    /// <summary>Reads the parent PID from <c>/proc/&lt;pid&gt;/stat</c>.</summary>
    /// <remarks>
    /// The second field is the executable name in parentheses and may itself contain spaces and
    /// parentheses, so the fields are counted from the <i>last</i> closing parenthesis: state is
    /// first, the parent PID second.
    /// </remarks>
    private static int? ReadParentProcessId(int pid)
    {
        try
        {
            var stat = File.ReadAllText(
                string.Create(CultureInfo.InvariantCulture, $"/proc/{pid}/stat"));

            var close = stat.LastIndexOf(')');
            if (close < 0)
            {
                return null;
            }

            var fields = stat[(close + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);

            return fields.Length >= 2
                   && int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var parent)
                ? parent
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Best-effort rollback after a partial apply.
    /// </summary>
    /// <remarks>
    /// A half-applied policy is worse than none: a mark rule without its table's route leaks, and a
    /// route without its rule is dead state that confuses the next attempt. The removal path is
    /// idempotent, so running it here cannot make things worse, and its own failure is deliberately
    /// swallowed — the caller is already returning the original error, which is the actionable one.
    /// </remarks>
    private async Task RollbackAsync(ProcessRoutingPlan plan, CancellationToken cancellationToken)
    {
        try
        {
            await RemoveAsync(plan, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Cancellation must not mask the original failure.
        }
    }

    private void RemoveSlices(IEnumerable<string> slices)
    {
        var names = slices.Distinct(StringComparer.Ordinal).ToArray();

        if (names.Length == 0 || _cgroups.Detect().IsFailure)
        {
            return;
        }

        foreach (var slice in names)
        {
            _ = _cgroups.RemoveSlice(slice);
        }
    }

    private static IEnumerable<string> SliceNames(string tunnelSlice)
    {
        yield return tunnelSlice;
        yield return CgroupV2Manager.BypassSliceName;
    }

    private static string WritePrivateRuleset(string ruleset)
    {
        var path = Path.Combine(Path.GetTempPath(), $"myvpn-route-{Guid.NewGuid():N}.nft");

        File.WriteAllText(path, ruleset);

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return path;
    }

    private static void DeleteQuietly(string path)
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
            // A leftover 0600 file in the temporary directory is harmless.
        }
    }

    /// <summary>
    /// True when an <c>nft --check</c> failure looks like "this kernel cannot match socket cgroupv2"
    /// rather than "this ruleset has a typo". The distinction matters because the first is a missing
    /// platform capability that the user must be told about, and the second is a bug.
    /// </summary>
    private static bool LooksLikeMissingCgroupMatchSupport(string output) =>
        output.Contains("cgroupv2", StringComparison.OrdinalIgnoreCase)
        || output.Contains("not supported", StringComparison.OrdinalIgnoreCase)
        || output.Contains("Operation not supported", StringComparison.OrdinalIgnoreCase);

    /// <summary>The kernel's spelling of "this rule or route is already in the desired state".</summary>
    private static bool IsAlreadyPresent(CommandResult result) =>
        result.Combined.Contains("File exists", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The kernel's spelling of "there is nothing here to remove". <c>ip rule del</c> and
    /// <c>ip route flush</c> on a missing table both exit non-zero, and both mean the desired end
    /// state already holds.
    /// </summary>
    private static bool IsAlreadyGone(CommandResult result) =>
        result.Combined.Contains("No such file or directory", StringComparison.OrdinalIgnoreCase)
        || result.Combined.Contains("No such process", StringComparison.OrdinalIgnoreCase)
        || result.Combined.Contains("FIB table does not exist", StringComparison.OrdinalIgnoreCase)
        || result.Combined.Contains("Cannot find device", StringComparison.OrdinalIgnoreCase)
        || result.Combined.Contains("No such device", StringComparison.OrdinalIgnoreCase);

    private static string Describe(MyVpnError error) => Trim(error.TechnicalDetail ?? error.MessageKey);

    private static string Trim(string? value) =>
        value switch
        {
            null => string.Empty,
            { Length: <= 300 } => value,
            _ => value[..300] + "…",
        };

    private static MyVpnError NotElevated() =>
        new MyVpnError(
            ErrorCodes.PrivilegeDenied,
            "error.process.needs_privileges",
            ErrorSeverity.Error,
            "Per-process routing creates a cgroup, loads firewall rules and changes the routing table, "
            + "all of which require root. The UI must never run as root; this step belongs to the "
            + "privileged helper.",
            "privilege.install_helper");

    private static MyVpnError ToolMissing(string tool, string remediationKey) =>
        new MyVpnError(
            ErrorCodes.PlatformToolMissing,
            "error.process.tool_missing",
            ErrorSeverity.Error,
            $"The '{tool}' tool is not installed, so per-process routing cannot be applied.",
            remediationKey)
        .WithArg("tool", tool);

    /// <summary>
    /// The capability refusal: the kernel cannot evaluate the match, so the rules would load nowhere
    /// and every selected process would silently keep using the physical route.
    /// </summary>
    private static MyVpnError CgroupMatchUnsupported(string output) =>
        new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.cgroupv2_match_unsupported",
            ErrorSeverity.Error,
            "This kernel cannot match sockets by cgroup v2, so per-process routing is not enforceable "
            + "here. 'socket cgroupv2' needs Linux 5.13 or newer and nftables 0.99 or newer, plus a "
            + "mounted cgroup v2 hierarchy. Kernel said: " + Trim(output),
            "platform.upgrade_kernel");

    private static MyVpnError RulesetRejected(string output) =>
        new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.ruleset_rejected",
            ErrorSeverity.Error,
            "nftables rejected the per-process routing ruleset: " + Trim(output),
            "process.reapply");

    /// <summary>
    /// The ruleset loaded but could not be read back. Reporting success here would tell the user their
    /// selected applications are tunnelled when nothing is in force.
    /// </summary>
    private static MyVpnError VerifyFailed(string output) =>
        new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.verify_failed",
            ErrorSeverity.Critical,
            "The per-process routing ruleset was loaded but the kernel did not report it back, so "
            + "enforcement cannot be confirmed: " + Trim(output),
            "process.reapply");

    private static MyVpnError RouteFailed(IpArgv command, CommandResult result) =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.process.route_failed",
            ErrorSeverity.Error,
            $"'ip {command}' failed with exit code {result.ExitCode}: {Trim(result.Combined)}",
            "network.restore")
        .WithArg("command", command.ToString());

    private static MyVpnError BypassNeedsUplink(string detail) =>
        new MyVpnError(
            ErrorCodes.RouteAddFailed,
            "error.process.bypass_needs_uplink",
            ErrorSeverity.Error,
            "A selected application is meant to bypass the tunnel, but the physical uplink's default "
            + "route could not be identified, so there is no route to send it through. " + detail,
            "network.restore");

    private static MyVpnError RenderRefused(string detail) =>
        new MyVpnError(
            ErrorCodes.ProcessRoutingUnsupported,
            "error.process.render_refused",
            ErrorSeverity.Error,
            "The per-process routing plan cannot be rendered as enforceable rules: " + detail,
            "process.reconfigure");

    private static MyVpnError RemoveFailed(IReadOnlyList<string> failures) =>
        new MyVpnError(
            ErrorCodes.RouteRemoveFailed,
            "error.process.remove_failed",
            ErrorSeverity.Critical,
            "Some MyVpn per-process routing state could not be removed: "
            + Trim(string.Join(" | ", failures)),
            "network.restore");

    private static MyVpnError TeardownFailed(string output) =>
        new MyVpnError(
            ErrorCodes.RouteRemoveFailed,
            "error.process.remove_failed",
            ErrorSeverity.Critical,
            "nftables could not remove the per-process routing table: " + Trim(output),
            "network.restore");

    private static MyVpnError TeardownWriteFailed(string detail) =>
        new MyVpnError(
            ErrorCodes.RouteRemoveFailed,
            "error.process.remove_failed",
            ErrorSeverity.Critical,
            "The per-process routing teardown ruleset could not be written to disk: " + Trim(detail),
            "network.restore");

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
}
