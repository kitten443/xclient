using System.Globalization;
using System.Runtime.InteropServices;
using MyVpn.Core.Domain;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Windows.Execution;

namespace MyVpn.Platform.Windows.KillSwitch;

/// <summary>
/// Applies the Kill Switch through the Windows Filtering Platform (<c>fwpuclnt.dll</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why WFP and not the Windows Firewall COM API.</b> Explicit block rules beat allow rules
/// with no weighted ordering, so "block everything except the tunnel" is expressible through
/// <c>INetFwPolicy2</c> only by mutating the machine-wide <c>DefaultOutboundAction</c> — a
/// visible, GPO-overridable change to the host's firewall posture. <c>INetFwRule</c> has no
/// interface-LUID condition and commits rule by rule instead of transactionally, and
/// <c>Windows.Networking.Vpn</c> needs the <c>networkingVpnProvider</c> restricted capability
/// in a packaged app. There is no managed <c>Microsoft.Windows.WFP</c> namespace, so P/Invoke
/// is the only supported route.
/// </para>
/// <para>
/// <b>What this class does not do.</b> The policy itself is built by
/// <see cref="WfpKillSwitchPlanTranslator"/>, which is pure and unit-tested. This class only
/// resolves names (executable path → app-id blob, interface name → LUID, own token → security
/// descriptor) and calls the engine inside one transaction. Keeping the split means the part
/// where a mistake means either a leak or a locked-out machine is verified on any host.
/// </para>
/// <para>
/// <b>Session lifetime is the fail-open/fail-closed switch.</b> A
/// <see cref="WkNative.SessionFlagDynamic"/> session's objects are destroyed when the engine
/// handle closes, which is the ordinary mode: if the service dies, the tunnel is gone too and
/// the rules go with it. An always-on plan uses a non-dynamic session with persistent objects
/// instead, which is why <see cref="IDisposable"/> only has to matter for the first case.
/// </para>
/// <para>
/// <b>Runtime status.</b> Everything below that calls into <c>fwpuclnt.dll</c> is guarded by
/// <see cref="WindowsPlatform.IsWindows"/> and can only execute on Windows; on any other host
/// each entry point returns an unsupported result having made no call at all. The struct
/// layouts and constants were transcribed from the Windows SDK headers
/// (<c>fwpmu.h</c>, <c>fwpmtypes.h</c>, <c>fwptypes.h</c>) and their marshalling offsets were
/// checked field by field against a compiled C equivalent of those declarations; the calls
/// themselves are unverified until they run on Windows against a live BFE.
/// </para>
/// </remarks>
public sealed class WindowsWfpKillSwitch : IKillSwitch, IDisposable
{
    /// <summary>
    /// Fixed provider key. Compile-time constant on purpose: teardown, diagnostics and a
    /// crashed session's leftovers are all identified by this key, so it must never be
    /// regenerated at runtime. Derived once from the name <c>myvpn.wfp.provider</c>.
    /// </summary>
    public static readonly Guid ProviderKey = new("bd5cfa56-f6ea-59a4-918a-5b7c09953994");

    /// <summary>Fixed sub-layer key, derived once from <c>myvpn.wfp.sublayer.killswitch</c>.</summary>
    public static readonly Guid SubLayerKey = new("8865d3b7-c6b5-521f-9dfa-d2d01337f899");

    /// <summary>
    /// Maximum sub-layer weight. MyVpn's arbitration is then evaluated first, ahead of
    /// anything else installed on the machine. It does <i>not</i> let a permit override
    /// somebody else's hard block: a corporate firewall block still wins, by design.
    /// </summary>
    public const ushort SubLayerWeight = 0xFFFF;

    /// <summary>Provider display name; also the name shown in <c>netsh wfp show filters</c>.</summary>
    public const string ProviderName = "MyVpn";

    /// <summary>
    /// Service that must own the persistent objects and be auto-start, or BFE adds them
    /// <i>disabled</i> at boot — a fail-open that looks like success.
    /// </summary>
    public const string PersistentServiceName = "MyVpnSvc";

    private readonly Func<bool> _isElevated;
    private readonly object _gate = new();

    /// <summary>Open dynamic engine session, or <see cref="IntPtr.Zero"/> when disarmed.</summary>
    private IntPtr _engineHandle = IntPtr.Zero;

    public WindowsWfpKillSwitch(Func<bool>? isElevated = null) =>
        _isElevated = isElevated ?? WindowsPlatform.IsProcessElevated;

    public string MechanismName => "Windows Filtering Platform";

    /// <summary>
    /// True when this host is Windows <i>and</i> the process may talk to the filter engine.
    /// </summary>
    /// <remarks>
    /// Deliberately cheap and deliberately honest: one OS check and one token query. The
    /// authoritative test — whether BFE is running and <c>FwpmEngineOpen0</c> succeeds — needs
    /// a call into the engine, and a property getter must not perform one. An unelevated
    /// process reports <c>false</c> rather than discovering the problem after the tunnel is
    /// already up.
    /// </remarks>
    public bool IsSupported => WindowsPlatform.IsWindows && _isElevated();

    /// <summary>
    /// Installs the translated filter set inside a single engine transaction.
    /// </summary>
    /// <remarks>
    /// Synchronous work surfacing as a <see cref="Task"/> because the interface is shared with
    /// platforms whose executors spawn processes. Every WFP call is a local, non-blocking
    /// syscall, so there is nothing to await and no thread is consumed.
    /// </remarks>
    public Task<KillSwitchApplyResult> ApplyAsync(KillSwitchPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(KillSwitchApplyResult.Failed(
                WindowsPlatform.Unsupported("The WFP Kill Switch")));
        }

        if (plan.Mode == KillSwitchMode.Disabled)
        {
            // "Disabled" means "no rules", so the correct action is teardown. RemoveAsync is
            // idempotent, which makes this safe to call on a machine with nothing installed.
            return RemoveAsync(plan.Identifier, cancellationToken);
        }

        if (!_isElevated())
        {
            return Task.FromResult(KillSwitchApplyResult.Failed(NotElevated()));
        }

        var translated = WfpKillSwitchPlanTranslator.Translate(plan);
        if (translated.IsFailure)
        {
            return Task.FromResult(KillSwitchApplyResult.Failed(translated.Error!));
        }

        var set = translated.Value;

        // The TUN permit is the predicate that keeps traffic already routed into the tunnel
        // working. Without the adapter's LUID there is no safe rule set: the catch-all block
        // would also cut the tunnel, which is the outage the plan validation exists to avoid.
        if (!WindowsAdapters.TryGetLuid(set.TunnelInterface, out var tunnelLuid))
        {
            return Task.FromResult(KillSwitchApplyResult.Failed(new MyVpnError(
                ErrorCodes.KillSwitchApplyFailed,
                "error.killswitch.no_tunnel_interface",
                ErrorSeverity.Error,
                $"The TUN adapter '{set.TunnelInterface}' could not be resolved to an interface LUID, "
                + "so the 'traffic through the tunnel' permit cannot be built and no filter was "
                + "installed.",
                "killswitch.reapply")
                .WithArg("interface", set.TunnelInterface)));
        }

        return Task.FromResult(Install(set, tunnelLuid));
    }

    /// <summary>
    /// Removes every WFP object MyVpn owns.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Ownership is decided by the provider key, not by the plan that installed the objects:
    /// after a crash the settings may have changed, and the plan that would be passed here is
    /// not necessarily the one that created them. The identifier is used for diagnostics only.
    /// </para>
    /// <para>
    /// Idempotent by construction: "not found" from any deletion is the desired end state.
    /// </para>
    /// </remarks>
    public Task<KillSwitchApplyResult> RemoveAsync(string identifier, CancellationToken cancellationToken)
    {
        if (!WindowsPlatform.IsWindows)
        {
            // A refusal, not a success: on a non-Windows host no WFP engine was consulted, and
            // reporting "cleaned" would be a claim about a machine state that was never read.
            return Task.FromResult(KillSwitchApplyResult.Failed(
                WindowsPlatform.Unsupported("Removing WFP filters")));
        }

        if (!_isElevated())
        {
            return Task.FromResult(KillSwitchApplyResult.Failed(NotElevated()));
        }

        lock (_gate)
        {
            // Own dynamic session first: an open dynamic session makes opening a second,
            // non-dynamic one fail with FWP_E_DYNAMIC_SESSION_IN_PROGRESS, and closing it also
            // removes the dynamic objects it holds.
            CloseSessionLocked();

            var opened = WkNative.EngineOpen(persistent: false, out var handle);
            if (opened != 0)
            {
                return Task.FromResult(KillSwitchApplyResult.Failed(
                    EngineUnavailable("FwpmEngineOpen0", opened)));
            }

            try
            {
                var removed = WkNative.TransactionBegin(handle, 0);
                if (removed != 0)
                {
                    return Task.FromResult(KillSwitchApplyResult.Failed(
                        Failure("FwpmTransactionBegin0", removed)));
                }

                var committed = false;
                try
                {
                    var deletedFilters = DeleteOwnedFilters(handle);

                    // Sublayer before provider: a persistent sublayer references the provider,
                    // and the engine refuses to delete an object another one still references.
                    var subLayer = WkNative.SubLayerDeleteByKey(handle, SubLayerKey);
                    var provider = WkNative.ProviderDeleteByKey(handle, ProviderKey);

                    var commit = WkNative.TransactionCommit(handle);
                    if (commit != 0)
                    {
                        return Task.FromResult(KillSwitchApplyResult.Failed(
                            Failure("FwpmTransactionCommit0", commit)));
                    }

                    committed = true;

                    return Task.FromResult(KillSwitchApplyResult.Ok(
                        $"Removed {deletedFilters.ToString(CultureInfo.InvariantCulture)} WFP filter(s) for "
                        + $"'{identifier}' (sublayer=0x{subLayer:X8}, provider=0x{provider:X8})."));
                }
                finally
                {
                    if (!committed)
                    {
                        // Abort is best effort: the transaction may already be gone.
                        WkNative.TransactionAbort(handle);
                    }
                }
            }
            finally
            {
                WkNative.EngineClose(handle);
            }
        }
    }

    /// <summary>
    /// Reads back what the engine actually holds, so "armed" is an observation rather than an
    /// assumption.
    /// </summary>
    /// <remarks>
    /// A missing engine, a missing sub-layer or an empty filter list all mean "not armed".
    /// Filters reported with <c>FWPM_FILTER_FLAG_DISABLED</c> are drift, not protection: that
    /// flag is what BFE sets on a persistent object whose provider names a service that is not
    /// installed and auto-start, and it is the documented way a persistent kill switch fails
    /// open while every install call returned success.
    /// </remarks>
    public Task<KillSwitchState> InspectAsync(KillSwitchPlan? expected, CancellationToken cancellationToken)
    {
        if (!WindowsPlatform.IsWindows || !_isElevated())
        {
            // Without the engine nothing can be observed. "Not armed" is the honest answer and
            // must not be read as "verified clean"; the caller has the error surface for that.
            return Task.FromResult(new KillSwitchState
            {
                IsArmed = false,
                IsDrifted = false,
                MechanismName = MechanismName,
            });
        }

        lock (_gate)
        {
            IntPtr handle;

            if (_engineHandle != IntPtr.Zero)
            {
                // Reuse the live session: on a dynamic session the objects exist only while it
                // is open, so observing them through a different session would see nothing.
                handle = _engineHandle;
            }
            else
            {
                var opened = WkNative.EngineOpen(persistent: false, out handle);
                if (opened != 0)
                {
                    return Task.FromResult(new KillSwitchState
                    {
                        IsArmed = false,
                        IsDrifted = false,
                        OrphanedRules = new[] { $"FwpmEngineOpen0 failed with 0x{opened:X8}" },
                        MechanismName = MechanismName,
                    });
                }
            }

            var ownsHandle = handle != _engineHandle;

            try
            {
                var orphaned = new List<string>();
                var total = 0;
                var disabled = 0;

                foreach (var layer in new[] { WkNative.LayerAleAuthConnectV4, WkNative.LayerAleAuthConnectV6 })
                {
                    var counted = CountOwnedFilters(handle, layer, out var disabledInLayer, out var error);
                    total += counted;
                    disabled += disabledInLayer;

                    if (error is not null)
                    {
                        orphaned.Add(error);
                    }
                }

                if (disabled > 0)
                {
                    orphaned.Add(
                        $"{disabled.ToString(CultureInfo.InvariantCulture)} MyVpn filter(s) are marked "
                        + "FWPM_FILTER_FLAG_DISABLED, which is how BFE reports a persistent object whose "
                        + "provider's service is missing or not auto-start. Protection is NOT in force.");
                }

                // A plan with no expected count check would let a half-installed rule set look
                // armed. When the caller supplies the plan we compare against what it should be.
                if (expected is not null && expected.Mode != KillSwitchMode.Disabled)
                {
                    var wanted = WfpKillSwitchPlanTranslator.Translate(expected);
                    if (wanted.IsSuccess && wanted.Value.Filters.Count != total)
                    {
                        orphaned.Add(
                            $"expected {wanted.Value.Filters.Count.ToString(CultureInfo.InvariantCulture)} "
                            + $"filter(s) for the planned rule set but the engine holds "
                            + $"{total.ToString(CultureInfo.InvariantCulture)}");
                    }
                }

                return Task.FromResult(new KillSwitchState
                {
                    IsArmed = total > 0 && disabled < total,
                    IsDrifted = disabled > 0 || orphaned.Count > 0,
                    OrphanedRules = orphaned,
                    MechanismName = MechanismName,
                });
            }
            finally
            {
                if (ownsHandle)
                {
                    WkNative.EngineClose(handle);
                }
            }
        }
    }

    /// <summary>
    /// Ends a dynamic session, which destroys every filter it installed.
    /// </summary>
    /// <remarks>
    /// The owner of this object is the service, and the service's shutdown path calls this.
    /// Forgetting it would leave a dynamic session's rules in force until the process exits,
    /// which is exactly wrong for a clean disconnect.
    /// </remarks>
    public void Dispose()
    {
        lock (_gate)
        {
            CloseSessionLocked();
        }
    }

    // ------------------------------------------------------------------ install

    private KillSwitchApplyResult Install(WfpFilterSet set, ulong tunnelLuid)
    {
        lock (_gate)
        {
            // Re-apply is a normal event (a reconnect, a settings change). Dropping the previous
            // dynamic session first removes its objects, so the install is a replacement rather
            // than an accumulation; persistent objects are deleted explicitly below.
            CloseSessionLocked();

            var opened = WkNative.EngineOpen(set.PersistAcrossReboot, out var handle);
            if (opened != 0)
            {
                return KillSwitchApplyResult.Failed(EngineUnavailable("FwpmEngineOpen0", opened));
            }

            var keepSession = false;
            var committed = false;
            var allocations = new List<IntPtr>();

            try
            {
                var begin = WkNative.TransactionBegin(handle, 0);
                if (begin != 0)
                {
                    return KillSwitchApplyResult.Failed(Failure("FwpmTransactionBegin0", begin));
                }

                try
                {
                    var provider = AddProvider(handle, set.PersistAcrossReboot);
                    if (provider != 0)
                    {
                        return KillSwitchApplyResult.Failed(Failure("FwpmProviderAdd0", provider));
                    }

                    var subLayer = AddSubLayer(handle, set.PersistAcrossReboot, allocations);
                    if (subLayer != 0)
                    {
                        return KillSwitchApplyResult.Failed(Failure("FwpmSubLayerAdd0", subLayer));
                    }

                    // Anything left from a previous run is removed inside the same transaction,
                    // so a re-apply cannot end with two generations of filters in the sub-layer.
                    DeleteOwnedFilters(handle);

                    var tunnelCondition = AllocateUInt64(tunnelLuid, allocations);
                    var userDescriptor = AllocateUserDescriptor(allocations);

                    var added = AddFilters(handle, set, tunnelCondition, userDescriptor, allocations);
                    if (added.IsFailure)
                    {
                        return KillSwitchApplyResult.Failed(added.Error!);
                    }

                    var commit = WkNative.TransactionCommit(handle);
                    if (commit != 0)
                    {
                        return KillSwitchApplyResult.Failed(Failure("FwpmTransactionCommit0", commit));
                    }

                    // A dynamic session must stay open: its objects die with the handle. A
                    // persistent session has nothing to keep alive, so the handle is closed and
                    // the filters remain in the engine.
                    keepSession = !set.PersistAcrossReboot;
                    committed = true;

                    if (keepSession)
                    {
                        _engineHandle = handle;
                    }

                    return KillSwitchApplyResult.Ok(
                        $"Installed {set.Filters.Count.ToString(CultureInfo.InvariantCulture)} WFP filter(s) "
                        + $"in sub-layer 0x{SubLayerWeight:X4} "
                        + $"(mode={(set.PersistAcrossReboot ? "persistent+boot-time" : "dynamic")}, "
                        + $"tunnel LUID={tunnelLuid.ToString(CultureInfo.InvariantCulture)}).");
                }
                finally
                {
                    // Aborting a committed transaction is pointless and would mask nothing, so it
                    // only happens on the paths that actually left work unfinished.
                    if (!committed)
                    {
                        WkNative.TransactionAbort(handle);
                    }
                }
            }
            finally
            {
                FreeAllocations(allocations);

                if (!keepSession)
                {
                    WkNative.EngineClose(handle);
                }
            }
        }
    }

    private static uint AddProvider(IntPtr handle, bool persistent)
    {
        var name = Marshal.StringToHGlobalUni(ProviderName);
        var description = Marshal.StringToHGlobalUni("MyVpn Kill Switch policy provider");
        var serviceName = persistent ? Marshal.StringToHGlobalUni(PersistentServiceName) : IntPtr.Zero;

        try
        {
            var provider = new WkNative.NativeProvider
            {
                ProviderKey = ProviderKey,
                DisplayData = new WkNative.NativeDisplayData { Name = name, Description = description },

                // A persistent object whose provider does not name an auto-start service is
                // added by BFE as *disabled*, so the service name is what makes lockdown mode
                // actually survive a reboot.
                Flags = persistent ? WkNative.ProviderFlagPersistent : 0,
                ProviderData = default,
                ServiceName = serviceName,
            };

            var result = WkNative.ProviderAdd(handle, ref provider);

            // A previous persistent run already registered the provider. That is the normal
            // always-on re-apply case, not an error: the existing object is the same one.
            return result == WkNative.ErrorAlreadyExists ? 0u : result;
        }
        finally
        {
            Marshal.FreeHGlobal(name);
            Marshal.FreeHGlobal(description);

            if (serviceName != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(serviceName);
            }
        }
    }

    private static uint AddSubLayer(IntPtr handle, bool persistent, List<IntPtr> allocations)
    {
        var name = Marshal.StringToHGlobalUni("MyVpn Kill Switch");
        var description = Marshal.StringToHGlobalUni("Fail-closed egress policy");
        var providerKey = AllocateGuid(ProviderKey, allocations);

        try
        {
            var subLayer = new WkNative.NativeSubLayer
            {
                SubLayerKey = SubLayerKey,
                DisplayData = new WkNative.NativeDisplayData { Name = name, Description = description },
                Flags = persistent ? WkNative.SubLayerFlagPersistent : 0,
                ProviderKey = providerKey,
                ProviderData = default,
                Weight = SubLayerWeight,
            };

            var result = WkNative.SubLayerAdd(handle, ref subLayer);
            return result == WkNative.ErrorAlreadyExists ? 0u : result;
        }
        finally
        {
            Marshal.FreeHGlobal(name);
            Marshal.FreeHGlobal(description);
        }
    }

    private static Result AddFilters(
        IntPtr handle,
        WfpFilterSet set,
        IntPtr tunnelCondition,
        IntPtr userDescriptor,
        List<IntPtr> allocations)
    {
        var applicationIds = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);

        foreach (var descriptor in set.Filters)
        {
            var conditions = new List<WkNative.NativeCondition>(descriptor.Conditions.Count);

            foreach (var condition in descriptor.Conditions)
            {
                var built = BuildCondition(condition, applicationIds, userDescriptor, tunnelCondition, allocations);

                if (built.IsFailure)
                {
                    return Result.Fail(built.Error!);
                }

                conditions.Add(built.Value);
            }

            var filter = new WkNative.NativeFilter
            {
                FilterKey = Guid.NewGuid(),
                DisplayData = new WkNative.NativeDisplayData
                {
                    Name = Marshal.StringToHGlobalUni(descriptor.Name),
                    Description = Marshal.StringToHGlobalUni(descriptor.ReasonKey),
                },
                Flags = descriptor.Flags switch
                {
                    WfpFilterFlags.Persistent => WkNative.FilterFlagPersistent,
                    WfpFilterFlags.BootTime => WkNative.FilterFlagBootTime,
                    _ => 0u,
                },
                ProviderKey = AllocateGuid(ProviderKey, allocations),
                ProviderData = default,
                LayerKey = descriptor.Layer == WfpLayer.AleAuthConnectV6
                    ? WkNative.LayerAleAuthConnectV6
                    : WkNative.LayerAleAuthConnectV4,
                SubLayerKey = SubLayerKey,
                Weight = WkNative.ValueUInt8(descriptor.Weight),
                NumFilterConditions = (uint)conditions.Count,
                FilterCondition = WkNative.AllocateConditions(conditions, allocations),
                Action = new WkNative.NativeAction
                {
                    Type = descriptor.Action == WfpAction.Block
                        ? WkNative.ActionBlock
                        : WkNative.ActionPermit,

                    // "An arbitrary GUID chosen by the policy provider" — zero is what the
                    // reference implementation passes for non-callout actions.
                    FilterType = Guid.Empty,
                },
                Context = default,
                Reserved = IntPtr.Zero,
                FilterId = 0,
                EffectiveWeight = default,
            };

            var result = WkNative.FilterAdd(handle, ref filter, out _);

            if (result != 0 && result != WkNative.ErrorAlreadyExists)
            {
                return Result.Fail(Failure($"FwpmFilterAdd0('{descriptor.Name}')", result));
            }

            // The engine copies the condition data, so the display strings are released here
            // rather than kept alive for the lifetime of the session.
            Marshal.FreeHGlobal(filter.DisplayData.Name);
            Marshal.FreeHGlobal(filter.DisplayData.Description);
        }

        return Result.Ok();
    }

    /// <summary>Builds one native match condition from a translated descriptor condition.</summary>
    private static Result<WkNative.NativeCondition> BuildCondition(
        WfpCondition condition,
        Dictionary<string, IntPtr> applicationIds,
        IntPtr userDescriptor,
        IntPtr tunnelCondition,
        List<IntPtr> allocations)
    {
        switch (condition.Kind)
        {
            case WfpConditionKind.ApplicationPath:
            {
                var path = condition.Value ?? string.Empty;

                if (!applicationIds.TryGetValue(path, out var blob))
                {
                    var result = WkNative.GetAppIdFromFileName(path, out blob);

                    if (result != 0)
                    {
                        return Result<WkNative.NativeCondition>.Fail(new MyVpnError(
                            ErrorCodes.KillSwitchApplyFailed,
                            "error.killswitch.application_path_not_absolute",
                            ErrorSeverity.Error,
                            $"FwpmGetAppIdFromFileName0 could not derive an application identity for "
                            + $"'{path}' (0x{result:X8}), so the exemption that keeps the tunnel alive "
                            + "cannot be built and nothing was installed.",
                            "killswitch.reapply"));
                    }

                    applicationIds[path] = blob;
                }

                return Result<WkNative.NativeCondition>.Ok(WkNative.Condition(
                    WkNative.ConditionAleAppId,
                    WkNative.MatchEqual,
                    WkNative.ValueBlob(blob)));
            }

            case WfpConditionKind.ProcessUserScope:
            {
                if (userDescriptor == IntPtr.Zero)
                {
                    // Deliberately fatal: silently dropping the condition would leave a rule set
                    // that any process running the same image path could inherit.
                    return Result<WkNative.NativeCondition>.Fail(new MyVpnError(
                        ErrorCodes.KillSwitchApplyFailed,
                        "error.killswitch.needs_privileges",
                        ErrorSeverity.Error,
                        "The security descriptor of this process's token could not be built, so the "
                        + "ALE_USER_ID condition that stops a same-path copy of the core from inheriting "
                        + "the tunnel exemption is unavailable. No filter was installed.",
                        "killswitch.reapply"));
                }

                return Result<WkNative.NativeCondition>.Ok(WkNative.Condition(
                    WkNative.ConditionAleUserId,
                    WkNative.MatchEqual,
                    WkNative.ValueBlob(userDescriptor)));
            }

            case WfpConditionKind.RemoteAddress:
            {
                if (!CidrBlock.TryParse(condition.Value, out var block))
                {
                    return Result<WkNative.NativeCondition>.Fail(new MyVpnError(
                        ErrorCodes.KillSwitchApplyFailed,
                        "error.killswitch.server_not_resolved",
                        ErrorSeverity.Error,
                        $"'{condition.Value}' is not a CIDR block, so the address condition cannot be "
                        + "built. Every destination must be a resolved IP literal.",
                        "killswitch.reapply"));
                }

                return Result<WkNative.NativeCondition>.Ok(WkNative.Condition(
                    WkNative.ConditionIpRemoteAddress,
                    WkNative.MatchEqual,
                    WkNative.ValueAddress(block, allocations)));
            }

            case WfpConditionKind.RemotePort:
                return Result<WkNative.NativeCondition>.Ok(WkNative.Condition(
                    WkNative.ConditionIpRemotePort,
                    WkNative.MatchEqual,
                    WkNative.ValueUInt16((ushort)(condition.Port ?? 0))));

            case WfpConditionKind.Protocol:
                return Result<WkNative.NativeCondition>.Ok(WkNative.Condition(
                    WkNative.ConditionIpProtocol,
                    WkNative.MatchEqual,
                    WkNative.ValueUInt8(ProtocolNumber(condition.Value))));

            case WfpConditionKind.IsLoopback:
                return Result<WkNative.NativeCondition>.Ok(WkNative.Condition(
                    WkNative.ConditionFlags,

                    // FWP_MATCH_FLAGS_ALL_SET: every bit in the value must be set in the field.
                    WkNative.MatchFlagsAllSet,
                    WkNative.ValueUInt32(WkNative.ConditionFlagIsLoopback)));

            case WfpConditionKind.LocalInterface:
                return Result<WkNative.NativeCondition>.Ok(WkNative.Condition(
                    WkNative.ConditionIpLocalInterface,
                    WkNative.MatchEqual,
                    WkNative.ValueUInt64Pointer(tunnelCondition)));

            default:
                return Result<WkNative.NativeCondition>.Fail(new MyVpnError(
                    ErrorCodes.KillSwitchApplyFailed,
                    "error.killswitch.apply_failed",
                    ErrorSeverity.Error,
                    $"The translator produced a condition kind this executor cannot build "
                    + $"({condition.Kind}). Nothing was installed."));
        }
    }

    /// <summary>IP protocol numbers, as <c>FWPM_CONDITION_IP_PROTOCOL</c> expects them.</summary>
    private static byte ProtocolNumber(string? protocol) => protocol switch
    {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "icmpv6" => 58,
        _ => 0,
    };

    // ------------------------------------------------------------------ teardown helpers

    /// <summary>
    /// Deletes every filter owned by <see cref="ProviderKey"/>, whatever installed it.
    /// </summary>
    /// <remarks>
    /// Ownership is read from the engine rather than reconstructed from a plan, which is what
    /// makes teardown correct after a crash or an upgrade. The return value is the number of
    /// filters deleted; failures are ignored on purpose because a filter that is already gone
    /// is the state we are trying to reach.
    /// </remarks>
    private static int DeleteOwnedFilters(IntPtr handle)
    {
        var deleted = 0;

        foreach (var layer in new[] { WkNative.LayerAleAuthConnectV4, WkNative.LayerAleAuthConnectV6 })
        {
            foreach (var key in OwnedFilterKeys(handle, layer))
            {
                var result = WkNative.FilterDeleteByKey(handle, key);

                if (result == 0 || result == WkNative.ErrorFilterNotFound || result == WkNative.ErrorNotFound)
                {
                    deleted++;
                }
            }
        }

        return deleted;
    }

    private static int CountOwnedFilters(IntPtr handle, Guid layer, out int disabled, out string? error)
    {
        disabled = 0;
        error = null;

        var keys = new List<Guid>();
        var found = EnumerateOwnedFilters(handle, layer, keys, out var disabledCount, out error);
        disabled = disabledCount;
        return found;
    }

    /// <summary>
    /// Enumerates MyVpn's filters on one layer, including disabled and boot-time objects.
    /// </summary>
    /// <remarks>
    /// <c>FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED</c> matters: without it a filter that BFE
    /// silently disabled at boot is simply not returned, and the read-back would report a clean
    /// state while nothing is enforced.
    /// </remarks>
    private static int EnumerateOwnedFilters(
        IntPtr handle,
        Guid layer,
        List<Guid> keys,
        out int disabled,
        out string? error)
    {
        disabled = 0;
        error = null;

        var providerKey = AllocateGuidEphemeral(ProviderKey);

        try
        {
            var template = new WkNative.NativeFilterEnumTemplate
            {
                ProviderKey = providerKey,
                LayerKey = layer,
                EnumType = WkNative.FilterEnumOverlapping,
                Flags = WkNative.FilterEnumFlagIncludeDisabled | WkNative.FilterEnumFlagIncludeBootTime,
                ProviderContextTemplate = IntPtr.Zero,
                NumFilterConditions = 0,
                FilterCondition = IntPtr.Zero,

                // A zero action mask means "any action".
                ActionMask = 0,
                CalloutKey = IntPtr.Zero,
            };

            var created = WkNative.FilterCreateEnumHandle(handle, ref template, out var enumHandle);

            if (created != 0)
            {
                error = $"FwpmFilterCreateEnumHandle0 failed with 0x{created:X8}";
                return 0;
            }

            try
            {
                var count = 0;
                var entries = IntPtr.Zero;
                uint returned;

                do
                {
                    returned = 0;
                    var next = WkNative.FilterEnum(handle, enumHandle, 64, out entries, out returned);

                    if (next != 0)
                    {
                        error = $"FwpmFilterEnum0 failed with 0x{next:X8}";
                        break;
                    }

                    for (var index = 0; index < returned; index++)
                    {
                        var pointer = Marshal.ReadIntPtr(entries, index * IntPtr.Size);
                        var filter = Marshal.PtrToStructure<WkNative.NativeFilter>(pointer);

                        // The template's provider filter is honoured by the engine, but the
                        // ownership check is repeated here: deleting a foreign filter because a
                        // template field was ignored would be a serious bug.
                        if (filter.ProviderKey == IntPtr.Zero
                            || !Marshal.PtrToStructure<Guid>(filter.ProviderKey).Equals(ProviderKey))
                        {
                            continue;
                        }

                        count++;
                        keys.Add(filter.FilterKey);

                        if ((filter.Flags & WkNative.FilterFlagDisabled) != 0)
                        {
                            disabled++;
                        }
                    }

                    if (entries != IntPtr.Zero)
                    {
                        WkNative.FreeMemory(ref entries);
                    }
                }
                while (returned > 0);

                return count;
            }
            finally
            {
                WkNative.FilterDestroyEnumHandle(handle, enumHandle);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(providerKey);
        }
    }

    /// <summary>Deletes filters by key, used by <see cref="DeleteOwnedFilters"/>.</summary>
    private static IEnumerable<Guid> OwnedFilterKeys(IntPtr handle, Guid layer)
    {
        var keys = new List<Guid>();
        EnumerateOwnedFilters(handle, layer, keys, out _, out _);
        return keys;
    }

    // ------------------------------------------------------------------ memory helpers

    private static IntPtr AllocateUInt64(ulong value, List<IntPtr> allocations)
    {
        var pointer = Marshal.AllocHGlobal(sizeof(long));
        Marshal.WriteInt64(pointer, unchecked((long)value));
        allocations.Add(pointer);
        return pointer;
    }

    private static IntPtr AllocateGuid(Guid value, List<IntPtr> allocations)
    {
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        Marshal.StructureToPtr(value, pointer, false);
        allocations.Add(pointer);
        return pointer;
    }

    private static IntPtr AllocateGuidEphemeral(Guid value)
    {
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        Marshal.StructureToPtr(value, pointer, false);
        return pointer;
    }

    /// <summary>
    /// Builds the security descriptor used as the <c>ALE_USER_ID</c> condition.
    /// </summary>
    /// <remarks>
    /// Both conditions on the core's permit matter. <c>ALE_APP_ID</c> is a <i>path</i>, so any
    /// second process running the same image would otherwise inherit the tunnel exemption; the
    /// user-id condition is what the reference implementation adds to stop that. The descriptor
    /// is built in SDDL (<c>D:(A;;CC;;;&lt;sid&gt;)</c>) from this process's own token SID, which
    /// for the service is its service SID.
    /// </remarks>
    private static IntPtr AllocateUserDescriptor(List<IntPtr> allocations)
    {
        var token = IntPtr.Zero;
        var buffer = IntPtr.Zero;
        var stringSid = IntPtr.Zero;
        var descriptor = IntPtr.Zero;

        try
        {
            if (!WkNative.OpenProcessToken(WkNative.GetCurrentProcess(), WkNative.TokenQuery, out token))
            {
                return IntPtr.Zero;
            }

            if (!WkNative.GetTokenInformation(token, WkNative.TokenUser, IntPtr.Zero, 0, out var needed)
                && needed <= 0)
            {
                return IntPtr.Zero;
            }

            buffer = Marshal.AllocHGlobal(needed);

            if (!WkNative.GetTokenInformation(token, WkNative.TokenUser, buffer, needed, out _))
            {
                return IntPtr.Zero;
            }

            // TOKEN_USER { SID_AND_ATTRIBUTES { SID* Sid; DWORD Attributes; } } — the SID
            // pointer is the first field of the structure.
            var sid = Marshal.ReadIntPtr(buffer);

            if (!WkNative.ConvertSidToStringSid(sid, out stringSid))
            {
                return IntPtr.Zero;
            }

            var sidText = Marshal.PtrToStringUni(stringSid);
            if (string.IsNullOrWhiteSpace(sidText))
            {
                return IntPtr.Zero;
            }

            // CC = SERVICE_CONNECT. The descriptor is a condition, not an ACL on an object, so
            // the granted right is the connect right the ALE layer checks.
            var sddl = $"D:(A;;CC;;;{sidText})";

            if (!WkNative.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    sddl, WkNative.SddlRevision1, out descriptor, out _))
            {
                return IntPtr.Zero;
            }

            allocations.Add(descriptor);
            return descriptor;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return IntPtr.Zero;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);

            if (stringSid != IntPtr.Zero)
            {
                WkNative.LocalFree(stringSid);
            }

            if (token != IntPtr.Zero)
            {
                WkNative.CloseHandle(token);
            }
        }
    }

    private static void FreeAllocations(List<IntPtr> allocations)
    {
        foreach (var pointer in allocations)
        {
            if (pointer != IntPtr.Zero)
            {
                WkNative.FreeMemoryPointer(pointer);
            }
        }

        allocations.Clear();
    }

    private void CloseSessionLocked()
    {
        if (_engineHandle == IntPtr.Zero)
        {
            return;
        }

        WkNative.EngineClose(_engineHandle);
        _engineHandle = IntPtr.Zero;
    }

    // ------------------------------------------------------------------ errors

    private static MyVpnError NotElevated() =>
        WindowsPlatform.NotElevated(
            "error.killswitch.needs_privileges",
            "Installing WFP filters requires administrative rights or the SYSTEM account, and this "
            + "process has neither. The UI must never run elevated; this step belongs to the "
            + "privileged helper.",
            "privilege.install_helper");

    private static MyVpnError EngineUnavailable(string call, uint code) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.not_available",
            ErrorSeverity.Critical,
            $"{call} failed with 0x{code:X8}{Describe(code)}. The Base Filtering Engine is either not "
            + "running or refused this process, so no WFP policy is in force. Protection is not "
            + "available on this machine right now.",
            "diagnostics.run");

    private static MyVpnError Failure(string call, uint code) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.apply_failed",
            ErrorSeverity.Critical,
            $"{call} failed with 0x{code:X8}{Describe(code)}. The transaction was aborted, so the "
            + "previous state is unchanged.",
            "killswitch.reapply");

    /// <summary>Names the handful of FWP error codes worth recognising in a log line.</summary>
    private static string Describe(uint code) => code switch
    {
        WkNative.ErrorAlreadyExists => " (FWP_E_ALREADY_EXISTS)",
        WkNative.ErrorNotFound => " (FWP_E_NOT_FOUND)",
        WkNative.ErrorFilterNotFound => " (FWP_E_FILTER_NOT_FOUND)",
        WkNative.ErrorProviderNotFound => " (FWP_E_PROVIDER_NOT_FOUND)",
        WkNative.ErrorSubLayerNotFound => " (FWP_E_SUBLAYER_NOT_FOUND)",
        WkNative.ErrorInUse => " (FWP_E_IN_USE)",
        WkNative.ErrorDynamicSessionInProgress => " (FWP_E_DYNAMIC_SESSION_IN_PROGRESS)",
        WkNative.ErrorTransactionInProgress => " (FWP_E_TXN_IN_PROGRESS)",
        WkNative.ErrorIncompatibleTransaction => " (FWP_E_INCOMPATIBLE_TXN)",
        5 => " (ERROR_ACCESS_DENIED)",
        _ => string.Empty,
    };

    /// <summary>
    /// The <c>fwpuclnt.dll</c> surface MyVpn uses, with the layouts and constants transcribed
    /// from the Windows SDK headers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every member here is reached only through a public entry point that has already checked
    /// <see cref="WindowsPlatform.IsWindows"/>, so nothing in this type can run on Linux. It is
    /// a nested type rather than a separate file so the "no P/Invoke outside the guarded
    /// executor" rule is visible at a glance.
    /// </para>
    /// <para>
    /// The struct layouts are ABI-verified: marshalling offsets were compared field by field
    /// against a compiled C translation of <c>FWPM_FILTER0</c>, <c>FWPM_SESSION0</c>,
    /// <c>FWPM_PROVIDER0</c>, <c>FWPM_SUBLAYER0</c>, <c>FWPM_ACTION0</c> and
    /// <c>FWPM_FILTER_CONDITION0</c>. The <i>calls</i> remain runtime-unverified.
    /// </para>
    /// </remarks>
    private static class WkNative
    {
        public const uint SessionFlagDynamic = 0x00000001;
        public const uint ProviderFlagPersistent = 0x00000001;
        public const uint ProviderFlagDisabled = 0x00000010;
        public const uint SubLayerFlagPersistent = 0x00000001;
        public const uint FilterFlagPersistent = 0x00000001;
        public const uint FilterFlagBootTime = 0x00000002;
        public const uint FilterFlagDisabled = 0x00000020;

        public const uint FilterEnumFlagIncludeBootTime = 0x00000008;
        public const uint FilterEnumFlagIncludeDisabled = 0x00000010;
        public const uint FilterEnumOverlapping = 1;

        public const uint ActionBlock = 0x00001001;
        public const uint ActionPermit = 0x00001002;

        public const uint ConditionFlagIsLoopback = 0x00000001;

        public const uint DataTypeEmpty = 0;
        public const uint DataTypeUInt8 = 1;
        public const uint DataTypeUInt16 = 2;
        public const uint DataTypeUInt32 = 3;
        public const uint DataTypeUInt64 = 4;
        public const uint DataTypeV4AddrMask = 0x100;
        public const uint DataTypeV6AddrMask = 0x101;
        public const uint DataTypeByteBlob = 12;

        public const uint MatchEqual = 0;
        public const uint MatchFlagsAllSet = 6;

        public const uint ErrorFilterNotFound = 0x80320003;
        public const uint ErrorProviderNotFound = 0x80320005;
        public const uint ErrorSubLayerNotFound = 0x80320007;
        public const uint ErrorNotFound = 0x80320008;
        public const uint ErrorAlreadyExists = 0x80320009;
        public const uint ErrorInUse = 0x8032000A;
        public const uint ErrorDynamicSessionInProgress = 0x8032000B;
        public const uint ErrorTransactionInProgress = 0x8032000E;
        public const uint ErrorIncompatibleTransaction = 0x80320011;

        public const uint TokenQuery = 0x0008;
        public const int TokenUser = 1;
        public const uint SddlRevision1 = 1;
        public const uint RpcCAuthnWinnt = 10;
        public const uint InfiniteTimeout = 0xFFFFFFFF;

        public static readonly Guid LayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        public static readonly Guid LayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        public static readonly Guid ConditionAleAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
        public static readonly Guid ConditionAleUserId = new("af043a0a-b34d-4f86-979c-c90371af6e66");
        public static readonly Guid ConditionIpProtocol = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
        public static readonly Guid ConditionIpRemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        public static readonly Guid ConditionIpRemotePort = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");
        public static readonly Guid ConditionIpLocalInterface = new("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
        public static readonly Guid ConditionFlags = new("632ce23b-5167-435c-86d7-e903684aa80c");

        // -------------------------------------------------------------- engine lifecycle

        public static uint EngineOpen(bool persistent, out IntPtr handle)
        {
            var sessionName = Marshal.StringToHGlobalUni(ProviderName);
            var sessionDescription = Marshal.StringToHGlobalUni("MyVpn Kill Switch session");

            try
            {
                var session = new NativeSession
                {
                    SessionKey = Guid.Empty,
                    DisplayData = new NativeDisplayData { Name = sessionName, Description = sessionDescription },
                    Flags = persistent ? 0u : SessionFlagDynamic,

                    // Wait indefinitely for another transaction rather than failing a connect
                    // because two administrative tools touched the policy at the same moment.
                    TxnWaitTimeoutInMSec = InfiniteTimeout,
                    ProcessId = 0,
                    Sid = IntPtr.Zero,
                    Username = IntPtr.Zero,
                    KernelMode = 0,
                };

                return FwpmEngineOpen0(null, RpcCAuthnWinnt, IntPtr.Zero, ref session, out handle);
            }
            finally
            {
                Marshal.FreeHGlobal(sessionName);
                Marshal.FreeHGlobal(sessionDescription);
            }
        }

        public static void EngineClose(IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                FwpmEngineClose0(handle);
            }
        }

        public static uint TransactionBegin(IntPtr handle, uint flags) => FwpmTransactionBegin0(handle, flags);

        public static uint TransactionCommit(IntPtr handle) => FwpmTransactionCommit0(handle);

        public static void TransactionAbort(IntPtr handle) => FwpmTransactionAbort0(handle);

        public static uint ProviderAdd(IntPtr handle, ref NativeProvider provider) =>
            FwpmProviderAdd0(handle, ref provider, IntPtr.Zero);

        public static uint ProviderDeleteByKey(IntPtr handle, Guid key)
        {
            var pointer = AllocateGuidEphemeralStatic(key);

            try
            {
                return FwpmProviderDeleteByKey0(handle, pointer);
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
        }

        public static uint SubLayerAdd(IntPtr handle, ref NativeSubLayer subLayer) =>
            FwpmSubLayerAdd0(handle, ref subLayer, IntPtr.Zero);

        public static uint SubLayerDeleteByKey(IntPtr handle, Guid key)
        {
            var pointer = AllocateGuidEphemeralStatic(key);

            try
            {
                return FwpmSubLayerDeleteByKey0(handle, pointer);
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
        }

        public static uint FilterAdd(IntPtr handle, ref NativeFilter filter, out ulong id) =>
            FwpmFilterAdd0(handle, ref filter, IntPtr.Zero, out id);

        public static uint FilterDeleteByKey(IntPtr handle, Guid key)
        {
            var pointer = AllocateGuidEphemeralStatic(key);

            try
            {
                return FwpmFilterDeleteByKey0(handle, pointer);
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
        }

        public static uint FilterCreateEnumHandle(
            IntPtr handle,
            ref NativeFilterEnumTemplate template,
            out IntPtr enumHandle) =>
            FwpmFilterCreateEnumHandle0(handle, ref template, out enumHandle);

        public static uint FilterEnum(
            IntPtr handle,
            IntPtr enumHandle,
            uint requested,
            out IntPtr entries,
            out uint returned) =>
            FwpmFilterEnum0(handle, enumHandle, requested, out entries, out returned);

        public static void FilterDestroyEnumHandle(IntPtr handle, IntPtr enumHandle) =>
            FwpmFilterDestroyEnumHandle0(handle, enumHandle);

        public static uint GetAppIdFromFileName(string path, out IntPtr appId) =>
            FwpmGetAppIdFromFileName0(path, out appId);

        public static void FreeMemory(ref IntPtr pointer) => FwpmFreeMemory0(ref pointer);

        /// <summary>Frees memory the engine handed back through an out-parameter.</summary>
        public static void FreeMemoryPointer(IntPtr pointer)
        {
            var local = pointer;
            FwpmFreeMemory0(ref local);
        }

        // -------------------------------------------------------------- token / SDDL

        public static IntPtr GetCurrentProcess() => KernelGetCurrentProcess();

        public static bool OpenProcessToken(IntPtr process, uint access, out IntPtr token) =>
            AdvapiOpenProcessToken(process, access, out token);

        public static bool GetTokenInformation(
            IntPtr token,
            int infoClass,
            IntPtr info,
            int length,
            out int returned) =>
            AdvapiGetTokenInformation(token, infoClass, info, length, out returned);

        public static bool ConvertSidToStringSid(IntPtr sid, out IntPtr text) =>
            AdvapiConvertSidToStringSid(sid, out text);

        public static bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string sddl,
            uint revision,
            out IntPtr descriptor,
            out uint size) =>
            AdvapiConvertStringSecurityDescriptorToSecurityDescriptor(sddl, revision, out descriptor, out size);

        public static IntPtr LocalFree(IntPtr memory) => KernelLocalFree(memory);

        public static void CloseHandle(IntPtr handle) => KernelCloseHandle(handle);

        // -------------------------------------------------------------- condition values

        public static NativeCondition Condition(Guid fieldKey, uint matchType, NativeValue value) => new()
        {
            FieldKey = fieldKey,
            MatchType = matchType,
            ConditionValue = value,
        };

        public static NativeValue ValueUInt8(byte value) => new() { Type = DataTypeUInt8, UInt8 = value };

        public static NativeValue ValueUInt16(ushort value) => new() { Type = DataTypeUInt16, UInt16 = value };

        public static NativeValue ValueUInt32(uint value) => new() { Type = DataTypeUInt32, UInt32 = value };

        public static NativeValue ValueUInt64Pointer(IntPtr pointer) => new()
        {
            Type = DataTypeUInt64,
            Pointer = pointer,
        };

        public static NativeValue ValueBlob(IntPtr blob) => new()
        {
            Type = DataTypeByteBlob,
            Pointer = blob,
        };

        /// <summary>
        /// Builds the address-mask value the address conditions expect.
        /// </summary>
        /// <remarks>
        /// IPv4 and IPv6 use different structures, and both are passed <i>by pointer</i>:
        /// <c>FWP_V4_ADDR_AND_MASK</c> is an 8-byte <c>{ UINT32 addr; UINT32 mask; }</c> in
        /// network byte order, and <c>FWP_V6_ADDR_AND_MASK</c> is 16 address bytes followed by
        /// the prefix length. Writing them field by field through <c>Marshal</c> avoids
        /// declaring two more structs whose padding would have to be re-derived per
        /// architecture.
        /// </remarks>
        public static NativeValue ValueAddress(CidrBlock block, List<IntPtr> allocations)
        {
            if (block.IsIPv4)
            {
                var pointer = Marshal.AllocHGlobal(8);
                allocations.Add(pointer);

                var address = block.Network.GetAddressBytes();
                var host = ((uint)address[0] << 24) | ((uint)address[1] << 16)
                           | ((uint)address[2] << 8) | address[3];

                var mask = block.PrefixLength == 0 ? 0u : 0xFFFFFFFFu << (32 - block.PrefixLength);

                Marshal.WriteInt32(pointer, 0, unchecked((int)host));
                Marshal.WriteInt32(pointer, 4, unchecked((int)mask));

                return new NativeValue { Type = DataTypeV4AddrMask, Pointer = pointer };
            }
            else
            {
                var pointer = Marshal.AllocHGlobal(17);
                allocations.Add(pointer);

                var address = block.Network.GetAddressBytes();
                Marshal.Copy(address, 0, pointer, 16);
                Marshal.WriteByte(pointer, 16, (byte)block.PrefixLength);

                return new NativeValue { Type = DataTypeV6AddrMask, Pointer = pointer };
            }
        }

        /// <summary>Marshals a condition array into unmanaged memory the engine can read.</summary>
        public static IntPtr AllocateConditions(List<NativeCondition> conditions, List<IntPtr> allocations)
        {
            if (conditions.Count == 0)
            {
                // The unconditional catch-all: no conditions at all is the match-everything rule.
                return IntPtr.Zero;
            }

            var size = Marshal.SizeOf<NativeCondition>();
            var pointer = Marshal.AllocHGlobal(size * conditions.Count);
            allocations.Add(pointer);

            for (var index = 0; index < conditions.Count; index++)
            {
                Marshal.StructureToPtr(conditions[index], IntPtr.Add(pointer, index * size), false);
            }

            return pointer;
        }

        private static IntPtr AllocateGuidEphemeralStatic(Guid value)
        {
            var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
            Marshal.StructureToPtr(value, pointer, false);
            return pointer;
        }

        // -------------------------------------------------------------- native types

        [StructLayout(LayoutKind.Sequential)]
        public struct NativeDisplayData
        {
            public IntPtr Name;
            public IntPtr Description;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NativeByteBlob
        {
            public uint Size;
            public IntPtr Data;
        }

        /// <summary><c>FWPM_ACTION0</c>: <c>{ FWP_ACTION_TYPE type; union { GUID; UINT64; } }</c>, 20 bytes.</summary>
        [StructLayout(LayoutKind.Explicit, Size = 20)]
        public struct NativeAction
        {
            [FieldOffset(0)]
            public uint Type;

            [FieldOffset(4)]
            public Guid FilterType;

            [FieldOffset(4)]
            public ulong CalloutKey;
        }

        /// <summary>
        /// <c>FWP_VALUE0</c> / <c>FWP_CONDITION_VALUE0</c>: a type tag plus an 8-byte union.
        /// Scalar types live inline in the union; pointers, blobs, address masks and 64-bit
        /// values are passed by pointer, which is why the union offsets are explicit.
        /// </summary>
        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public struct NativeValue
        {
            [FieldOffset(0)]
            public uint Type;

            [FieldOffset(8)]
            public byte UInt8;

            [FieldOffset(8)]
            public ushort UInt16;

            [FieldOffset(8)]
            public uint UInt32;

            [FieldOffset(8)]
            public ulong UInt64;

            [FieldOffset(8)]
            public IntPtr Pointer;
        }

        /// <summary><c>FWPM_FILTER_CONDITION0</c>: 40 bytes (verified against the C layout).</summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct NativeCondition
        {
            public Guid FieldKey;
            public uint MatchType;
            public NativeValue ConditionValue;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public struct NativeContextUnion
        {
            [FieldOffset(0)]
            public ulong RawContext;

            [FieldOffset(0)]
            public Guid ProviderContextKey;
        }

        /// <summary><c>FWPM_FILTER0</c>: 200 bytes (verified against the C layout).</summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct NativeFilter
        {
            public Guid FilterKey;
            public NativeDisplayData DisplayData;
            public uint Flags;
            public IntPtr ProviderKey;
            public NativeByteBlob ProviderData;
            public Guid LayerKey;
            public Guid SubLayerKey;
            public NativeValue Weight;
            public uint NumFilterConditions;
            public IntPtr FilterCondition;
            public NativeAction Action;
            public NativeContextUnion Context;
            public IntPtr Reserved;
            public ulong FilterId;
            public NativeValue EffectiveWeight;
        }

        /// <summary><c>FWPM_SESSION0</c>: 72 bytes (verified against the C layout).</summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct NativeSession
        {
            public Guid SessionKey;
            public NativeDisplayData DisplayData;
            public uint Flags;
            public uint TxnWaitTimeoutInMSec;
            public uint ProcessId;
            public IntPtr Sid;
            public IntPtr Username;
            public int KernelMode;
        }

        /// <summary><c>FWPM_PROVIDER0</c>: 64 bytes.</summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct NativeProvider
        {
            public Guid ProviderKey;
            public NativeDisplayData DisplayData;
            public uint Flags;
            public NativeByteBlob ProviderData;
            public IntPtr ServiceName;
        }

        /// <summary><c>FWPM_SUBLAYER0</c>: 72 bytes.</summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct NativeSubLayer
        {
            public Guid SubLayerKey;
            public NativeDisplayData DisplayData;
            public uint Flags;
            public IntPtr ProviderKey;
            public NativeByteBlob ProviderData;
            public ushort Weight;
        }

        /// <summary><c>FWPM_FILTER_ENUM_TEMPLATE0</c>: 72 bytes.</summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct NativeFilterEnumTemplate
        {
            public IntPtr ProviderKey;
            public Guid LayerKey;
            public uint EnumType;
            public uint Flags;
            public IntPtr ProviderContextTemplate;
            public uint NumFilterConditions;
            public IntPtr FilterCondition;
            public uint ActionMask;
            public IntPtr CalloutKey;
        }

        // -------------------------------------------------------------- imports

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmEngineOpen0(
            [MarshalAs(UnmanagedType.LPWStr)] string? serverName,
            uint authnService,
            IntPtr authIdentity,
            ref NativeSession session,
            out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmEngineClose0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref NativeProvider provider, IntPtr sd);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmProviderDeleteByKey0(IntPtr engineHandle, IntPtr key);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref NativeSubLayer subLayer, IntPtr sd);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, IntPtr key);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmFilterAdd0(
            IntPtr engineHandle,
            ref NativeFilter filter,
            IntPtr sd,
            out ulong id);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, IntPtr key);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmFilterCreateEnumHandle0(
            IntPtr engineHandle,
            ref NativeFilterEnumTemplate enumTemplate,
            out IntPtr enumHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmFilterEnum0(
            IntPtr engineHandle,
            IntPtr enumHandle,
            uint numEntriesRequested,
            out IntPtr entries,
            out uint numEntriesReturned);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern uint FwpmGetAppIdFromFileName0(
            [MarshalAs(UnmanagedType.LPWStr)] string fileName,
            out IntPtr appId);

        [DllImport("fwpuclnt.dll", ExactSpelling = true, SetLastError = false)]
        public static extern void FwpmFreeMemory0(ref IntPtr p);

        [DllImport("kernel32.dll", EntryPoint = "GetCurrentProcess", ExactSpelling = true, SetLastError = false)]
        private static extern IntPtr KernelGetCurrentProcess();

        [DllImport("advapi32.dll", EntryPoint = "OpenProcessToken", ExactSpelling = true, SetLastError = false)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdvapiOpenProcessToken(
            IntPtr processHandle,
            uint desiredAccess,
            out IntPtr tokenHandle);

        [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", ExactSpelling = true, SetLastError = false)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdvapiGetTokenInformation(
            IntPtr tokenHandle,
            int tokenInformationClass,
            IntPtr tokenInformation,
            int tokenInformationLength,
            out int returnLength);

        [DllImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", ExactSpelling = true, SetLastError = false)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdvapiConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ExactSpelling = true,
            SetLastError = false)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdvapiConvertStringSecurityDescriptorToSecurityDescriptor(
            [MarshalAs(UnmanagedType.LPWStr)] string stringSecurityDescriptor,
            uint stringSecurityDescriptorLength,
            out IntPtr securityDescriptor,
            out uint securityDescriptorSize);

        [DllImport("kernel32.dll", EntryPoint = "LocalFree", ExactSpelling = true, SetLastError = false)]
        private static extern IntPtr KernelLocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", ExactSpelling = true, SetLastError = false)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool KernelCloseHandle(IntPtr handle);
    }
}
