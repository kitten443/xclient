using MyVpn.Core.Results;

namespace MyVpn.Core.Domain;

/// <summary>A single, observed state change.</summary>
public sealed record VpnStateChange(
    VpnConnectionState From,
    VpnConnectionState To,
    string Reason,
    DateTimeOffset Timestamp,
    MyVpnError? Error = null);

/// <summary>
/// The authoritative VPN lifecycle state machine.
/// </summary>
/// <remarks>
/// <para>
/// Centralizing the legal transitions here (rather than scattering booleans such as
/// <c>isConnecting</c> across view models) is what makes the leak-safety properties
/// checkable: the Kill Switch decision is a pure function of the current state
/// (<see cref="VpnConnectionStateExtensions.RequiresKillSwitch"/>), and no code path
/// can move from <see cref="VpnConnectionState.Connected"/> straight to
/// <see cref="VpnConnectionState.Disconnected"/> without passing through
/// <see cref="VpnConnectionState.Disconnecting"/>.
/// </para>
/// <para>Thread-safe: all mutation happens under a single lock.</para>
/// </remarks>
public sealed class VpnStateMachine
{
    private readonly object _gate = new();
    private readonly List<VpnStateChange> _history = new();
    private readonly int _historyLimit;

    /// <summary>Legal target states for each state. Same-state transitions are ignored.</summary>
    private static readonly IReadOnlyDictionary<VpnConnectionState, VpnConnectionState[]> Allowed =
        new Dictionary<VpnConnectionState, VpnConnectionState[]>
        {
            [VpnConnectionState.Disconnected] = new[]
            {
                VpnConnectionState.Preparing,
                VpnConnectionState.Faulted,
            },
            [VpnConnectionState.Preparing] = new[]
            {
                VpnConnectionState.Connecting,
                VpnConnectionState.Disconnecting,
                VpnConnectionState.Disconnected,
                VpnConnectionState.Faulted,
            },
            [VpnConnectionState.Connecting] = new[]
            {
                VpnConnectionState.Connected,
                VpnConnectionState.Degraded,
                VpnConnectionState.Reconnecting,
                VpnConnectionState.Disconnecting,
                VpnConnectionState.Disconnected,
                VpnConnectionState.Faulted,
            },
            [VpnConnectionState.Connected] = new[]
            {
                VpnConnectionState.Degraded,
                VpnConnectionState.Reconnecting,
                VpnConnectionState.Disconnecting,
                VpnConnectionState.Faulted,
            },
            [VpnConnectionState.Degraded] = new[]
            {
                VpnConnectionState.Connected,
                VpnConnectionState.Reconnecting,
                VpnConnectionState.Disconnecting,
                VpnConnectionState.Faulted,
            },
            [VpnConnectionState.Reconnecting] = new[]
            {
                VpnConnectionState.Connected,
                VpnConnectionState.Degraded,
                VpnConnectionState.Disconnecting,
                VpnConnectionState.Disconnected,
                VpnConnectionState.Faulted,
            },
            [VpnConnectionState.Disconnecting] = new[]
            {
                VpnConnectionState.Disconnected,
                VpnConnectionState.Faulted,
            },
            [VpnConnectionState.Faulted] = new[]
            {
                VpnConnectionState.Preparing,
                VpnConnectionState.Connecting,
                VpnConnectionState.Disconnecting,
                VpnConnectionState.Disconnected,
            },
        };

    public VpnStateMachine(VpnConnectionState initial = VpnConnectionState.Disconnected, int historyLimit = 64)
    {
        if (historyLimit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(historyLimit));
        }

        _historyLimit = historyLimit;
        Current = initial;
        Previous = initial;
        _history.Add(new VpnStateChange(initial, initial, "initial", DateTimeOffset.UtcNow));
    }

    /// <summary>Raised after every successful transition, outside the lock.</summary>
    public event EventHandler<VpnStateChange>? StateChanged;

    public VpnConnectionState Current { get; private set; }

    public VpnConnectionState Previous { get; private set; }

    /// <summary>True while connecting / reconnecting / disconnecting.</summary>
    public bool IsBusy
    {
        get
        {
            lock (_gate)
            {
                return Current.IsTransitional();
            }
        }
    }

    /// <summary>
    /// The Kill Switch requirement derived from the current state. This is the single
    /// source of truth used by the connection use case.
    /// </summary>
    public bool RequiresKillSwitch
    {
        get
        {
            lock (_gate)
            {
                return Current.RequiresKillSwitch();
            }
        }
    }

    public IReadOnlyList<VpnStateChange> History
    {
        get
        {
            lock (_gate)
            {
                return _history.ToArray();
            }
        }
    }

    /// <summary>Checks whether <paramref name="next"/> may be entered from the current state.</summary>
    public bool CanTransitionTo(VpnConnectionState next)
    {
        lock (_gate)
        {
            return CanTransitionToCore(next);
        }
    }

    /// <summary>
    /// Attempts a transition. Fails (rather than throwing) when the transition is not
    /// legal, because an illegal transition is reachable from a UI callback racing a
    /// background task and must not crash the app.
    /// </summary>
    public Result<VpnStateChange> TryTransitionTo(
        VpnConnectionState next,
        string reason,
        MyVpnError? error = null)
    {
        VpnStateChange change;

        lock (_gate)
        {
            if (next == Current)
            {
                return Result<VpnStateChange>.Fail(new MyVpnError(
                    ErrorCodes.ConfigInvalid,
                    "error.state.already_in_state",
                    ErrorSeverity.Warning,
                    $"State is already {next}."));
            }

            if (!CanTransitionToCore(next))
            {
                return Result<VpnStateChange>.Fail(new MyVpnError(
                    ErrorCodes.ConfigInvalid,
                    "error.state.illegal_transition",
                    ErrorSeverity.Warning,
                    $"Illegal transition {Current} -> {next} (reason: {reason})."));
            }

            Previous = Current;
            Current = next;
            change = new VpnStateChange(Previous, next, reason, DateTimeOffset.UtcNow, error);
            _history.Add(change);
            if (_history.Count > _historyLimit)
            {
                _history.RemoveRange(0, _history.Count - _historyLimit);
            }
        }

        StateChanged?.Invoke(this, change);
        return Result<VpnStateChange>.Ok(change);
    }

    /// <summary>
    /// Transitions without consulting the table. Reserved for crash recovery, where the
    /// process may have died mid-transition and the recorded state is untrustworthy.
    /// </summary>
    public VpnStateChange ForceTransitionTo(VpnConnectionState next, string reason, MyVpnError? error = null)
    {
        VpnStateChange change;

        lock (_gate)
        {
            Previous = Current;
            Current = next;
            change = new VpnStateChange(Previous, next, $"forced: {reason}", DateTimeOffset.UtcNow, error);
            _history.Add(change);
            if (_history.Count > _historyLimit)
            {
                _history.RemoveRange(0, _history.Count - _historyLimit);
            }
        }

        StateChanged?.Invoke(this, change);
        return change;
    }

    /// <summary>
    /// Whether a new user-initiated connect is meaningful, i.e. we are not already
    /// connected or in the middle of something.
    /// </summary>
    public bool CanStartConnect
    {
        get
        {
            lock (_gate)
            {
                return Current is VpnConnectionState.Disconnected or VpnConnectionState.Faulted;
            }
        }
    }

    private bool CanTransitionToCore(VpnConnectionState next) =>
        Allowed.TryGetValue(Current, out var targets) && Array.IndexOf(targets, next) >= 0;
}
