using MyVpn.Core.Domain;
using MyVpn.Core.Results;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class VpnStateMachineTests
{
    private static readonly VpnConnectionState[] AllStates = Enum.GetValues<VpnConnectionState>();

    /// <summary>
    /// The transition table restated independently of the implementation, derived
    /// from the documented lifecycle. Any divergence is a test failure.
    /// </summary>
    private static readonly Dictionary<VpnConnectionState, VpnConnectionState[]> ExpectedAllowed = new()
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

    [Fact]
    public void Initial_state_is_the_requested_state()
    {
        var machine = new VpnStateMachine(VpnConnectionState.Connecting);

        machine.Current.ShouldBe(VpnConnectionState.Connecting);
        machine.Previous.ShouldBe(VpnConnectionState.Connecting);
        machine.History.Count.ShouldBe(1);
        machine.History[0].Reason.ShouldBe("initial");
    }

    [Fact]
    public void Constructor_rejects_a_non_positive_history_limit()
    {
        Should.Throw<ArgumentOutOfRangeException>(() => new VpnStateMachine(historyLimit: 0));
        Should.Throw<ArgumentOutOfRangeException>(() => new VpnStateMachine(historyLimit: -1));
    }

    [Fact]
    public void Every_transition_matches_the_expected_table()
    {
        foreach (var from in AllStates)
        {
            foreach (var to in AllStates)
            {
                var expected = to != from && ExpectedAllowed[from].Contains(to);

                var machine = new VpnStateMachine(from);
                var result = machine.TryTransitionTo(to, "matrix");

                result.IsSuccess.ShouldBe(
                    expected,
                    $"transition {from} -> {to} should {(expected ? "succeed" : "fail")}");

                if (expected)
                {
                    machine.Current.ShouldBe(to);
                    machine.Previous.ShouldBe(from);
                }
                else
                {
                    machine.Current.ShouldBe(from);
                    result.Error.ShouldNotBeNull();
                }
            }
        }
    }

    [Fact]
    public void CanTransitionTo_agrees_with_the_expected_table()
    {
        foreach (var from in AllStates)
        {
            foreach (var to in AllStates)
            {
                var machine = new VpnStateMachine(from);
                machine.CanTransitionTo(to).ShouldBe(to != from && ExpectedAllowed[from].Contains(to));
            }
        }
    }

    [Fact]
    public void Same_state_transition_fails_and_does_not_throw()
    {
        foreach (var state in AllStates)
        {
            var machine = new VpnStateMachine(state);

            var result = machine.TryTransitionTo(state, "repeat");

            result.IsFailure.ShouldBeTrue();
            result.Error!.MessageKey.ShouldBe("error.state.already_in_state");
            result.Error!.Severity.ShouldBe(ErrorSeverity.Warning);
            machine.Current.ShouldBe(state);
            machine.History.Count.ShouldBe(1);
        }
    }

    [Fact]
    public void Illegal_transition_returns_a_failure_rather_than_throwing()
    {
        var machine = new VpnStateMachine(VpnConnectionState.Disconnected);

        var result = machine.TryTransitionTo(VpnConnectionState.Connected, "skip-ahead");

        result.IsFailure.ShouldBeTrue();
        result.Error!.MessageKey.ShouldBe("error.state.illegal_transition");
        result.Error.TechnicalDetail.ShouldNotBeNull();
        result.Error!.TechnicalDetail!.ShouldContain("Disconnected -> Connected");
    }

    [Fact]
    public void Connected_to_Disconnected_is_impossible()
    {
        var machine = new VpnStateMachine(VpnConnectionState.Connected);

        machine.CanTransitionTo(VpnConnectionState.Disconnected).ShouldBeFalse();
        var result = machine.TryTransitionTo(VpnConnectionState.Disconnected, "direct teardown");

        result.IsFailure.ShouldBeTrue();
        machine.Current.ShouldBe(VpnConnectionState.Connected);

        // The only legal way out is through Disconnecting.
        machine.TryTransitionTo(VpnConnectionState.Disconnecting, "teardown").IsSuccess.ShouldBeTrue();
        machine.TryTransitionTo(VpnConnectionState.Disconnected, "teardown").IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void RequiresKillSwitch_is_true_in_every_protected_state()
    {
        foreach (var state in new[]
                 {
                     VpnConnectionState.Connected,
                     VpnConnectionState.Degraded,
                     VpnConnectionState.Reconnecting,
                     VpnConnectionState.Faulted,
                     VpnConnectionState.Disconnecting,
                 })
        {
            new VpnStateMachine(state).RequiresKillSwitch.ShouldBeTrue($"{state} must keep the Kill Switch");
            state.RequiresKillSwitch().ShouldBeTrue();
        }
    }

    [Fact]
    public void RequiresKillSwitch_is_false_when_there_is_nothing_to_protect()
    {
        foreach (var state in new[]
                 {
                     VpnConnectionState.Disconnected,
                     VpnConnectionState.Preparing,
                     VpnConnectionState.Connecting,
                 })
        {
            new VpnStateMachine(state).RequiresKillSwitch.ShouldBeFalse($"{state} must not keep the Kill Switch");
            state.RequiresKillSwitch().ShouldBeFalse();
        }
    }

    [Fact]
    public void Faulted_keeps_the_kill_switch_engaged()
    {
        // Failing open is never acceptable.
        VpnConnectionState.Faulted.RequiresKillSwitch().ShouldBeTrue();
        VpnConnectionState.Disconnected.RequiresKillSwitch().ShouldBeFalse();
    }

    [Fact]
    public void StateChanged_fires_once_per_successful_transition()
    {
        var machine = new VpnStateMachine();
        var observed = new List<VpnStateChange>();
        machine.StateChanged += (_, change) => observed.Add(change);

        machine.TryTransitionTo(VpnConnectionState.Preparing, "go").IsSuccess.ShouldBeTrue();
        machine.TryTransitionTo(VpnConnectionState.Connected, "illegal").IsFailure.ShouldBeTrue();
        machine.TryTransitionTo(VpnConnectionState.Connecting, "go").IsSuccess.ShouldBeTrue();

        observed.Count.ShouldBe(2);
        observed[0].From.ShouldBe(VpnConnectionState.Disconnected);
        observed[0].To.ShouldBe(VpnConnectionState.Preparing);
        observed[0].Reason.ShouldBe("go");
        observed[1].From.ShouldBe(VpnConnectionState.Preparing);
        observed[1].To.ShouldBe(VpnConnectionState.Connecting);
    }

    [Fact]
    public void StateChanged_does_not_fire_on_a_refused_transition()
    {
        var machine = new VpnStateMachine(VpnConnectionState.Connected);
        var fired = 0;
        machine.StateChanged += (_, _) => fired++;

        machine.TryTransitionTo(VpnConnectionState.Disconnected, "illegal");
        machine.TryTransitionTo(VpnConnectionState.Connected, "same");

        fired.ShouldBe(0);
        machine.Current.ShouldBe(VpnConnectionState.Connected);
    }

    [Fact]
    public void StateChanged_carries_the_error_when_one_is_supplied()
    {
        var machine = new VpnStateMachine();
        VpnStateChange? observed = null;
        machine.StateChanged += (_, change) => observed = change;

        var error = new MyVpnError(ErrorCodes.XrayStartFailed, "error.xray.start_failed");
        machine.TryTransitionTo(VpnConnectionState.Preparing, "start", error);

        observed.ShouldNotBeNull();
        observed!.Error.ShouldBe(error);
    }

    [Fact]
    public void History_is_bounded_by_the_history_limit()
    {
        var machine = new VpnStateMachine(historyLimit: 3);

        machine.TryTransitionTo(VpnConnectionState.Preparing, "1");
        machine.TryTransitionTo(VpnConnectionState.Connecting, "2");
        machine.TryTransitionTo(VpnConnectionState.Connected, "3");
        machine.TryTransitionTo(VpnConnectionState.Degraded, "4");
        machine.TryTransitionTo(VpnConnectionState.Connected, "5");

        machine.History.Count.ShouldBe(3);
        machine.History.Select(h => h.Reason).ShouldBe(new[] { "3", "4", "5" });
    }

    [Fact]
    public void History_never_exceeds_the_limit_even_with_force_transitions()
    {
        var machine = new VpnStateMachine(historyLimit: 2);

        for (var i = 0; i < 10; i++)
        {
            machine.ForceTransitionTo(VpnConnectionState.Connected, $"force {i}");
        }

        machine.History.Count.ShouldBe(2);
    }

    [Fact]
    public void ForceTransitionTo_bypasses_the_table()
    {
        var machine = new VpnStateMachine(VpnConnectionState.Disconnected);

        var change = machine.ForceTransitionTo(VpnConnectionState.Connected, "crash recovery");

        machine.Current.ShouldBe(VpnConnectionState.Connected);
        machine.Previous.ShouldBe(VpnConnectionState.Disconnected);
        change.From.ShouldBe(VpnConnectionState.Disconnected);
        change.To.ShouldBe(VpnConnectionState.Connected);
        change.Reason.ShouldBe("forced: crash recovery");
    }

    [Fact]
    public void ForceTransitionTo_fires_StateChanged_and_appends_history()
    {
        var machine = new VpnStateMachine();
        var fired = 0;
        machine.StateChanged += (_, _) => fired++;

        machine.ForceTransitionTo(VpnConnectionState.Faulted, "recovery");

        fired.ShouldBe(1);
        machine.History.Count.ShouldBe(2);
        machine.History[1].To.ShouldBe(VpnConnectionState.Faulted);
    }

    [Fact]
    public void IsBusy_is_true_only_in_transitional_states()
    {
        foreach (var state in AllStates)
        {
            var expected = state is VpnConnectionState.Preparing
                or VpnConnectionState.Connecting
                or VpnConnectionState.Reconnecting
                or VpnConnectionState.Disconnecting;

            new VpnStateMachine(state).IsBusy.ShouldBe(expected, $"{state}");
            state.IsTransitional().ShouldBe(expected, $"{state}");
        }
    }

    [Fact]
    public void IsTunnelUp_covers_connected_degraded_and_reconnecting()
    {
        foreach (var state in AllStates)
        {
            var expected = state is VpnConnectionState.Connected
                or VpnConnectionState.Degraded
                or VpnConnectionState.Reconnecting;

            state.IsTunnelUp().ShouldBe(expected, $"{state}");
        }
    }

    [Fact]
    public void CanStartConnect_is_true_only_when_idle_or_faulted()
    {
        foreach (var state in AllStates)
        {
            var expected = state is VpnConnectionState.Disconnected or VpnConnectionState.Faulted;
            new VpnStateMachine(state).CanStartConnect.ShouldBe(expected, $"{state}");
        }
    }

    [Fact]
    public void History_snapshot_is_detached_from_later_mutation()
    {
        var machine = new VpnStateMachine();
        var snapshot = machine.History;

        machine.TryTransitionTo(VpnConnectionState.Preparing, "go");

        snapshot.Count.ShouldBe(1);
        machine.History.Count.ShouldBe(2);
    }
}
