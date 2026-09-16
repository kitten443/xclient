using MyVpn.Core.Domain;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class ServerScoreTests
{
    private static ServerScore Score(
        double? latency = 50,
        double? jitter = 5,
        double loss = 0,
        double success = 1.0,
        int disconnects = 0,
        double? download = null) => new()
    {
        ProfileId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
        LatencyMs = latency,
        LatencyJitterMs = jitter,
        PacketLoss = loss,
        ConnectionSuccessRate = success,
        UnexpectedDisconnects = disconnects,
        DownloadMbps = download,
    };

    [Fact]
    public void Unmeasured_profile_scores_a_neutral_fifty()
    {
        var score = Score(latency: null);

        score.IsUnmeasured.ShouldBeTrue();
        score.ComputeScore().ShouldBe(50.0);
    }

    [Fact]
    public void Unmeasured_profile_scores_fifty_even_with_awful_other_signals()
    {
        var score = Score(latency: null, jitter: null, loss: 1.0, success: 0.0, disconnects: 8);

        score.ComputeScore().ShouldBe(50.0);
    }

    [Fact]
    public void Fast_clean_profile_beats_a_slow_lossy_one()
    {
        var good = Score(latency: 20, jitter: 1, loss: 0, success: 1.0, disconnects: 0).ComputeScore();
        var bad = Score(latency: 350, jitter: 120, loss: 0.4, success: 0.5, disconnects: 5).ComputeScore();

        good.ShouldBeGreaterThan(bad);
    }

    [Fact]
    public void Packet_loss_one_lowers_the_score()
    {
        var clean = Score(loss: 0).ComputeScore();
        var lossy = Score(loss: 1).ComputeScore();

        lossy.ShouldBeLessThan(clean);
    }

    [Fact]
    public void Packet_loss_reduces_the_score_monotonically()
    {
        var previous = double.MaxValue;
        foreach (var loss in new[] { 0.0, 0.1, 0.25, 0.5, 0.75, 1.0 })
        {
            var score = Score(loss: loss).ComputeScore();
            score.ShouldBeLessThanOrEqualTo(previous);
            previous = score;
        }
    }

    [Fact]
    public void Perfect_metrics_without_throughput_score_one_hundred()
    {
        // Missing throughput must not be treated as zero throughput: it is excluded
        // from the weighted average rather than dragging the score down.
        Score(latency: 0, jitter: 0, loss: 0, success: 1.0, disconnects: 0, download: null)
            .ComputeScore().ShouldBe(100.0);
    }

    [Fact]
    public void Missing_throughput_does_not_change_the_relative_ordering()
    {
        var without = Score(latency: 80, jitter: 20, loss: 0.1, success: 0.9, disconnects: 1, download: null).ComputeScore();
        var withGood = Score(latency: 80, jitter: 20, loss: 0.1, success: 0.9, disconnects: 1, download: 200).ComputeScore();
        var withBad = Score(latency: 80, jitter: 20, loss: 0.1, success: 0.9, disconnects: 1, download: 1).ComputeScore();

        withGood.ShouldBeGreaterThan(without);
        withBad.ShouldBeLessThan(without);
    }

    [Fact]
    public void Score_is_always_within_zero_and_one_hundred()
    {
        var cases = new[]
        {
            Score(latency: -100, jitter: -50, loss: -1, success: 5, disconnects: -3, download: 100000),
            Score(latency: 100000, jitter: 100000, loss: 100, success: -5, disconnects: 1000, download: -100),
            Score(latency: 0, jitter: 0, loss: 0, success: 0, disconnects: 0, download: 0),
            Score(latency: 400, jitter: 150, loss: 1, success: 0, disconnects: 8, download: 0),
            Score(latency: double.MaxValue, jitter: double.MaxValue, loss: double.MaxValue, success: double.MinValue),
            Score(latency: double.NaN, jitter: double.NaN),
        };

        foreach (var score in cases)
        {
            var value = score.ComputeScore();
            value.ShouldBeInRange(0.0, 100.0);
        }
    }

    [Fact]
    public void Custom_weights_are_honoured()
    {
        var weights = new ScoreWeights
        {
            Latency = 1.0,
            Jitter = 0,
            PacketLoss = 0,
            ConnectionSuccess = 0,
            Stability = 0,
            Throughput = 0,
        };

        // 0 ms latency -> 100, 200 ms -> 50.
        Score(latency: 0, jitter: null).ComputeScore(weights).ShouldBe(100.0);
        Score(latency: 200, jitter: null).ComputeScore(weights).ShouldBe(50.0);
    }

    [Fact]
    public void All_zero_weights_yield_the_neutral_score()
    {
        var weights = new ScoreWeights
        {
            Latency = 0,
            Jitter = 0,
            PacketLoss = 0,
            ConnectionSuccess = 0,
            Stability = 0,
            Throughput = 0,
        };

        Score().ComputeScore(weights).ShouldBe(50.0);
    }

    [Fact]
    public void Default_weights_are_the_documented_values()
    {
        var weights = ScoreWeights.Default;

        weights.Latency.ShouldBe(0.25);
        weights.Jitter.ShouldBe(0.10);
        weights.PacketLoss.ShouldBe(0.25);
        weights.ConnectionSuccess.ShouldBe(0.20);
        weights.Stability.ShouldBe(0.20);
        weights.Throughput.ShouldBe(0.15);
    }

    [Fact]
    public void FreshnessFactor_halves_at_the_half_life()
    {
        var now = DateTimeOffset.UnixEpoch.AddDays(10_000);
        var score = Score() with { LastMeasuredAt = now - TimeSpan.FromHours(1) };

        score.FreshnessFactor(now, TimeSpan.FromHours(1)).ShouldBe(0.5, 1e-9);
    }

    [Fact]
    public void FreshnessFactor_quarters_at_two_half_lives()
    {
        var now = DateTimeOffset.UnixEpoch.AddDays(10_000);
        var score = Score() with { LastMeasuredAt = now - TimeSpan.FromHours(2) };

        score.FreshnessFactor(now, TimeSpan.FromHours(1)).ShouldBe(0.25, 1e-9);
    }

    [Fact]
    public void FreshnessFactor_is_one_for_a_fresh_measurement()
    {
        var now = DateTimeOffset.UnixEpoch.AddDays(10_000);
        var score = Score() with { LastMeasuredAt = now };

        score.FreshnessFactor(now, TimeSpan.FromHours(1)).ShouldBe(1.0);
    }

    [Fact]
    public void FreshnessFactor_is_one_for_a_future_measurement()
    {
        var now = DateTimeOffset.UnixEpoch.AddDays(10_000);
        var score = Score() with { LastMeasuredAt = now + TimeSpan.FromHours(5) };

        score.FreshnessFactor(now, TimeSpan.FromHours(1)).ShouldBe(1.0);
    }

    [Fact]
    public void Non_positive_half_life_disables_decay()
    {
        var now = DateTimeOffset.UnixEpoch.AddDays(10_000);
        var score = Score() with { LastMeasuredAt = now - TimeSpan.FromDays(5) };

        score.FreshnessFactor(now, TimeSpan.Zero).ShouldBe(1.0);
        score.FreshnessFactor(now, TimeSpan.FromSeconds(-1)).ShouldBe(1.0);
    }

    [Fact]
    public void More_unexpected_disconnects_lower_the_score()
    {
        var stable = Score(disconnects: 0).ComputeScore();
        var flaky = Score(disconnects: 4).ComputeScore();

        flaky.ShouldBeLessThan(stable);
    }

    [Fact]
    public void Lower_connection_success_rate_lowers_the_score()
    {
        Score(success: 1.0).ComputeScore().ShouldBeGreaterThan(Score(success: 0.2).ComputeScore());
    }

    [Fact]
    public void Default_profile_id_is_required_and_settable()
    {
        var id = Guid.NewGuid();
        var score = Score() with { ProfileId = id };

        score.ProfileId.ShouldBe(id);
        score.LastMeasuredAt.ShouldNotBe(default);
    }
}
