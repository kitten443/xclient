namespace MyVpn.Core.Domain;

/// <summary>
/// Health measurements used by auto-select.
/// </summary>
/// <remarks>
/// Explicitly NOT ping-only. Requirement: "Не выбирать сервер только по ping."
/// A server with 12 ms latency that drops every fourth handshake and has restarted
/// twice in the last ten minutes is a worse choice than a stable 90 ms server, and
/// the score is designed to reflect that.
/// </remarks>
public sealed record ServerScore
{
    public required Guid ProfileId { get; init; }

    /// <summary>Round-trip time in milliseconds; <c>null</c> when never measured.</summary>
    public double? LatencyMs { get; init; }

    /// <summary>Standard deviation of recent latency samples, in milliseconds.</summary>
    public double? LatencyJitterMs { get; init; }

    /// <summary>Observed packet loss in the range 0..1.</summary>
    public double PacketLoss { get; init; }

    /// <summary>
    /// Successful connects divided by attempts, in the range 0..1.
    /// </summary>
    public double ConnectionSuccessRate { get; init; } = 1.0;

    /// <summary>Number of unexpected core exits observed for this profile.</summary>
    public int UnexpectedDisconnects { get; init; }

    /// <summary>Measured throughput in Mbit/s; <c>null</c> when not measured.</summary>
    public double? DownloadMbps { get; init; }

    public DateTimeOffset LastMeasuredAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>True when nothing has ever been measured for this profile.</summary>
    public bool IsUnmeasured => LatencyMs is null;

    /// <summary>
    /// Score in the range 0..100 where higher is better. Unmeasured profiles get a
    /// neutral mid score rather than 0, so a brand-new subscription is still usable
    /// before the first measurement round completes.
    /// </summary>
    /// <param name="weights">Tunable weights; see <see cref="ScoreWeights"/>.</param>
    public double ComputeScore(ScoreWeights? weights = null)
    {
        var w = weights ?? ScoreWeights.Default;

        if (IsUnmeasured)
        {
            return 50.0;
        }

        // Latency: 0 ms -> 100 points, 400 ms -> 0 points, clamped.
        var latency = Clamp01(1.0 - (LatencyMs!.Value / 400.0)) * 100.0;

        // Jitter: 0 ms -> 100, 150 ms -> 0.
        var jitter = Clamp01(1.0 - ((LatencyJitterMs ?? 0.0) / 150.0)) * 100.0;

        var loss = Clamp01(1.0 - PacketLoss) * 100.0;
        var success = Clamp01(ConnectionSuccessRate) * 100.0;

        // Stability: each unexpected disconnect costs 12 points.
        var stability = Clamp01(1.0 - (UnexpectedDisconnects / 8.0)) * 100.0;

        // Throughput is optional; when absent it must not distort the score, so we
        // redistribute its weight across the other signals.
        double throughput = 0;
        var throughputWeight = w.Throughput;
        if (DownloadMbps is { } mbps)
        {
            throughput = Clamp01(mbps / 200.0) * 100.0;
        }
        else
        {
            throughputWeight = 0;
        }

        var totalWeight = w.Latency + w.Jitter + w.PacketLoss + w.ConnectionSuccess + w.Stability + throughputWeight;
        if (totalWeight <= 0)
        {
            return 50.0;
        }

        var score =
            (latency * w.Latency +
             jitter * w.Jitter +
             loss * w.PacketLoss +
             success * w.ConnectionSuccess +
             stability * w.Stability +
             throughput * throughputWeight) / totalWeight;

        return Math.Round(Math.Clamp(score, 0.0, 100.0), 2);
    }

    /// <summary>Recency decay: measurements older than an hour count for less.</summary>
    public double FreshnessFactor(DateTimeOffset now, TimeSpan halfLife)
    {
        if (halfLife <= TimeSpan.Zero)
        {
            return 1.0;
        }

        var age = now - LastMeasuredAt;
        if (age <= TimeSpan.Zero)
        {
            return 1.0;
        }

        return Math.Pow(0.5, age.TotalSeconds / halfLife.TotalSeconds);
    }

    // Math.Clamp propagates NaN (every comparison against NaN is false), which would
    // leak a NaN score out of the documented 0..100 range. A non-finite sample is
    // treated as the worst possible value instead.
    private static double Clamp01(double value) =>
        double.IsNaN(value) ? 0.0 : Math.Clamp(value, 0.0, 1.0);
}

/// <summary>Weights for <see cref="ServerScore.ComputeScore"/>.</summary>
public sealed record ScoreWeights
{
    public static readonly ScoreWeights Default = new();

    public double Latency { get; init; } = 0.25;

    public double Jitter { get; init; } = 0.10;

    public double PacketLoss { get; init; } = 0.25;

    public double ConnectionSuccess { get; init; } = 0.20;

    public double Stability { get; init; } = 0.20;

    public double Throughput { get; init; } = 0.15;
}
