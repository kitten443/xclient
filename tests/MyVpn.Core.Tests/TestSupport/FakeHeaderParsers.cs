using MyVpn.Core.Results;
using MyVpn.Core.Subscriptions;

namespace MyVpn.Core.Tests;

/// <summary>A parser that always throws, used to prove registry isolation.</summary>
internal sealed class ThrowingHeaderParser : ISubscriptionHeaderParser
{
    public string Id => "fake-throwing";

    public int Version => 1;

    public int Priority => 1000;

    public HeaderApplyGate Gate => HeaderApplyGate.Auto;

    public IReadOnlyCollection<string> HeaderNames { get; } = new[] { "x-fake-throw" };

    public int MaxValueLength => 1024;

    public bool CanParse(string headerName) =>
        headerName.Equals("x-fake-throw", StringComparison.OrdinalIgnoreCase);

    public ParseResult Parse(HeaderParseContext context) =>
        throw new InvalidOperationException("deliberate test failure");
}

/// <summary>
/// A parser that emits an applicable change for a header whose catalog gate is
/// <see cref="HeaderApplyGate.Auto"/>, used to prove the registry enforces gates
/// rather than trusting the parser.
/// </summary>
internal sealed class GateViolatingHeaderParser : ISubscriptionHeaderParser
{
    public string Id => "fake-gate-violator";

    public int Version => 1;

    public int Priority => 1001;

    public HeaderApplyGate Gate => HeaderApplyGate.RequiresConfirmation;

    public IReadOnlyCollection<string> HeaderNames { get; } = new[] { "x-fake-gate" };

    public int MaxValueLength => 1024;

    public bool CanParse(string headerName) =>
        headerName.Equals("x-fake-gate", StringComparison.OrdinalIgnoreCase);

    public ParseResult Parse(HeaderParseContext context) => new()
    {
        PendingChanges = new[]
        {
            new PendingChange
            {
                Id = "profile-title",
                HeaderName = "profile-title",
                Value = "true",
                ValueFingerprint = "fingerprint",
                Risk = ChangeRisk.High,
                LabelKey = "fake.label",
                ConsentToken = new string('0', 64),
            },
        },
    };
}

/// <summary>A parser that emits a change for a completely unknown header.</summary>
internal sealed class UnknownHeaderChangeParser : ISubscriptionHeaderParser
{
    public string Id => "fake-unknown-change";

    public int Version => 1;

    public int Priority => 1002;

    public HeaderApplyGate Gate => HeaderApplyGate.RequiresConfirmation;

    public IReadOnlyCollection<string> HeaderNames { get; } = new[] { "x-fake-unknown" };

    public int MaxValueLength => 1024;

    public bool CanParse(string headerName) =>
        headerName.Equals("x-fake-unknown", StringComparison.OrdinalIgnoreCase);

    public ParseResult Parse(HeaderParseContext context) => new()
    {
        PendingChanges = new[]
        {
            new PendingChange
            {
                Id = "x-fake-unknown",
                HeaderName = "x-fake-unknown",
                Value = "true",
                ValueFingerprint = "fingerprint",
                Risk = ChangeRisk.High,
                LabelKey = "fake.label",
                ConsentToken = new string('1', 64),
            },
        },
    };
}
