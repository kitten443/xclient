using MyVpn.Application.Abstractions;
using MyVpn.Application.Connection;
using MyVpn.Core.Domain;
using MyVpn.Core.Parsing;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Core.Subscriptions;
using MyVpn.UI.ViewModels;

namespace MyVpn.Core.Tests.UI;

/// <summary>
/// A scriptable <see cref="IVpnSession"/>.
/// </summary>
/// <remarks>
/// The point of these tests is the view model's behaviour, not the connect sequence, which has its
/// own coverage. This fake lets a test put the session into an exact state — including a state
/// that failed verification — and assert what the UI shows.
/// </remarks>
internal sealed class FakeVpnSession : IVpnSession
{
    private readonly object _gate = new();

    public VpnConnectionState State { get; private set; } = VpnConnectionState.Disconnected;

    public event EventHandler<VpnStateChange>? StateChanged;

    public event EventHandler<ConnectionSnapshot>? SnapshotChanged;

    public ConnectionSnapshot Snapshot { get; private set; } = new() { State = VpnConnectionState.Disconnected };

    /// <summary>Requests the fake was asked to connect with.</summary>
    public List<ConnectRequest> ConnectRequests { get; } = new();

    /// <summary>Number of disconnect calls.</summary>
    public int DisconnectCount { get; private set; }

    /// <summary>When set, a connect waits on this before returning.</summary>
    public TaskCompletionSource? ConnectGate { get; set; }

    /// <summary>Result the next connect returns. <c>null</c> means success.</summary>
    public MyVpnError? ConnectError { get; set; }

    /// <summary>Snapshot a successful connect publishes.</summary>
    public ConnectionSnapshot? ConnectSnapshot { get; set; }

    /// <summary>Result a disconnect returns. <c>null</c> means success.</summary>
    public MyVpnError? DisconnectError { get; set; }

    public async Task<Result<ConnectionSnapshot>> ConnectAsync(
        ConnectRequest request,
        CancellationToken cancellationToken)
    {
        ConnectRequests.Add(request);

        // The real session refuses a concurrent call rather than queueing it. Mirroring that here
        // is what lets a test prove the UI never reaches the point of provoking the refusal.
        if (ConnectRequests.Count > 1 && ConnectGate is { Task.IsCompleted: false })
        {
            return Result<ConnectionSnapshot>.Fail(new MyVpnError(
                ErrorCodes.ConfigInvalid,
                "error.session.busy",
                ErrorSeverity.Warning,
                "A connection operation is already in progress."));
        }

        SetState(VpnConnectionState.Preparing);
        SetState(VpnConnectionState.Connecting);

        if (ConnectGate is { } gate)
        {
            await gate.Task.ConfigureAwait(false);
        }

        if (ConnectError is { } error)
        {
            SetState(VpnConnectionState.Disconnecting);
            SetState(VpnConnectionState.Disconnected);

            Snapshot = Snapshot with
            {
                LastError = error,
                ProfileId = request.Profile.Id,
                ProfileName = request.Profile.DisplayName,
                Verification = null,
                ConnectedAt = null,
            };

            SnapshotChanged?.Invoke(this, Snapshot);
            return Result<ConnectionSnapshot>.Fail(error);
        }

        Snapshot = ConnectSnapshot ?? new ConnectionSnapshot
        {
            State = VpnConnectionState.Connected,
            ProfileId = request.Profile.Id,
            ProfileName = request.Profile.DisplayName,
            CoreVersion = "1.8.0",
            ConnectedAt = DateTimeOffset.UtcNow,
        };

        SetState(VpnConnectionState.Connected);
        SnapshotChanged?.Invoke(this, Snapshot);
        return Result<ConnectionSnapshot>.Ok(Snapshot);
    }

    public Task<Result> DisconnectAsync(CancellationToken cancellationToken)
    {
        DisconnectCount++;

        if (DisconnectError is { } error)
        {
            return Task.FromResult(Result.Fail(error));
        }

        SetState(VpnConnectionState.Disconnecting);
        Snapshot = Snapshot with { Verification = null, ConnectedAt = null, ProfileName = null };
        SetState(VpnConnectionState.Disconnected);
        SnapshotChanged?.Invoke(this, Snapshot);
        return Task.FromResult(Result.Ok());
    }

    /// <summary>Publishes a snapshot directly, for tests about rendering rather than connecting.</summary>
    public void Publish(ConnectionSnapshot snapshot)
    {
        Snapshot = snapshot;
        State = snapshot.State;
        SnapshotChanged?.Invoke(this, snapshot);
        StateChanged?.Invoke(this, new VpnStateChange(State, snapshot.State, "test", DateTimeOffset.UtcNow));
    }

    private void SetState(VpnConnectionState next)
    {
        VpnConnectionState previous;

        // The new value is committed before the event is raised, because the view model's handler
        // reads the session's own properties: a handler that ran first would render the old state.
        lock (_gate)
        {
            previous = State;
            State = next;
            Snapshot = Snapshot with { State = next };
        }

        StateChanged?.Invoke(this, new VpnStateChange(previous, next, "test", DateTimeOffset.UtcNow));
        SnapshotChanged?.Invoke(this, Snapshot);
    }
}

/// <summary>A subscription importer that returns a canned result.</summary>
internal sealed class FakeSubscriptionImporter : ISubscriptionImporter
{
    public SubscriptionImportResult? Next { get; set; }

    public MyVpnError? Error { get; set; }

    public List<string> RequestedUrls { get; } = new();

    public Task<Result<SubscriptionImportResult>> ImportAsync(
        string url,
        SubscriptionSettings settings,
        CancellationToken cancellationToken)
    {
        RequestedUrls.Add(url);

        return Task.FromResult(Error is { } error
            ? Result<SubscriptionImportResult>.Fail(error)
            : Result<SubscriptionImportResult>.Ok(Next ?? Empty));
    }

    public static SubscriptionImportResult Empty => new()
    {
        SubscriptionUrl = "https://example.invalid/sub",
        Profiles = Array.Empty<ServerProfile>(),
        Failures = Array.Empty<ShareLinkFailure>(),
        RefusedHeaders = Array.Empty<string>(),
        PendingChanges = Array.Empty<PendingChange>(),
        Errors = Array.Empty<MyVpnError>(),
    };
}

/// <summary>An in-memory settings store.</summary>
internal sealed class FakeUserSettingsStore : IUserSettingsStore
{
    public AppSettings Settings { get; set; } = new();

    public IReadOnlyList<ServerProfile> Profiles { get; set; } = Array.Empty<ServerProfile>();

    public string? SubscriptionUrl { get; set; }

    public string? CoreBinaryPath { get; set; }

    public bool IsDirty { get; private set; }

    public int SaveCount { get; private set; }

    public void MarkDirty() => IsDirty = true;

    public Task<UserState> LoadAsync(CancellationToken cancellationToken) => Task.FromResult(new UserState
    {
        Settings = Settings,
        Profiles = Profiles,
        SubscriptionUrl = SubscriptionUrl,
        CoreBinaryPath = CoreBinaryPath,
    });

    public Task SaveAsync(CancellationToken cancellationToken)
    {
        SaveCount++;
        IsDirty = false;
        return Task.CompletedTask;
    }
}

/// <summary>A minimal, well-formed profile for tests.</summary>
internal static class TestProfiles
{
    public static ServerProfile Create(string name = "Test server", string address = "203.0.113.7") => new()
    {
        DisplayName = name,
        Address = address,
        Port = 443,
        Protocol = ProxyProtocol.Vless,
        UserId = "11111111-2222-3333-4444-555555555555",
        Security = SecurityKind.Tls,
    };
}
