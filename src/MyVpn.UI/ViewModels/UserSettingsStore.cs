using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using MyVpn.Application.Abstractions;
using MyVpn.Core.Domain;
using MyVpn.Core.Settings;

namespace MyVpn.UI.ViewModels;

/// <summary>Everything the UI persists between runs.</summary>
public sealed record UserState
{
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public const int CurrentSchemaVersion = 1;

    public AppSettings Settings { get; init; } = new();

    public IReadOnlyList<ServerProfile> Profiles { get; init; } = Array.Empty<ServerProfile>();

    /// <summary>
    /// The user's subscription URL, verbatim.
    /// </summary>
    /// <remarks>
    /// Kept because it is the user's own input and would otherwise have to be retyped on every
    /// launch. It carries a provider token, so it is written to a user-only file and is
    /// <i>never</i> rendered: the view models display a masked form (see
    /// <see cref="SubscriptionImportViewModel"/>), and nothing logs it.
    /// </remarks>
    public string? SubscriptionUrl { get; init; }

    /// <summary>Explicitly chosen core binary, or <c>null</c> to use the search order.</summary>
    public string? CoreBinaryPath { get; init; }
}

/// <summary>Reads and writes the UI's own persisted state.</summary>
/// <remarks>
/// A port so the view models can be tested without touching the filesystem. The implementation
/// is deliberately trivial and local: nothing in this store performs I/O that could announce the
/// user's presence to anything, and nothing in it can mutate the network.
/// </remarks>
public interface IUserSettingsStore
{
    /// <summary>Current in-memory settings. Mutating this does not persist until <see cref="SaveAsync"/>.</summary>
    AppSettings Settings { get; set; }

    IReadOnlyList<ServerProfile> Profiles { get; set; }

    string? SubscriptionUrl { get; set; }

    string? CoreBinaryPath { get; set; }

    /// <summary>True when something changed since the last successful save.</summary>
    bool IsDirty { get; }

    /// <summary>Marks the state dirty. The caller decides when to <see cref="SaveAsync"/>.</summary>
    void MarkDirty();

    Task<UserState> LoadAsync(CancellationToken cancellationToken);

    Task SaveAsync(CancellationToken cancellationToken);
}

/// <summary>
/// JSON-backed persistence of the UI's own state.
/// </summary>
/// <remarks>
/// <para>
/// The file is written through <see cref="IConfigFileStore.WriteAtomicAsync"/>, which stages to a
/// sibling temporary file, restricts it to the owner and renames it into place. That matters
/// here: the file holds the subscription URL, which is a credential, so it must never be
/// world-readable and a crash mid-write must not leave a truncated copy that the next launch
/// fails to parse.
/// </para>
/// <para>
/// A corrupt or unreadable file is a warning, not a startup failure. The user's next action is to
/// re-import their subscription, which is recoverable; refusing to start is not.
/// </para>
/// </remarks>
public sealed class JsonUserSettingsStore : IUserSettingsStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly IAppPaths _paths;
    private readonly IConfigFileStore _files;
    private readonly ILogger<JsonUserSettingsStore> _logger;

    public JsonUserSettingsStore(
        IAppPaths paths,
        IConfigFileStore files,
        ILogger<JsonUserSettingsStore> logger)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _files = files ?? throw new ArgumentNullException(nameof(files));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public AppSettings Settings { get; set; } = new();

    public IReadOnlyList<ServerProfile> Profiles { get; set; } = Array.Empty<ServerProfile>();

    public string? SubscriptionUrl { get; set; }

    public string? CoreBinaryPath { get; set; }

    /// <summary>Marks the state dirty. The owner calls <see cref="SaveAsync"/>.</summary>
    public void MarkDirty() => IsDirty = true;

    /// <summary>True when something changed since the last successful save.</summary>
    public bool IsDirty { get; private set; }

    /// <summary>Path of the state file. Under the per-user state root, never beside the binary.</summary>
    public string StatePath => Path.Combine(_paths.StateDirectory, "ui-state.json");

    public async Task<UserState> LoadAsync(CancellationToken cancellationToken)
    {
        if (!_files.Exists(StatePath))
        {
            Settings = new AppSettings();
            Profiles = Array.Empty<ServerProfile>();
            return new UserState { Settings = Settings };
        }

        var read = await _files.ReadAsync(StatePath, cancellationToken).ConfigureAwait(false);
        if (read.IsFailure)
        {
            _logger.LogWarning("Could not read the UI state file; starting from defaults: {Error}", read.Error);
            Settings = new AppSettings();
            Profiles = Array.Empty<ServerProfile>();
            return new UserState { Settings = Settings };
        }

        UserState state;
        try
        {
            state = JsonSerializer.Deserialize<UserState>(read.Value, SerializerOptions) ?? new UserState();
        }
        catch (JsonException ex)
        {
            // Deliberately not fatal, and deliberately not deleted: the file is the only copy of
            // the user's profile list, so it is preserved for manual recovery rather than
            // silently overwritten with defaults.
            _logger.LogWarning(ex, "The UI state file is not valid JSON; starting from defaults.");
            state = new UserState();
        }

        // Normalize rather than trust: a file written by a newer build can carry out-of-range
        // values, and the connect path validates settings it is handed. The null checks are for
        // a hand-edited file: the deserializer honours an explicit null even for a non-nullable
        // property, and a null settings object would otherwise surface as a NullReference later.
        var settings = (state.Settings ?? new AppSettings()).Normalize();
        IReadOnlyList<ServerProfile>? persistedProfiles = state.Profiles;
        var profiles = persistedProfiles ?? Array.Empty<ServerProfile>();

        Settings = settings;
        Profiles = profiles;
        SubscriptionUrl = state.SubscriptionUrl;
        CoreBinaryPath = state.CoreBinaryPath;

        return state with { Settings = settings, Profiles = profiles };
    }

    public async Task SaveAsync(CancellationToken cancellationToken)
    {
        var state = new UserState
        {
            Settings = Settings,
            Profiles = Profiles,
            SubscriptionUrl = SubscriptionUrl,
            CoreBinaryPath = CoreBinaryPath,
        };

        var payload = JsonSerializer.Serialize(state, SerializerOptions);

        var written = await _files.WriteAtomicAsync(StatePath, payload, cancellationToken).ConfigureAwait(false);
        if (written.IsFailure)
        {
            // Left dirty on purpose: the caller may retry, and claiming a successful save that
            // did not happen is how a user loses their profile list.
            _logger.LogWarning("Could not persist the UI state: {Error}", written.Error);
            return;
        }

        IsDirty = false;
    }
}
