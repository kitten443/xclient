using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Core.Subscriptions;
using MyVpn.UI.Localization;

namespace MyVpn.UI.ViewModels;

/// <summary>
/// One confirmation-gated change from a subscription, waiting for the user.
/// </summary>
/// <remarks>
/// The <see cref="ConsentToken"/> is carried through unchanged and echoed back when the user
/// consents. It binds the consent to the exact <c>(subscription, header, value)</c> triple, so a
/// provider that presents a harmless request, obtains a "yes", and then changes the value on the
/// next refresh does not get the change applied.
/// </remarks>
public sealed class PendingChangeRow : ObservableObject
{
    private string _label = string.Empty;
    private string _description = string.Empty;
    private string _outcome = string.Empty;

    public PendingChangeRow(PendingChange change)
    {
        Change = change ?? throw new ArgumentNullException(nameof(change));
    }

    public PendingChange Change { get; }

    public string HeaderName => Change.HeaderName;

    /// <summary>Consent token for this exact value.</summary>
    public string ConsentToken => Change.ConsentToken;

    /// <summary>Localized header name.</summary>
    public string Label
    {
        get => _label;
        private set => SetField(ref _label, value);
    }

    /// <summary>Localized explanation of what accepting would do.</summary>
    public string Description
    {
        get => _description;
        private set => SetField(ref _description, value);
    }

    /// <summary>Localized note explaining mobile-only applicability, when relevant.</summary>
    public string MobileNote { get; private set; } = string.Empty;

    public bool IsMobileOnly => Change.MobileOnly;

    /// <summary>Value the user is being asked to accept. Provider-supplied, shown for consent.</summary>
    public string Value => Change.Value;

    public string Risk => Change.Risk.ToString();

    /// <summary>Result of this change after consent was given, or empty while it is pending.</summary>
    public string Outcome
    {
        get => _outcome;
        set
        {
            if (SetField(ref _outcome, value))
            {
                OnPropertyChanged(nameof(HasOutcome));
            }
        }
    }

    public bool HasOutcome => _outcome.Length > 0;

    public void Localize(LocalizationService localization)
    {
        ArgumentNullException.ThrowIfNull(localization);

        Label = localization.Get(Change.LabelKey);
        Description = Change.DescriptionKey is { } key ? localization.Get(key) : string.Empty;
        MobileNote = Change.MobileOnly ? localization.Get("header.per_app_mode") : string.Empty;
    }
}

/// <summary>
/// The subscription import screen, including the three-gate presentation from ADR-0008.
/// </summary>
/// <remarks>
/// <para>
/// The three gates are visible here rather than collapsed into "import":
/// </para>
/// <list type="number">
/// <item><description>
/// <b>Gate A (auto)</b> — the provider title and announcement. Display metadata only; it cannot
/// change how traffic flows, so it is applied without asking.
/// </description></item>
/// <item><description>
/// <b>Gate B (consent)</b> — collected into <see cref="PendingChanges"/> and shown as a list the
/// user must act on. Nothing in this class writes a gated value into settings; the
/// <see cref="ApplyConsentedChangesCommand"/> builds a <i>proposed</i> snapshot from the rows the
/// user has explicitly marked and hands it to the owner, which is the only thing that persists.
/// </description></item>
/// <item><description>
/// <b>Gate C (refused)</b> — <see cref="RefusedHeaders"/> is rendered as a notice and never
/// applied and never offered for acceptance. A provider-supplied routing or tunnel config is
/// exactly the arbitrary-config-injection case the gate exists for.
/// </description></item>
/// </list>
/// <para>
/// <b>The URL is never rendered.</b> It carries a provider token, so the screen shows a masked
/// form and the raw value stays in this class and in the persisted state file (owner-only
/// permissions) only.
/// </para>
/// </remarks>
public sealed class SubscriptionImportViewModel : ObservableObject
{
    private readonly ISubscriptionImporter _importer;
    private readonly LocalizationService _localization;
    private readonly IUserSettingsStore _store;

    private string _url = string.Empty;
    private string _maskedUrlHint = string.Empty;
    private string _status = string.Empty;
    private string _providerTitle = string.Empty;
    private string _announce = string.Empty;
    private string _refusedNotice = string.Empty;
    private string _failureNotice = string.Empty;
    private string _error = string.Empty;
    private int _profileCount;
    private int _failureCount;
    private bool _imported;
    private bool _busy;
    private SubscriptionSettings _subscriptionSettings = new();

    public SubscriptionImportViewModel(
        ISubscriptionImporter importer,
        IUserSettingsStore store,
        LocalizationService localization)
    {
        _importer = importer ?? throw new ArgumentNullException(nameof(importer));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _localization = localization ?? throw new ArgumentNullException(nameof(localization));

        _subscriptionSettings = store.Settings.Subscriptions;

        _localization.LanguageChanged += (_, _) => Relocalize();

        ImportCommand = new AsyncRelayCommand(ImportAsync, () => !_busy && HasUrl);
        ApplyConsentedChangesCommand = new RelayCommand(ApplyConsentedChanges, () => PendingChanges.Count > 0 && !_busy);
    }

    // ---- commands --------------------------------------------------------

    /// <summary>Fetches and interprets the subscription.</summary>
    public IAsyncRelayCommand ImportCommand { get; }

    /// <summary>
    /// Applies only the changes the user has explicitly consented to.
    /// </summary>
    /// <remarks>
    /// A plain (non-async) command: it performs no I/O. It raises
    /// <see cref="ConsentGiven"/> with a proposed snapshot, and the owner persists it.
    /// </remarks>
    public IRelayCommand ApplyConsentedChangesCommand { get; }

    /// <summary>
    /// Raised when the user has consented to a set of changes.
    /// </summary>
    /// <remarks>
    /// The event carries the profiles, the URL (so it can be persisted, never displayed) and the
    /// proposed settings. The view model deliberately cannot write settings itself: consent has
    /// to pass through something that owns the session, so there is exactly one place where a
    /// provider-influenced value can become live configuration.
    /// </remarks>
    public event EventHandler<SubscriptionConsentEventArgs>? ConsentGiven;

    // ---- input -----------------------------------------------------------

    /// <summary>The subscription URL, typed by the user. Never bound to a visible TextBlock.</summary>
    public string Url
    {
        get => _url;
        set
        {
            if (SetField(ref _url, value))
            {
                MaskedUrlHint = MaskUrl(value, _localization);
                OnPropertyChanged(nameof(HasUrl));
                ImportCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool HasUrl => !string.IsNullOrWhiteSpace(_url);

    /// <summary>A token-free rendering of the URL, safe to show.</summary>
    public string MaskedUrlHint
    {
        get => _maskedUrlHint;
        private set => SetField(ref _maskedUrlHint, value);
    }

    // ---- results ---------------------------------------------------------

    public string ProviderTitle
    {
        get => _providerTitle;
        private set => SetField(ref _providerTitle, value);
    }

    public string Announce
    {
        get => _announce;
        private set => SetField(ref _announce, value);
    }

    public bool HasAnnounce => _announce.Length > 0;

    /// <summary>Number of usable profiles in the last import.</summary>
    public int ProfileCount
    {
        get => _profileCount;
        private set => SetField(ref _profileCount, value);
    }

    /// <summary>Lines that looked like share links but could not be parsed.</summary>
    public int FailureCount
    {
        get => _failureCount;
        private set => SetField(ref _failureCount, value);
    }

    public bool HasFailures => _failureCount > 0;

    /// <summary>Localized notice describing unparsable lines, or empty.</summary>
    public string FailureNotice
    {
        get => _failureNotice;
        private set => SetField(ref _failureNotice, value);
    }

    /// <summary>Localized notice listing refused headers. Always shown when non-empty.</summary>
    public string RefusedNotice
    {
        get => _refusedNotice;
        private set => SetField(ref _refusedNotice, value);
    }

    public bool HasRefusedHeaders => _refusedNotice.Length > 0;

    /// <summary>Gate B: changes awaiting explicit consent.</summary>
    public ObservableCollection<PendingChangeRow> PendingChanges { get; } = new();

    public bool HasPendingChanges => PendingChanges.Count > 0;

    /// <summary>Parser diagnostics from the registry.</summary>
    public ObservableCollection<DetailRow> Errors { get; } = new();

    public bool HasErrors => Errors.Count > 0;

    /// <summary>Outcome line for the last action.</summary>
    public string Status
    {
        get => _status;
        private set => SetField(ref _status, value);
    }

    /// <summary>Localized failure of the import itself.</summary>
    public string Error
    {
        get => _error;
        private set
        {
            if (SetField(ref _error, value))
            {
                OnPropertyChanged(nameof(HasError));
            }
        }
    }

    public bool HasError => _error.Length > 0;

    /// <summary>True while a fetch is in flight, so the button cannot start a second one.</summary>
    public bool IsBusy
    {
        get => _busy;
        private set
        {
            if (SetField(ref _busy, value))
            {
                ImportCommand.NotifyCanExecuteChanged();
                ApplyConsentedChangesCommand.NotifyCanExecuteChanged();
            }
        }
    }

    /// <summary>True once a subscription has been parsed, so the consent list means something.</summary>
    public bool HasImported
    {
        get => _imported;
        private set => SetField(ref _imported, value);
    }

    // ---- localized chrome ------------------------------------------------

    public string Heading => _localization.Get("main.update_subscription");

    public string UrlLabel => _localization.Get("subscription.fix_url");

    public string ImportLabel => _localization.Get("main.update_subscription");

    public string ProviderLabel => _localization.Get("header.profile_title");

    public string AnnounceLabel => _localization.Get("header.announce");

    public string ProfileCountLabel => _localization.Get("main.change_server");

    public string RefusedLabel => _localization.Get("error.header.refused_for_security");

    public string PendingLabel => _localization.Get("header.routing_enable");

    public string ApplyLabel => _localization.Get("subscription.retry");

    public string ConsentTokenLabel => _localization.Get("header.provider_id");

    // ---- behaviour -------------------------------------------------------

    /// <summary>Restores a previously used URL without displaying it.</summary>
    public void Restore(string? url)
    {
        _url = url ?? string.Empty;
        MaskedUrlHint = MaskUrl(_url, _localization);
        OnPropertyChanged(nameof(Url));
        OnPropertyChanged(nameof(HasUrl));
        ImportCommand.NotifyCanExecuteChanged();
    }

    /// <summary>
    /// Supplies the settings the fetch uses and the snapshot a consented change is applied to.
    /// </summary>
    /// <remarks>
    /// Read through a store rather than copied once: the live settings can change while the
    /// import screen is open (a core binary is chosen, advanced mode is toggled), and a consent
    /// decision must be applied to what is actually in force, not to a snapshot taken when the
    /// window opened. A stale base would silently revert unrelated changes the user made
    /// meanwhile.
    /// </remarks>
    public void RestoreSettings()
    {
        _subscriptionSettings = _store.Settings.Subscriptions;
    }

    /// <summary>
    /// Fetches and parses, then updates the gates.
    /// </summary>
    /// <remarks>
    /// Applying nothing is the default outcome of a successful import: profiles are staged and
    /// the consent list is populated, but no setting changes until the user acts on it.
    /// </remarks>
    public async Task ImportAsync()
    {
        if (_busy || !HasUrl)
        {
            return;
        }

        IsBusy = true;
        Error = string.Empty;
        Status = string.Empty;

        try
        {
            var result = await _importer
                .ImportAsync(_url, _subscriptionSettings, CancellationToken.None)
                .ConfigureAwait(true);

            if (result.IsFailure)
            {
                SetError(result.Error!);
                return;
            }

            Present(result.Value);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Populates every gate section from a parsed result. Public so tests can drive it.</summary>
    public void Present(SubscriptionImportResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        ProviderTitle = string.IsNullOrWhiteSpace(result.Title)
            ? _localization.Get("main.no_server")
            : result.Title!;

        Announce = result.Announce ?? string.Empty;
        ProfileCount = result.Profiles.Count;
        FailureCount = result.Failures.Count;

        FailureNotice = result.Failures.Count == 0
            ? string.Empty
            : $"{_localization.Get("error.sharelink.malformed")} ({result.Failures.Count})";

        // Gate C. Rendered as a notice, never applied and never offered for acceptance. The
        // header list is passed as the message's own {headers} argument rather than concatenated,
        // so the catalog decides how the sentence is put together.
        RefusedNotice = result.RefusedHeaders.Count == 0
            ? string.Empty
            : Presentation.DescribeKey(
                _localization,
                "error.header.refused_for_security",
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["headers"] = string.Join(", ", result.RefusedHeaders),
                });

        // Gate B. Each row carries its own consent token; nothing is applied here.
        PendingChanges.Clear();
        foreach (var change in result.PendingChanges)
        {
            var row = new PendingChangeRow(change);
            row.Localize(_localization);
            PendingChanges.Add(row);
        }

        Errors.Clear();
        _errors.Clear();
        foreach (var error in result.Errors)
        {
            _errors.Add(error);
            Errors.Add(new DetailRow("—", Presentation.Describe(_localization, error)));
        }

        _lastResult = result;
        HasImported = true;
        Status = string.Empty;

        OnPropertyChanged(nameof(HasAnnounce));
        OnPropertyChanged(nameof(HasFailures));
        OnPropertyChanged(nameof(HasRefusedHeaders));
        OnPropertyChanged(nameof(HasPendingChanges));
        OnPropertyChanged(nameof(HasErrors));
        ApplyConsentedChangesCommand.NotifyCanExecuteChanged();
    }

    /// <summary>
    /// Applies every change the user has consented to, and hands the proposed snapshot to the
    /// owner.
    /// </summary>
    /// <remarks>
    /// <para>
    /// "Consent" here is the user pressing the apply button on a list that shows, for each row,
    /// the exact header, the exact value and the risk. The consent token carried by the row is
    /// verified against the token recomputed from the row's own header and value, so a value that
    /// was swapped out after the list was rendered is refused rather than applied — this is the
    /// mechanism that stops a provider presenting a harmless request, obtaining a "yes", and then
    /// changing the value on the next refresh.
    /// </para>
    /// <para>
    /// The result is a <i>proposed</i> snapshot, applied on top of the live settings read at this
    /// moment. It travels with <see cref="ConsentGiven"/>; the owner is the only thing that can
    /// persist it, which keeps a provider-influenced value one step away from live configuration.
    /// </para>
    /// </remarks>
    private void ApplyConsentedChanges()
    {
        if (_lastResult is null)
        {
            return;
        }

        var proposed = _store.Settings;
        var applied = 0;

        foreach (var row in PendingChanges)
        {
            var expected = PendingChangeApplier.ConsentToken(
                _lastResult.SubscriptionUrl,
                row.HeaderName,
                row.Change.ValueFingerprint);

            if (!string.Equals(expected, row.ConsentToken, StringComparison.Ordinal))
            {
                row.Outcome = _localization.Get("error.header.gate_violation");
                continue;
            }

            switch (PendingChangeApplier.Apply(ref proposed, row.Change))
            {
                case PendingChangeApplier.Outcome.Applied:
                    row.Outcome = _localization.Get("status.connected");
                    applied++;
                    break;
                case PendingChangeApplier.Outcome.InvalidValue:
                    row.Outcome = _localization.Get("error.header.value_out_of_range");
                    break;
                default:
                    // Mapped to nothing: the client has no field for this header. Reported
                    // rather than guessed at.
                    row.Outcome = _localization.Get("error.header.value_not_allowed");
                    break;
            }
        }

        Status = $"{_localization.Get("main.update_subscription")}: {applied}/{PendingChanges.Count}";
        ConsentGiven?.Invoke(this, new SubscriptionConsentEventArgs(_lastResult, proposed));
    }

    private SubscriptionImportResult? _lastResult;
    private readonly List<MyVpnError> _errors = new();

    private void SetError(MyVpnError error)
    {
        Error = Presentation.DescribeWithSeverity(_localization, error);
        Status = string.Empty;
        PendingChanges.Clear();
        _errors.Clear();
        RefusedNotice = string.Empty;
        FailureNotice = string.Empty;
        OnPropertyChanged(nameof(HasPendingChanges));
        OnPropertyChanged(nameof(HasRefusedHeaders));
        OnPropertyChanged(nameof(HasFailures));
        OnPropertyChanged(nameof(HasErrors));
        ApplyConsentedChangesCommand.NotifyCanExecuteChanged();
    }

    private void Relocalize()
    {
        // Re-render from the stored errors rather than from their previous rendering: the
        // localized text is derived, and a language switch must not leave the old language on
        // screen next to the new one.
        Errors.Clear();
        foreach (var error in _errors)
        {
            Errors.Add(new DetailRow("—", Presentation.Describe(_localization, error)));
        }

        foreach (var row in PendingChanges)
        {
            row.Localize(_localization);

            // An outcome is a rendered message, so it has to be re-rendered too. The token check
            // is not re-run: consent was already granted and recorded.
            if (row.HasOutcome)
            {
                row.Outcome = string.Empty;
            }
        }

        if (_lastResult is not null)
        {
            ProviderTitle = string.IsNullOrWhiteSpace(_lastResult.Title)
                ? _localization.Get("main.no_server")
                : _lastResult.Title!;

            RefusedNotice = _lastResult.RefusedHeaders.Count == 0
                ? string.Empty
                : Presentation.DescribeKey(
                    _localization,
                    "error.header.refused_for_security",
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["headers"] = string.Join(", ", _lastResult.RefusedHeaders),
                    });

            FailureNotice = _lastResult.Failures.Count == 0
                ? string.Empty
                : $"{_localization.Get("error.sharelink.malformed")} ({_lastResult.Failures.Count})";
        }

        MaskedUrlHint = MaskUrl(_url, _localization);
        OnAllPropertiesChanged();
    }

    /// <summary>
    /// Renders a subscription URL with its path and query removed.
    /// </summary>
    /// <remarks>
    /// A subscription URL is a bearer credential: the token lives in the path (and sometimes the
    /// query). Showing the host is useful — it tells the user which provider they configured —
    /// while the token stays off the screen, out of screenshots and out of bug reports.
    /// </remarks>
    public static string MaskUrl(string? url, LocalizationService localization)
    {
        ArgumentNullException.ThrowIfNull(localization);

        if (string.IsNullOrWhiteSpace(url))
        {
            return string.Empty;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            // Not a URL at all, so there is no safe part to show.
            return localization.Get(Presentation.UnknownKey);
        }

        var port = uri.IsDefaultPort ? string.Empty : $":{uri.Port}";
        return $"{uri.Scheme}://{uri.Host}{port}/…";
    }
}

/// <summary>The consented import, ready to be persisted by the owner.</summary>
public sealed class SubscriptionConsentEventArgs : EventArgs
{
    public SubscriptionConsentEventArgs(SubscriptionImportResult result, AppSettings proposedSettings)
    {
        Result = result ?? throw new ArgumentNullException(nameof(result));
        ProposedSettings = proposedSettings ?? throw new ArgumentNullException(nameof(proposedSettings));
    }

    public SubscriptionImportResult Result { get; }

    /// <summary>The settings after the consented changes. Not live until the owner persists it.</summary>
    public AppSettings ProposedSettings { get; }
}
