using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using CommunityToolkit.Mvvm.Input;
using MyVpn.Core.Domain;
using MyVpn.UI.Localization;

namespace MyVpn.UI.ViewModels;

/// <summary>One label/value row on the main screen.</summary>
public sealed record DetailRow(string Label, string Value);

/// <summary>
/// Main screen view model.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately thin. The view model reads from <see cref="VpnStateMachine"/> and renders
/// localized strings; it never touches the firewall, routes, DNS, the Xray process or any
/// privileged API. That is enforced structurally: this project references only Core, the
/// application layer, the IPC contract and platform <i>abstractions</i>, never a concrete
/// platform implementation or an executor.
/// </para>
/// <para>
/// Commands that change network state are declared here but delegate to the application
/// layer, which is not yet wired in this build; they therefore report their status through
/// the UI rather than performing partial work.
/// </para>
/// </remarks>
public sealed class MainWindowViewModel : INotifyPropertyChanged
{
    private readonly VpnStateMachine _stateMachine;
    private readonly LocalizationService _localization;

    private string _serverName = string.Empty;
    private string _pingText = "—";
    private string _ipText = "—";
    private string _downloadText = "—";
    private string _uploadText = "—";
    private string _durationText = "—";
    private bool _advancedMode;

    public MainWindowViewModel(VpnStateMachine stateMachine, LocalizationService localization)
    {
        _stateMachine = stateMachine ?? throw new ArgumentNullException(nameof(stateMachine));
        _localization = localization ?? throw new ArgumentNullException(nameof(localization));

        _stateMachine.StateChanged += OnStateChanged;
        _localization.LanguageChanged += OnLanguageChanged;

        ToggleConnectionCommand = new RelayCommand(ToggleConnection);
        ChangeServerCommand = new RelayCommand(() => SetTransientStatus("main.change_server"));
        AutoSelectCommand = new RelayCommand(() => SetTransientStatus("main.auto_select"));
        UpdateSubscriptionCommand = new RelayCommand(() => SetTransientStatus("main.update_subscription"));
        RestoreNetworkCommand = new RelayCommand(() => SetTransientStatus("main.restore_network"));
        SetLanguageCommand = new RelayCommand<string>(code => _localization.SetLanguage(code));

        RebuildDetails();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    // ---- commands ------------------------------------------------------

    public IRelayCommand ToggleConnectionCommand { get; }

    public IRelayCommand ChangeServerCommand { get; }

    public IRelayCommand AutoSelectCommand { get; }

    public IRelayCommand UpdateSubscriptionCommand { get; }

    public IRelayCommand RestoreNetworkCommand { get; }

    public IRelayCommand<string> SetLanguageCommand { get; }

    // ---- localized chrome ---------------------------------------------

    public string AppTitle => _localization.Get("app.title");

    public string AppSubtitle => _localization.Get("app.subtitle");

    public string LabelStatus => _localization.Get("main.status");

    public string LabelServer => _localization.Get("main.server");

    public string LabelMode => _localization.Get("main.mode");

    public string LabelKillSwitch => _localization.Get("main.killswitch");

    public string LabelLanguage => _localization.Get("language.label");

    public string AdvancedModeLabel => _localization.Get("main.advanced_mode");

    public string CurrentLanguageCode => _localization.Language;

    // ---- live state ----------------------------------------------------

    /// <summary>Localized connection status.</summary>
    public string StatusText => _localization.Get(StatusKey(_stateMachine.Current));

    /// <summary>Primary button label, derived from the state machine.</summary>
    public string ConnectButtonText => _stateMachine.Current switch
    {
        VpnConnectionState.Connected or VpnConnectionState.Degraded => _localization.Get("main.disconnect"),
        VpnConnectionState.Connecting or VpnConnectionState.Preparing => _localization.Get("main.connecting"),
        VpnConnectionState.Disconnecting => _localization.Get("main.disconnecting"),
        _ => _localization.Get("main.connect"),
    };

    /// <summary>True while a transition is under way, so the button can be disabled.</summary>
    public bool IsBusy => _stateMachine.IsBusy;

    /// <summary>True when the Kill Switch is expected to be engaged.</summary>
    public bool KillSwitchEngaged => _stateMachine.RequiresKillSwitch;

    public string ServerName
    {
        get => _serverName.Length == 0 ? _localization.Get("main.no_server") : _serverName;
        set => SetField(ref _serverName, value);
    }

    public string PingText
    {
        get => _pingText;
        set => SetField(ref _pingText, value);
    }

    public string IpText
    {
        get => _ipText;
        set => SetField(ref _ipText, value);
    }

    public string DownloadText
    {
        get => _downloadText;
        set => SetField(ref _downloadText, value);
    }

    public string UploadText
    {
        get => _uploadText;
        set => SetField(ref _uploadText, value);
    }

    public string DurationText
    {
        get => _durationText;
        set => SetField(ref _durationText, value);
    }

    public bool AdvancedMode
    {
        get => _advancedMode;
        set => SetField(ref _advancedMode, value);
    }

    /// <summary>Rows shown in the detail table, rebuilt when any value or the language changes.</summary>
    public ObservableCollection<DetailRow> Details { get; } = new();

    // ---- internals -----------------------------------------------------

    private void ToggleConnection()
    {
        // The real connect/disconnect use case lives in MyVpn.Application and is reached
        // through the service facade. Until that is wired, reflect the state machine so the
        // UI is demonstrably driven by the same state model the backend uses.
        if (_stateMachine.CanStartConnect)
        {
            _stateMachine.TryTransitionTo(VpnConnectionState.Preparing, "ui-connect");
            _stateMachine.TryTransitionTo(VpnConnectionState.Connecting, "ui-connect");
            _stateMachine.TryTransitionTo(VpnConnectionState.Connected, "ui-connect");
        }
        else
        {
            _stateMachine.TryTransitionTo(VpnConnectionState.Disconnecting, "ui-disconnect");
            _stateMachine.TryTransitionTo(VpnConnectionState.Disconnected, "ui-disconnect");
        }
    }

    private void SetTransientStatus(string messageKey) => ServerName = _localization.Get(messageKey);

    private void OnStateChanged(object? sender, VpnStateChange change)
    {
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(ConnectButtonText));
        OnPropertyChanged(nameof(IsBusy));
        OnPropertyChanged(nameof(KillSwitchEngaged));
        RebuildDetails();
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        // An empty property name tells the binding layer to re-read every property, which is
        // what makes a language switch take effect immediately without rebuilding the window.
        OnPropertyChanged(string.Empty);
        RebuildDetails();
    }

    private void RebuildDetails()
    {
        Details.Clear();
        Details.Add(new DetailRow(LabelServer, ServerName));
        Details.Add(new DetailRow(_localization.Get("main.ping"), PingText));
        Details.Add(new DetailRow(_localization.Get("main.ip"), IpText));
        Details.Add(new DetailRow(_localization.Get("main.download"), DownloadText));
        Details.Add(new DetailRow(_localization.Get("main.upload"), UploadText));
        Details.Add(new DetailRow(_localization.Get("main.duration"), DurationText));
        Details.Add(new DetailRow(LabelMode, _localization.Get("mode.tun")));
        Details.Add(new DetailRow(
            LabelKillSwitch,
            _localization.Get(KillSwitchEngaged ? "killswitch.on_demand" : "killswitch.disabled")));
    }

    private static string StatusKey(VpnConnectionState state) => state switch
    {
        VpnConnectionState.Disconnected => "status.disconnected",
        VpnConnectionState.Preparing => "status.preparing",
        VpnConnectionState.Connecting => "status.connecting",
        VpnConnectionState.Connected => "status.connected",
        VpnConnectionState.Degraded => "status.degraded",
        VpnConnectionState.Reconnecting => "status.reconnecting",
        VpnConnectionState.Disconnecting => "status.disconnecting",
        _ => "status.faulted",
    };

    private void SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }

        field = value;
        OnPropertyChanged(propertyName);
    }

    private void OnPropertyChanged(string? propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

/// <summary>Formats values for display without hard-coded strings.</summary>
internal static class DisplayFormat
{
    public static string Bytes(long value)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double size = value;
        var unit = 0;

        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }

        return string.Format(CultureInfo.InvariantCulture, "{0:0.#} {1}", size, units[unit]);
    }

    public static string Duration(TimeSpan value) =>
        value.TotalHours >= 1
            ? string.Format(CultureInfo.InvariantCulture, "{0:0}:{1:00}:{2:00}", (int)value.TotalHours, value.Minutes, value.Seconds)
            : string.Format(CultureInfo.InvariantCulture, "{0:0}:{1:00}", value.Minutes, value.Seconds);
}
