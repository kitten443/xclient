using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using MyVpn.Core.Domain;
using MyVpn.Core.Settings;
using MyVpn.UI.Localization;

namespace MyVpn.UI.ViewModels;

/// <summary>
/// A read-only view of the settings the session will actually use.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately read-only in this build. The settings that decide whether traffic leaks — tunnel
/// mode, Kill Switch mode, DNS mode, IPv6 handling — are the ones a half-finished editor gets
/// wrong, and a wrong value there is not a cosmetic bug. Until each one has an editor with its
/// validation and its explanation, showing the effective value is the honest thing to do: the
/// user can see what is in force, and nothing can silently change it.
/// </para>
/// <para>
/// The one editable field is the core binary path, because choosing it is a local file decision
/// rather than a network-mutating one, and the session already accepts it per request.
/// </para>
/// </remarks>
public sealed class SettingsViewModel : ObservableObject
{
    private readonly LocalizationService _localization;
    private readonly IUserSettingsStore _store;

    private AppSettings _settings = new();
    private AppTheme _theme = AppTheme.System;
    private string _coreBinaryPath = string.Empty;
    private string _saveStatus = string.Empty;

    public SettingsViewModel(LocalizationService localization, IUserSettingsStore store)
    {
        _localization = localization ?? throw new ArgumentNullException(nameof(localization));
        _store = store ?? throw new ArgumentNullException(nameof(store));

        _localization.LanguageChanged += (_, _) => Refresh();

        SaveCommand = new AsyncRelayCommand(SaveAsync);
    }

    /// <summary>Persists the editable parts of the state.</summary>
    public IAsyncRelayCommand SaveCommand { get; }

    public ObservableCollection<DetailRow> Details { get; } = new();

    public string Heading => _localization.Get("main.settings");

    public string SaveLabel => _localization.Get("subscription.retry");

    public string CoreBinaryLabel => _localization.Get("xray.select_binary");

    public string LanguageLabel => _localization.Get("language.label");

    public string ThemeLabel => _localization.Get("theme.label");

    public string CurrentLanguageCode => _localization.Language;

    /// <summary>Explicitly chosen core binary, or empty to use the search order.</summary>
    public string CoreBinaryPath
    {
        get => _coreBinaryPath;
        set
        {
            if (SetField(ref _coreBinaryPath, value ?? string.Empty))
            {
                _store.CoreBinaryPath = _coreBinaryPath.Length == 0 ? null : _coreBinaryPath;
                _store.MarkDirty();
            }
        }
    }

    /// <summary>Outcome of the last save, or empty.</summary>
    public string SaveStatus
    {
        get => _saveStatus;
        private set => SetField(ref _saveStatus, value);
    }

    /// <summary>Adopts a settings snapshot and renders it.</summary>
    public void Restore(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _settings = settings;
        Refresh();
    }

    public Task SaveAsync()
    {
        _store.MarkDirty();
        return SaveCoreAsync();
    }

    private async Task SaveCoreAsync()
    {
        await _store.SaveAsync(CancellationToken.None).ConfigureAwait(true);
        SaveStatus = _store.IsDirty ? string.Empty : _localization.Get("status.connected");
    }

    private void Refresh()
    {
        // The language row reports the setting, not the active catalog: "System" is a real
        // choice (follow the OS), and showing the language that choice resolved to would make the
        // setting unreadable — the user could no longer tell an explicit choice from a detected
        // one.
        var rows = new (string Label, string Value)[]
        {
            (Heading, _localization.Get(ModeKey(_settings.TunnelMode))),
            (_localization.Get("main.killswitch"), _localization.Get(KillSwitchKey(_settings.KillSwitch))),
            (LanguageLabel, _localization.Get("language.system")),
            (ThemeLabel, _localization.Get(ThemeKey(_theme))),
            (CoreBinaryLabel, _coreBinaryPath.Length == 0
                ? _localization.Get("main.no_server")
                : _coreBinaryPath),
        };

        for (var index = 0; index < rows.Length; index++)
        {
            if (index < Details.Count)
            {
                Details[index].Set(rows[index].Label, rows[index].Value);
            }
            else
            {
                Details.Add(new DetailRow(rows[index].Label, rows[index].Value));
            }
        }

        OnAllPropertiesChanged();
    }

    private static string ModeKey(TunnelMode mode) => mode switch
    {
        TunnelMode.Tun => "mode.tun",
        TunnelMode.SystemProxy => "mode.system_proxy",
        _ => "mode.disabled",
    };

    private static string KillSwitchKey(KillSwitchMode mode) => mode switch
    {
        KillSwitchMode.AlwaysOn => "killswitch.always_on",
        KillSwitchMode.OnDemand => "killswitch.on_demand",
        _ => "killswitch.disabled",
    };

    private static string ThemeKey(AppTheme theme) => theme switch
    {
        AppTheme.Light => "theme.light",
        AppTheme.Dark => "theme.dark",
        _ => "theme.system",
    };
}
