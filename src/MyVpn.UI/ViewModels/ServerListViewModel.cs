using System.Collections.ObjectModel;
using MyVpn.Core.Domain;
using MyVpn.UI.Localization;

namespace MyVpn.UI.ViewModels;

/// <summary>One selectable server in the list.</summary>
/// <remarks>
/// Wraps a <see cref="ServerProfile"/>. The profile itself is never bound directly: it carries
/// credentials, and a binding is one <c>ToString()</c> away from putting them on screen. Only the
/// fields exposed here are renderable.
/// </remarks>
public sealed class ServerEntry : ObservableObject
{
    private string _summary = string.Empty;

    public ServerEntry(ServerProfile profile)
    {
        Profile = profile ?? throw new ArgumentNullException(nameof(profile));
    }

    /// <summary>The underlying profile. Never bound to directly.</summary>
    public ServerProfile Profile { get; }

    public Guid Id => Profile.Id;

    public string DisplayName => string.IsNullOrWhiteSpace(Profile.DisplayName)
        ? Profile.Endpoint
        : Profile.DisplayName;

    /// <summary>Protocol / transport / security, with the enum names localized.</summary>
    public string Summary
    {
        get => _summary;
        private set => SetField(ref _summary, value);
    }

    /// <summary>
    /// Re-renders the localized parts of this entry.
    /// </summary>
    /// <remarks>
    /// Called by the list when the language changes. Protocol, transport and security names are
    /// identifiers rather than prose — <c>VLESS</c>, <c>WebSocket</c>, <c>REALITY</c> are the
    /// names of the things on the wire — so they are not translated; the surrounding labels are.
    /// </remarks>
    public void Localize(LocalizationService localization)
    {
        ArgumentNullException.ThrowIfNull(localization);

        Summary = string.Join(
            " · ",
            ProtocolName(Profile.Protocol),
            Profile.Transport.ToString(),
            SecurityName(Profile.Security)).Trim();
    }

    private static string ProtocolName(ProxyProtocol protocol) => protocol switch
    {
        ProxyProtocol.Vless => "VLESS",
        ProxyProtocol.Vmess => "VMess",
        ProxyProtocol.Trojan => "Trojan",
        ProxyProtocol.Shadowsocks => "Shadowsocks",
        ProxyProtocol.Socks => "SOCKS",
        _ => "HTTP",
    };

    private static string SecurityName(SecurityKind security) => security switch
    {
        SecurityKind.Reality => "REALITY",
        SecurityKind.Tls => "TLS",
        _ => string.Empty,
    };
}

/// <summary>
/// The server list: what the connect button will connect to.
/// </summary>
/// <remarks>
/// The list is populated from the persisted profiles and, after an accepted import, from the
/// subscription. It performs no I/O of its own and holds no privileged capability at all.
/// </remarks>
public sealed class ServerListViewModel : ObservableObject
{
    private readonly LocalizationService _localization;
    private ServerEntry? _selected;

    public ServerListViewModel(LocalizationService localization)
    {
        _localization = localization ?? throw new ArgumentNullException(nameof(localization));
        _localization.LanguageChanged += (_, _) => Relocalize();
    }

    /// <summary>Every known server, in the order the subscription listed them.</summary>
    public ObservableCollection<ServerEntry> Profiles { get; } = new();

    public string Heading => _localization.Get("main.change_server");

    public string EmptyText => _localization.Get("main.no_server");

    public bool IsEmpty => Profiles.Count == 0;

    /// <summary>
    /// The highlighted entry.
    /// </summary>
    /// <remarks>
    /// Changing this is what "change server" means: the main screen reads it when the connect
    /// button is pressed. It does not reconnect an established session by itself — a server
    /// switch while connected is a teardown followed by a connect, and that decision belongs to
    /// the user pressing the button rather than to a list selection.
    /// </remarks>
    public ServerEntry? Selected
    {
        get => _selected;
        set => SetField(ref _selected, value);
    }

    /// <summary>Replaces the list, keeping the selection when the same server is still present.</summary>
    public void Restore(IReadOnlyList<ServerProfile> profiles)
    {
        ArgumentNullException.ThrowIfNull(profiles);

        var previous = _selected?.Id;

        Profiles.Clear();
        foreach (var profile in profiles)
        {
            var entry = new ServerEntry(profile);
            entry.Localize(_localization);
            Profiles.Add(entry);
        }

        _selected = previous is { } id ? Find(id) : Profiles.FirstOrDefault();
        OnPropertyChanged(nameof(Selected));
        OnPropertyChanged(nameof(IsEmpty));
    }

    public ServerEntry? Find(Guid id)
    {
        foreach (var entry in Profiles)
        {
            if (entry.Id == id)
            {
                return entry;
            }
        }

        return null;
    }

    private void Relocalize()
    {
        foreach (var entry in Profiles)
        {
            entry.Localize(_localization);
        }

        OnPropertyChanged(nameof(Heading));
        OnPropertyChanged(nameof(EmptyText));
    }
}
