using System.Globalization;
using System.Text;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Windows.Execution;

namespace MyVpn.Platform.Windows.Tun;

/// <summary>
/// Observes the Windows TUN adapter that the Xray core creates for the TUN inbound.
/// </summary>
/// <remarks>
/// <para>
/// <b>Xray owns the adapter; MyVpn observes it.</b> On Windows the core calls
/// <c>WintunCreateAdapter</c> from <c>wintun.dll</c> — which must sit beside <c>xray.exe</c>, as
/// the core's own TUN README states — then configures addresses, routes and DNS through
/// <c>winipcfg</c>. Wintun installs its signed driver on first use and needs elevation, so the
/// privileged party is the core process, not this observer. MyVpn never loads <c>wintun.dll</c>
/// and never creates a second adapter for the same tunnel: two parties configuring one interface
/// is how addresses, routes and the firewall's idea of the tunnel end up disagreeing.
/// </para>
/// <para>
/// <b>Adapters are read through <c>GetAdaptersAddresses</c>, not through text.</b>
/// <c>netsh interface show interface</c> and <c>ipconfig /all</c> are localized, so a parser
/// keyed on English labels returns nothing on a non-English Windows — a silent failure that
/// looks exactly like "the tunnel is not up". <see cref="WindowsAdapters"/> is the same source
/// the route manager uses to resolve interface indexes, so both agree on what exists.
/// </para>
/// <para>
/// <b>The interface index is not stable.</b> Windows reassigns indexes across restarts and
/// adapter re-creation, and a Wintun adapter is created and destroyed with the tunnel, so
/// anything that pins an index — <c>route.exe</c>'s <c>if</c> clause, a saved plan — must
/// re-resolve it from the adapter name at use time. That finding is why this class exposes the
/// LUID and the index together and never caches either.
/// </para>
/// <para>
/// <see cref="IsSupported"/> deliberately answers only "can this machine's adapter table be
/// read", which is what observing the tunnel requires. Whether a tunnel can be <i>created</i>
/// depends on <c>wintun.dll</c> being present next to the core and on the core running elevated;
/// the pre-flight for a session checks those separately, and reporting <c>false</c> here would
/// disable TUN mode on a machine where it works.
/// </para>
/// </remarks>
public sealed class WindowsTunDeviceManager : ITunDeviceManager
{
    /// <summary>Default interface name; matches the Xray TUN inbound's <c>name</c> field.</summary>
    public const string DefaultTunName = "myvpn0";

    /// <summary>
    /// Longest interface name MyVpn will hand to another tool.
    /// </summary>
    /// <remarks>
    /// Windows itself allows longer friendly names, and they may contain spaces. This limit is
    /// MyVpn's own: the name reaches <c>netsh</c> and <c>route.exe</c> as an argv element, and a
    /// bounded, printable value is easier to reason about in a log line than an arbitrary one.
    /// </remarks>
    public const int MaxInterfaceNameLength = 128;

    /// <summary>
    /// True when the adapter table can be read on this host.
    /// </summary>
    /// <remarks>
    /// Cheap and honest: an OS check, nothing more. No native call is made by a property getter.
    /// </remarks>
    public bool IsSupported => WindowsPlatform.IsWindows;

    public string DefaultInterfaceName => DefaultTunName;

    /// <summary>
    /// True when an adapter with this friendly name currently exists.
    /// </summary>
    /// <remarks>
    /// A missing adapter is the normal case before a session starts, so it is reported as
    /// <c>false</c> rather than as an error. An unreadable adapter table is also reported as
    /// <c>false</c>: this method answers a question about existence, and "unknown" is not
    /// "exists".
    /// </remarks>
    public Task<bool> ExistsAsync(string interfaceName, CancellationToken cancellationToken)
    {
        _ = cancellationToken;

        ValidateInterfaceName(interfaceName);

        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(false);
        }

        return Task.FromResult(WindowsAdapters.FindByName(interfaceName) is not null);
    }

    /// <summary>
    /// Returns the addresses assigned to the interface, with their prefix lengths.
    /// </summary>
    /// <remarks>
    /// The form is <c>address/prefix</c> (for example <c>10.8.0.2/24</c>) because the prefix is
    /// what the routing layer and the leak check need. An interface that does not exist, one with
    /// no addresses and an unreadable table all produce an empty list; none of them is worth
    /// failing a diagnostics run over.
    /// </remarks>
    public Task<IReadOnlyList<string>> GetAddressesAsync(
        string interfaceName,
        CancellationToken cancellationToken)
    {
        _ = cancellationToken;

        ValidateInterfaceName(interfaceName);

        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
        }

        var adapter = WindowsAdapters.FindByName(interfaceName);

        return Task.FromResult<IReadOnlyList<string>>(adapter?.Addresses ?? Array.Empty<string>());
    }

    /// <summary>Diagnostic description of the adapter, for the diagnostics bundle.</summary>
    public static string Describe(WindowsAdapterInfo adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"'{adapter.FriendlyName}' ifindex={adapter.IfIndex} luid={adapter.Luid} "
            + $"mtu={adapter.Mtu} up={adapter.IsUp} addresses=[{string.Join(", ", adapter.Addresses)}]");
    }

    /// <summary>
    /// True when <paramref name="name"/> is safe to hand to another tool as an interface name.
    /// </summary>
    /// <remarks>
    /// Arguments are already passed as a vector with no shell, so this is defence in depth rather
    /// than the only protection: it refuses control characters (which could forge a log line),
    /// path separators and quotes, and a leading hyphen. Spaces are allowed because real Windows
    /// adapter names contain them and an argv element carries a space safely.
    /// </remarks>
    public static bool IsValidInterfaceName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > MaxInterfaceNameLength)
        {
            return false;
        }

        if (name[0] == '-' || name == "." || name == "..")
        {
            return false;
        }

        foreach (var c in name)
        {
            if (char.IsControl(c) || c is '/' or '\\' or '"' or '\'' or '=' or ';' or '%')
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Throws when a name must not reach argv.</summary>
    /// <exception cref="ArgumentException">The name is not usable as a Windows adapter name.</exception>
    public static void ValidateInterfaceName(string? interfaceName)
    {
        if (interfaceName is null)
        {
            throw new ArgumentNullException(nameof(interfaceName));
        }

        if (IsValidInterfaceName(interfaceName))
        {
            return;
        }

        throw new ArgumentException(
            $"'{DescribeForLog(interfaceName)}' is not a usable Windows adapter name: it must be 1 "
            + $"to {MaxInterfaceNameLength} characters and contain no control characters, path "
            + "separators, quotes, '=', ';' or '%' (localization key: error.tun.interface_name_invalid).",
            nameof(interfaceName));
    }

    /// <summary>Renders a rejected value for a log line without letting control characters forge one.</summary>
    private static string DescribeForLog(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "(empty)";
        }

        var builder = new StringBuilder(Math.Min(value.Length, 40) + 1);

        foreach (var c in value)
        {
            if (builder.Length >= 40)
            {
                builder.Append('…');
                break;
            }

            builder.Append(char.IsControl(c) ? '?' : c);
        }

        return builder.ToString();
    }
}
