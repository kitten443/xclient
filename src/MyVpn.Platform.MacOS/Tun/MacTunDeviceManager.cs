using System.Globalization;
using System.Net;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.Platform;

namespace MyVpn.Platform.MacOS.Tun;

/// <summary>One utun device and the addresses currently assigned to it.</summary>
public sealed record TunnelInterfaceObservation(string Name, IReadOnlyList<string> Addresses);

/// <summary>
/// Observes the macOS utun device that the Xray core creates for the TUN inbound.
/// </summary>
/// <remarks>
/// <para>
/// <b>Xray creates the device; MyVpn only looks at it.</b> On macOS the utun driver registers a
/// kernel control named <c>com.apple.net.utun_control</c> with
/// <c>CTL_FLAG_PRIVILEGED | CTL_FLAG_REG_SETUP | CTL_FLAG_REG_EXTENDED</c> — it requires root — and the
/// core opens it with <c>socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)</c> plus a <c>connect</c> to
/// that control. The device is named <c>utunN</c>, the number is assigned by the kernel, and the
/// descriptor's owner (the core) is what keeps the interface alive: closing it removes the device and
/// XNU's <c>if_rtdel()</c> removes its routes with it.
/// </para>
/// <para>
/// Because MyVpn does not own the descriptor, it must never try to create or destroy the interface:
/// two parties configuring one device is how addresses, routes and the firewall end up disagreeing
/// about what exists. This class therefore reads back what <c>ifconfig</c> reports, so the Kill Switch,
/// the route manager and the diagnostics bundle all describe the same reality. The same reasoning
/// applies to the interface named in <c>RESTORE NETWORK</c>: the cleanup step reports the device as the
/// core's and leaves it alone.
/// </para>
/// <para>
/// <b>Why a DNS executor exists at all.</b> Xray's tun <c>dns</c> setting performs DNS <i>assignment</i>
/// on Windows only; on macOS the field is inert (see <c>XrayConfigBuilder</c>, which emits it for
/// Windows alone and says so). The resolvers a macOS host actually uses are chosen by mDNSResponder and
/// the SystemConfiguration resolver stack, so pointing them at the tunnel is <c>networksetup</c>'s job
/// — which is why <c>MacDnsConfigurator</c> exists and why this class has to be able to say which utun
/// is the tunnel.
/// </para>
/// <para>
/// <b>The name is dynamic, and PF will not tell you when it is wrong.</b> macOS assigns the first free
/// <c>utunN</c>, so <c>utun0</c> may belong to WireGuard, iCloud Private Relay or another VPN client.
/// PF accepts a rule naming an interface that does not exist yet, so a wrong name produces no error:
/// the tunnel pass matches nothing and the terminal block catches everything — fail-closed but
/// VPN-broken, and silent. <see cref="ResolveTunnelInterfaceAsync"/> is the answer: it prefers the name
/// the caller was told, accepts the only candidate when exactly one utun exists, and otherwise
/// identifies the tunnel by the point-to-point address Xray assigns. When that is inconclusive it
/// returns <c>null</c> rather than guessing, because guessing between two VPN clients is not a
/// recoverable mistake.
/// </para>
/// <para>
/// <b>Not verified on macOS here.</b> This project is developed and unit-tested on Linux; the
/// <c>ifconfig</c> output shapes this class parses are taken from Apple's tooling and the platform
/// research, but no test in this repository has executed them on a Mac. The parsers are pure, so they
/// are covered exhaustively by tests on any host; the invocation itself is runtime-unverified.
/// </para>
/// </remarks>
public sealed class MacTunDeviceManager : ITunDeviceManager
{
    /// <summary>The interface-observation tool.</summary>
    public const string IfconfigBinary = "ifconfig";

    /// <summary>Prefix every utun device name carries.</summary>
    public const string UtunPrefix = "utun";

    /// <summary>
    /// Name MyVpn asks Xray for, matching <c>XrayConfigBuilder</c>'s macOS default. It is a request,
    /// not a guarantee: the kernel assigns the real number.
    /// </summary>
    public const string DefaultTunName = "utun0";

    /// <summary>Longest accepted interface name, <c>IFNAMSIZ - 1</c>.</summary>
    public const int MaxInterfaceNameLength = 15;

    /// <summary>
    /// Point-to-point block Xray uses on macOS (<c>169.254.10.1/30</c>, with the local address being
    /// the next one, <c>169.254.10.2</c>). Used only to disambiguate several utun devices, never to
    /// configure anything.
    /// </summary>
    public const string DefaultTunnelAddressPrefix = "169.254.10.0/30";

    private readonly ICommandRunner _runner;
    private readonly CidrBlock _expectedPrefix;

    public MacTunDeviceManager(ICommandRunner? runner = null, string? expectedAddressPrefix = null)
    {
        _runner = runner ?? new ProcessCommandRunner();

        var prefix = expectedAddressPrefix ?? DefaultTunnelAddressPrefix;
        if (!CidrBlock.TryParse(prefix, out var block))
        {
            throw new ArgumentException(
                $"'{prefix}' is not a CIDR block.", nameof(expectedAddressPrefix));
        }

        _expectedPrefix = block;
    }

    /// <summary>
    /// True when this is macOS and <c>ifconfig</c> can be run.
    /// </summary>
    /// <remarks>
    /// Deliberately does not require root. The privileged party is the core process that creates the
    /// utun, not this observer; requiring elevation here would report "no TUN support" on a machine
    /// where TUN mode works fine. The property spawns no process.
    /// </remarks>
    public bool IsSupported => OperatingSystem.IsMacOS() && _runner.Exists(IfconfigBinary);

    /// <summary>The name MyVpn asks for; the kernel may assign a different number.</summary>
    public string DefaultInterfaceName => DefaultTunName;

    public async Task<bool> ExistsAsync(string interfaceName, CancellationToken cancellationToken)
    {
        ValidateInterfaceName(interfaceName);

        if (!OperatingSystem.IsMacOS())
        {
            // Every member of this class starts with this guard: 'ifconfig' exists on other Unix
            // systems, so without it a Linux test run (or a Linux host in a trimmed build) would
            // happily list Linux interfaces and call them utun devices.
            return false;
        }

        var result = await _runner
            .RunAsync(IfconfigBinary, new[] { interfaceName }, cancellationToken)
            .ConfigureAwait(false);

        return result.Succeeded;
    }

    /// <summary>
    /// Returns the addresses <c>ifconfig</c> reports, with prefix lengths (<c>10.8.0.2/24</c>),
    /// because the prefix is what the routing layer needs.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetAddressesAsync(
        string interfaceName,
        CancellationToken cancellationToken)
    {
        ValidateInterfaceName(interfaceName);

        if (!OperatingSystem.IsMacOS())
        {
            return Array.Empty<string>();
        }

        var result = await _runner
            .RunAsync(IfconfigBinary, new[] { interfaceName }, cancellationToken)
            .ConfigureAwait(false);

        return result.Succeeded
            ? ParseIfconfigAddresses(interfaceName, result.StandardOutput)
            : Array.Empty<string>();
    }

    /// <summary>Lists every <c>utunN</c> device, ordered by unit number.</summary>
    public async Task<IReadOnlyList<string>> ListTunnelInterfacesAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsMacOS())
        {
            return Array.Empty<string>();
        }

        var result = await _runner
            .RunAsync(IfconfigBinary, new[] { "-l" }, cancellationToken)
            .ConfigureAwait(false);

        return result.Succeeded ? ParseInterfaceList(result.StandardOutput) : Array.Empty<string>();
    }

    /// <summary>
    /// Finds the utun device that belongs to MyVpn's tunnel.
    /// </summary>
    /// <param name="preferredName">The name the caller was told (settings or the core's report).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The interface name, or <c>null</c> when it cannot be determined unambiguously.</returns>
    /// <remarks>
    /// Resolution order: the preferred name when it exists; the only utun when exactly one exists;
    /// otherwise the device carrying an address inside <see cref="DefaultTunnelAddressPrefix"/>. When
    /// none of those apply the answer is <c>null</c> on purpose — with two VPN clients on the machine,
    /// a guess would arm the Kill Switch against the wrong interface.
    /// </remarks>
    public async Task<string?> ResolveTunnelInterfaceAsync(
        string? preferredName,
        CancellationToken cancellationToken)
    {
        var candidates = await ListTunnelInterfacesAsync(cancellationToken).ConfigureAwait(false);
        if (candidates.Count == 0)
        {
            return null;
        }

        if (TryGetSafeInterfaceName(preferredName, out var preferred)
            && candidates.Contains(preferred, StringComparer.Ordinal))
        {
            return preferred;
        }

        if (candidates.Count == 1)
        {
            return candidates[0];
        }

        var observations = new List<TunnelInterfaceObservation>(candidates.Count);
        foreach (var candidate in candidates)
        {
            var addresses = await GetAddressesAsync(candidate, cancellationToken).ConfigureAwait(false);
            observations.Add(new TunnelInterfaceObservation(candidate, addresses));
        }

        return ChooseTunnelInterface(observations, preferredName, _expectedPrefix);
    }

    // ------------------------------------------------------------------ pure helpers

    /// <summary>Parses <c>ifconfig -l</c> (a single space-separated line of interface names).</summary>
    public static IReadOnlyList<string> ParseInterfaceList(string? output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return Array.Empty<string>();
        }

        return output
            .Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Where(IsTunnelInterfaceName)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(TunnelUnitNumber)
            .ToArray();
    }

    /// <summary>True when a name is a utun device name (<c>utun</c> plus digits).</summary>
    public static bool IsTunnelInterfaceName(string? name) =>
        !string.IsNullOrEmpty(name)
        && name.StartsWith(UtunPrefix, StringComparison.Ordinal)
        && name.Length > UtunPrefix.Length
        && name[UtunPrefix.Length..].All(char.IsAsciiDigit);

    /// <summary>
    /// Parses <c>ifconfig &lt;name&gt;</c> into <c>address/prefix</c> strings.
    /// </summary>
    /// <remarks>
    /// The local address is the first token after <c>inet</c>/<c>inet6</c>: the peer address that
    /// follows <c>--&gt;</c> is not an address of this interface and is dropped, as is the
    /// <c>%utunN</c> zone suffix on a link-local IPv6 address. The IPv4 prefix is derived from the hex
    /// <c>netmask</c> because <c>ifconfig</c> does not print it; IPv6 uses <c>prefixlen</c>.
    /// </remarks>
    public static IReadOnlyList<string> ParseIfconfigAddresses(string interfaceName, string? output)
    {
        var addresses = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrEmpty(output))
        {
            return addresses;
        }

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            var fields = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 2)
            {
                continue;
            }

            if (fields[0] == "inet")
            {
                var prefix = FindPrefixLength(fields, "netmask");
                AddIfAddress(addresses, seen, StripZone(fields[1]), prefix >= 0 ? prefix : 32);
                continue;
            }

            if (fields[0] == "inet6")
            {
                var prefix = FindPrefixLength(fields, "prefixlen");
                AddIfAddress(addresses, seen, StripZone(fields[1]), prefix >= 0 ? prefix : 128);
            }
        }

        return addresses;
    }

    /// <summary>
    /// Picks the tunnel interface from a set of observations; returns <c>null</c> when ambiguous.
    /// </summary>
    public static string? ChooseTunnelInterface(
        IReadOnlyList<TunnelInterfaceObservation> observations,
        string? preferredName,
        CidrBlock? expectedPrefix)
    {
        ArgumentNullException.ThrowIfNull(observations);

        if (observations.Count == 0)
        {
            return null;
        }

        if (TryGetSafeInterfaceName(preferredName, out var preferred))
        {
            var match = observations.FirstOrDefault(
                o => string.Equals(o.Name, preferred, StringComparison.Ordinal));

            if (match is not null)
            {
                return match.Name;
            }
        }

        if (observations.Count == 1)
        {
            return observations[0].Name;
        }

        if (expectedPrefix is not null)
        {
            var matching = observations
                .Where(o => o.Addresses.Any(a => AddressIsInside(a, expectedPrefix.Value)))
                .ToArray();

            if (matching.Length == 1)
            {
                return matching[0].Name;
            }
        }

        // Ambiguous: more than one utun exists and none carries the address MyVpn's tunnel should have.
        // Guessing here would point the Kill Switch, the routes and DNS at another product's device.
        return null;
    }

    /// <summary>True when <paramref name="name"/> can be handed to <c>ifconfig</c> as an argument.</summary>
    public static bool TryGetSafeInterfaceName(string? name, out string safeName)
    {
        safeName = string.Empty;

        if (string.IsNullOrWhiteSpace(name) || name.Length > MaxInterfaceNameLength)
        {
            return false;
        }

        if (name[0] is '-' or '.')
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.'))
            {
                return false;
            }
        }

        safeName = name;
        return true;
    }

    /// <summary>Throws when a name must not reach argv.</summary>
    /// <exception cref="ArgumentException">The name is not a usable macOS interface name.</exception>
    public static void ValidateInterfaceName(string? interfaceName)
    {
        if (interfaceName is null)
        {
            throw new ArgumentNullException(nameof(interfaceName));
        }

        if (TryGetSafeInterfaceName(interfaceName, out _))
        {
            return;
        }

        throw new ArgumentException(
            $"'{interfaceName}' is not a usable macOS interface name: 1 to "
            + $"{MaxInterfaceNameLength} characters, letters, digits, '_', '-' or '.', with no "
            + "leading '-' or '.' (localization key: error.tun.interface_name_invalid).",
            nameof(interfaceName));
    }

    /// <summary>Error for a call made on a host that is not macOS.</summary>
    public static MyVpnError UnsupportedOnThisHost() =>
        new MyVpnError(
            ErrorCodes.TunMissing,
            "error.platform.macos_only",
            ErrorSeverity.Error,
            "The macOS TUN observer reads 'ifconfig', which only exists on macOS. This call is "
            + "refused before any process is started.",
            "diagnostics.run");

    /// <summary>Error for a tunnel interface that does not exist.</summary>
    public static MyVpnError TunnelMissing(string interfaceName) =>
        new MyVpnError(
            ErrorCodes.TunMissing,
            "error.tun.macos_missing",
            ErrorSeverity.Error,
            $"The utun device '{interfaceName}' does not exist. The core creates it and the kernel "
            + "assigns the number dynamically; resolve the real name before configuring routes or the "
            + "Kill Switch.",
            "diagnostics.run");

    // ------------------------------------------------------------------ internals

    private static int TunnelUnitNumber(string name) =>
        int.TryParse(name[UtunPrefix.Length..], NumberStyles.None, CultureInfo.InvariantCulture, out var unit)
            ? unit
            : int.MaxValue;

    private static string StripZone(string address)
    {
        var zone = address.IndexOf('%');
        return zone > 0 ? address[..zone] : address;
    }

    private static int FindPrefixLength(string[] fields, string keyword)
    {
        for (var i = 0; i < fields.Length - 1; i++)
        {
            if (fields[i] == keyword)
            {
                return keyword == "netmask"
                    ? PrefixLengthFromHexNetmask(fields[i + 1])
                    : int.TryParse(fields[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out var bits)
                        ? bits
                        : -1;
            }
        }

        return -1;
    }

    /// <summary>Counts the set bits of an <c>ifconfig</c> hex netmask (<c>0xfffffffc</c> → 30).</summary>
    public static int PrefixLengthFromHexNetmask(string? netmask)
    {
        if (string.IsNullOrWhiteSpace(netmask))
        {
            return -1;
        }

        var value = netmask.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            value = value[2..];
        }

        if (!uint.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var mask))
        {
            return -1;
        }

        var bits = 0;
        while (bits < 32 && (mask & 0x80000000u) != 0)
        {
            bits++;
            mask <<= 1;
        }

        return mask == 0 ? bits : -1;
    }

    private static void AddIfAddress(
        List<string> addresses,
        HashSet<string> seen,
        string address,
        int prefixLength)
    {
        if (!IPAddress.TryParse(address, out var parsed))
        {
            return;
        }

        var maxPrefix = parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        if (prefixLength < 0 || prefixLength > maxPrefix)
        {
            prefixLength = maxPrefix;
        }

        var text = string.Create(CultureInfo.InvariantCulture, $"{address}/{prefixLength}");
        if (seen.Add(text))
        {
            addresses.Add(text);
        }
    }

    private static bool AddressIsInside(string address, CidrBlock block)
    {
        var slash = address.IndexOf('/');
        var text = slash > 0 ? address[..slash] : address;

        return IPAddress.TryParse(text, out var parsed) && block.Contains(parsed);
    }
}
