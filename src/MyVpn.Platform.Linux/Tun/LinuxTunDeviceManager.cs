using System.Text;
using MyVpn.Core.Net;
using MyVpn.Platform.Abstractions.Platform;
using MyVpn.Platform.Abstractions.Execution;

namespace MyVpn.Platform.Linux.Tun;

/// <summary>
/// Observes the Linux TUN interface that the Xray core creates for the TUN inbound.
/// </summary>
/// <remarks>
/// <para>
/// <b>Xray creates the device; MyVpn observes it.</b> On Linux the TUN inbound in the core does
/// <c>open("/dev/net/tun", O_RDWR)</c> followed by
/// <c>ioctl(TUNSETIFF, IFF_TUN | IFF_NO_PI)</c> (verified against <c>proxy/tun/tun_linux.go</c>
/// and recorded in <c>docs/research/03-xray-tun-inbound.md</c> §1), then sets the MTU and, when
/// the tunnel starts, brings the link up and installs addresses and routes. The kernel requires
/// <c>CAP_NET_ADMIN</c> for that ioctl even though <c>/dev/net/tun</c> is world-writable
/// (<c>0666</c>) — the device node's permissions are irrelevant because the capability check
/// happens at the ioctl, per the kernel's <c>tuntap.txt</c> §2. Whoever holds the file descriptor
/// owns the interface, and closing it removes the device and its routes, which is exactly Xray's
/// teardown model.
/// </para>
/// <para>
/// MyVpn therefore never opens <c>/dev/net/tun</c> and never creates a second device for the same
/// tunnel: two parties configuring one interface is how addresses and routes end up disagreeing
/// with what the firewall believes. This class only reads back what <c>ip</c> reports, so the
/// Kill Switch, the route manager and the diagnostics bundle all describe the same reality.
/// </para>
/// <para>
/// <b>The <c>XRAY_TUN_FD</c> alternative.</b> If the environment variable <c>XRAY_TUN_FD</c>
/// (alias <c>xray.tun.fd</c>) is set to an open descriptor, Xray validates it (fd ≥ 3,
/// <c>TUNGETIFF</c> shows <c>IFF_TUN</c>, <c>IFF_NO_PI</c> set, device name matches the configured
/// <c>name</c>) and then sets <c>ownsTun=false</c>, which disables <i>all</i> of its own interface
/// management: no MTU, no addresses, no routes, no link up and no teardown. That handoff is a
/// supported escape hatch but not the default, because it moves the whole interface lifecycle —
/// including crash recovery — onto MyVpn.
/// </para>
/// <para>
/// <see cref="IsSupported"/> deliberately answers only "can a TUN device be created on this
/// machine", which is what <c>/dev/net/tun</c> gates. It does <b>not</b> require root: the
/// privileged party is the Xray process (normally started by the helper), not this observer.
/// </para>
/// </remarks>
public sealed class LinuxTunDeviceManager : ITunDeviceManager
{
    /// <summary>The character device (10:200) that must exist for a TUN device to be created.</summary>
    public const string DeviceNodePath = "/dev/net/tun";

    /// <summary>Default interface name; matches the Xray TUN inbound's <c>name</c> field.</summary>
    public const string DefaultTunName = "myvpn0";

    /// <summary>
    /// Maximum interface name length, <c>IFNAMSIZ - 1</c>. The kernel's <c>dev_valid_name()</c>
    /// rejects anything longer, so passing one on would only produce a confusing <c>ip</c> error.
    /// </summary>
    public const int MaxInterfaceNameLength = 15;

    private const string IpTool = "ip";

    private static readonly char[] WhitespaceSeparators = { ' ', '\t' };

    private readonly ICommandRunner _runner;

    public LinuxTunDeviceManager(ICommandRunner? runner = null) =>
        _runner = runner ?? new ProcessCommandRunner();

    /// <summary>
    /// True when <c>/dev/net/tun</c> exists, which is what actually gates TUN creation here.
    /// </summary>
    /// <remarks>
    /// No privilege probe is performed. Creating the interface needs <c>CAP_NET_ADMIN</c> at the
    /// <c>TUNSETIFF</c> ioctl, and that call is made by Xray, which is the privileged party; the
    /// pre-flight for the session checks privileges separately. Reporting <c>false</c> here just
    /// because the UI process is unprivileged would disable TUN mode on a machine where it works.
    /// </remarks>
    public bool IsSupported => File.Exists(DeviceNodePath);

    public string DefaultInterfaceName => DefaultTunName;

    /// <summary>
    /// True when <c>ip link show</c> finds the interface.
    /// </summary>
    /// <remarks>
    /// A missing interface is the normal case before a session starts, so it is reported as
    /// <c>false</c> rather than as an error: <c>ip</c> exits non-zero for an unknown device and
    /// that exit code is the answer.
    /// </remarks>
    public async Task<bool> ExistsAsync(string interfaceName, CancellationToken cancellationToken)
    {
        ValidateInterfaceName(interfaceName);

        var result = await _runner
            .RunAsync(IpTool, new[] { "link", "show", interfaceName }, cancellationToken)
            .ConfigureAwait(false);

        return result.Succeeded;
    }

    /// <summary>
    /// Returns the addresses <c>ip</c> reports for the interface, with their prefix lengths
    /// (for example <c>10.8.0.2/24</c>), because the prefix is what the routing layer needs.
    /// </summary>
    /// <remarks>
    /// An interface with no addresses, an interface that does not exist and output this parser
    /// does not recognise all produce an empty list. None of them is an error worth failing a
    /// diagnostics run over.
    /// </remarks>
    public async Task<IReadOnlyList<string>> GetAddressesAsync(
        string interfaceName,
        CancellationToken cancellationToken)
    {
        ValidateInterfaceName(interfaceName);

        var result = await _runner
            .RunAsync(IpTool, new[] { "-brief", "address", "show", "dev", interfaceName }, cancellationToken)
            .ConfigureAwait(false);

        if (!result.Succeeded || string.IsNullOrEmpty(result.StandardOutput))
        {
            return Array.Empty<string>();
        }

        return ParseAddresses(interfaceName, result.StandardOutput);
    }

    /// <summary>
    /// Extracts the addresses from <c>ip -brief address show dev NAME</c> output.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Exposed because the network-state detector parses the same output, and both places must
    /// agree. The method is a pure function over <c>ip</c>'s text and never throws: anything it
    /// does not recognise is skipped, and whatever could be parsed is returned.
    /// </para>
    /// <para>
    /// Both layouts are accepted — the brief one (<c>name state address…</c>) and the detailed one
    /// (<c>inet 10.0.0.1/24 brd … scope global name</c>) — because a caller may have had to fall
    /// back to the non-brief command. In the detailed layout only the token immediately after
    /// <c>inet</c>/<c>inet6</c> is taken, which keeps the broadcast address, the scope and the
    /// lifetime counters out of the result.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> ParseAddresses(string interfaceName, string output)
    {
        var addresses = new List<string>();

        if (string.IsNullOrEmpty(output))
        {
            return addresses;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            var tokens = line.Split(WhitespaceSeparators, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 0)
            {
                continue;
            }

            // Brief layout: "<name> <state> <address>...". The index suffix ip prints for stacked
            // devices ("eth0@if3") is not part of the name.
            if (tokens.Length > 2 && NameMatches(tokens[0], interfaceName))
            {
                for (var index = 2; index < tokens.Length; index++)
                {
                    AddIfAddress(addresses, seen, tokens[index]);
                }

                continue;
            }

            if (tokens.Length >= 2 && (tokens[0] == "inet" || tokens[0] == "inet6"))
            {
                AddIfAddress(addresses, seen, tokens[1]);
            }
        }

        return addresses;
    }

    /// <summary>
    /// True when <paramref name="name"/> is safe to hand to <c>ip</c> as an interface name.
    /// </summary>
    /// <remarks>
    /// The kernel's <c>dev_valid_name()</c> limit is <see cref="MaxInterfaceNameLength"/>
    /// characters and forbids <c>/</c>, <c>:</c> and whitespace. This check is a little stricter —
    /// it accepts only ASCII letters, digits, <c>_</c>, <c>-</c> and <c>.</c>, and refuses a
    /// leading <c>-</c> — because the name becomes an argv element: a value starting with <c>-</c>
    /// would be read as an option by <c>ip</c>, and control characters could forge a log line.
    /// Arguments are already passed as a vector with no shell, so this is defence in depth rather
    /// than the only protection.
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
            if (!(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Throws when a name must not reach argv.</summary>
    /// <exception cref="ArgumentException">The name is not usable as a Linux interface name.</exception>
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
            $"'{DescribeForLog(interfaceName)}' is not a usable Linux interface name: it must be 1 to "
            + $"{MaxInterfaceNameLength} characters and contain only letters, digits, '_', '-' or '.', "
            + "with no whitespace, '/' or ':' (localization key: error.tun.interface_name_invalid).",
            nameof(interfaceName));
    }

    // ------------------------------------------------------------------ internals

    private static bool NameMatches(string token, string interfaceName)
    {
        var at = token.IndexOf('@');
        var name = at > 0 ? token[..at] : token;
        return string.Equals(name, interfaceName, StringComparison.Ordinal);
    }

    private static void AddIfAddress(List<string> addresses, HashSet<string> seen, string token)
    {
        // "10.0.0.1/24" and "fe80::1/64" are what ip prints. A bare integer — the "1500" of an
        // MTU field, say — is not an address in this position even though IPAddress.TryParse
        // accepts some of them, so the token has to look like one first.
        if (token.IndexOf('.') < 0 && token.IndexOf(':') < 0)
        {
            return;
        }

        if (!NetworkText.IsIpOrCidr(token))
        {
            return;
        }

        if (seen.Add(token))
        {
            addresses.Add(token);
        }
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
