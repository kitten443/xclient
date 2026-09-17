using System.Globalization;
using System.Runtime.InteropServices;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.Proxy;

namespace MyVpn.Platform.MacOS.Proxy;

/// <summary>
/// The <c>networksetup</c> argv vectors MyVpn can issue, as pure functions.
/// </summary>
/// <remarks>
/// <para>
/// <b>The grammar trap this class exists to make impossible.</b> <c>networksetup -setwebproxy</c> is
/// documented as <c>-setwebproxy networkservice domain portnumber authenticated username password</c>
/// and its description says, verbatim: <i>"Set Web proxy for &lt;networkservice&gt; with &lt;domain&gt;
/// and &lt;port number&gt;. Turns proxy on. Optionally, specify &lt;on&gt; or &lt;off&gt; for
/// &lt;authenticated&gt; to enable and disable authenticated proxy support."</i> The trailing
/// <c>on|off</c> is the <i>authenticated-proxy</i> switch, not the enable switch — so the widely
/// copied <c>networksetup -setwebproxy "Wi-Fi" host port off</c> idiom does not disable anything, it
/// only turns authenticated proxy support off, and it leaves the proxy enabled. Enabling and
/// disabling are separate commands: <c>-setwebproxystate</c>, <c>-setsecurewebproxystate</c>,
/// <c>-setsocksfirewallproxystate</c> (and <c>-setautoproxystate</c> for PAC).
/// </para>
/// <para>
/// Every value is a separate argv element. Service names contain spaces routinely
/// ("Built-in Ethernet", "Thunderbolt Bridge"), which is exactly why the argv vector matters: nothing
/// is ever interpolated into a shell string, so a service name or bypass domain cannot become a
/// command.
/// </para>
/// <para>
/// Each builder validates its service name. The name always lands in a fixed argv position, but a
/// value starting with <c>-</c> is refused anyway so a future edit cannot hand
/// <c>networksetup</c> something it would parse as a flag.
/// </para>
/// </remarks>
public static class NetworksetupCommands
{
    /// <summary>The tool that owns every SystemConfiguration network preference.</summary>
    public const string Binary = "networksetup";

    /// <summary>Longest accepted network-service name.</summary>
    public const int MaxServiceNameLength = 64;

    /// <summary>
    /// Literal that clears a DNS server list. The man page documents lowercase <c>empty</c> for
    /// <c>-setdnsservers</c>/<c>-setsearchdomains</c> and capitalised <c>Empty</c> for
    /// <c>-setproxybypassdomains</c>; the difference is deliberate here and asserted by tests.
    /// </summary>
    public const string ClearDnsServersLiteral = "empty";

    /// <summary>Literal that clears the proxy bypass list (capitalised in the man page).</summary>
    public const string ClearBypassDomainsLiteral = "Empty";

    /// <summary>Lists every network service; a leading <c>*</c> marks a disabled one.</summary>
    public static IReadOnlyList<string> ListAllServices() => new[] { "-listallnetworkservices" };

    /// <summary>Lists services in the order they are contacted; the first is the primary service.</summary>
    public static IReadOnlyList<string> ListServiceOrder() => new[] { "-listnetworkserviceorder" };

    public static IReadOnlyList<string> GetWebProxy(string service) =>
        new[] { "-getwebproxy", RequireService(service) };

    /// <summary>Sets the web proxy and turns it on; does not touch authenticated-proxy support.</summary>
    public static IReadOnlyList<string> SetWebProxy(string service, string host, int port) =>
        new[] { "-setwebproxy", RequireService(service), RequireHost(host), RequirePort(port) };

    public static IReadOnlyList<string> SetWebProxyState(string service, bool on) =>
        new[] { "-setwebproxystate", RequireService(service), OnOff(on) };

    public static IReadOnlyList<string> GetSecureWebProxy(string service) =>
        new[] { "-getsecurewebproxy", RequireService(service) };

    /// <summary>Sets the HTTPS proxy and turns it on; the state verb remains authoritative.</summary>
    public static IReadOnlyList<string> SetSecureWebProxy(string service, string host, int port) =>
        new[] { "-setsecurewebproxy", RequireService(service), RequireHost(host), RequirePort(port) };

    public static IReadOnlyList<string> SetSecureWebProxyState(string service, bool on) =>
        new[] { "-setsecurewebproxystate", RequireService(service), OnOff(on) };

    public static IReadOnlyList<string> GetSocksProxy(string service) =>
        new[] { "-getsocksfirewallproxy", RequireService(service) };

    public static IReadOnlyList<string> SetSocksProxy(string service, string host, int port) =>
        new[] { "-setsocksfirewallproxy", RequireService(service), RequireHost(host), RequirePort(port) };

    public static IReadOnlyList<string> SetSocksProxyState(string service, bool on) =>
        new[] { "-setsocksfirewallproxystate", RequireService(service), OnOff(on) };

    public static IReadOnlyList<string> GetAutoProxyUrl(string service) =>
        new[] { "-getautoproxyurl", RequireService(service) };

    /// <summary>Sets the PAC URL <i>and enables PAC</i>, which is what the man page documents.</summary>
    public static IReadOnlyList<string> SetAutoProxyUrl(string service, string url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        return new[] { "-setautoproxyurl", RequireService(service), url };
    }

    /// <summary>
    /// Turns PAC on or off.
    /// </summary>
    /// <remarks>
    /// Not in the July 2020 man-page snapshot mirrored for this project (which documents only
    /// <c>-setautoproxyurl</c>, a verb that can enable PAC but not disable it), but present in
    /// current <c>networksetup</c> builds and used by shipping scripts as
    /// <c>networksetup -setautoproxystate "Wi-Fi" off</c>. It is the only way to disable PAC, so
    /// <see cref="MacSystemProxy.ResetAsync"/> depends on it; the behaviour is therefore
    /// runtime-unverified on this host and flagged as such in the platform report.
    /// </remarks>
    public static IReadOnlyList<string> SetAutoProxyState(string service, bool on) =>
        new[] { "-setautoproxystate", RequireService(service), OnOff(on) };

    public static IReadOnlyList<string> GetBypassDomains(string service) =>
        new[] { "-getproxybypassdomains", RequireService(service) };

    /// <summary>Replaces the bypass list; an empty list clears it with the documented literal.</summary>
    public static IReadOnlyList<string> SetBypassDomains(string service, IReadOnlyCollection<string> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);

        var validated = RequireService(service);
        var arguments = new List<string>(2 + Math.Max(domains.Count, 1)) { "-setproxybypassdomains", validated };

        if (domains.Count == 0)
        {
            arguments.Add(ClearBypassDomainsLiteral);
        }
        else
        {
            arguments.AddRange(domains.Select(RequireBypassDomain));
        }

        return arguments;
    }

    public static IReadOnlyList<string> GetDnsServers(string service) =>
        new[] { "-getdnsservers", RequireService(service) };

    /// <summary>Sets the resolver list; an empty list clears it with the documented literal.</summary>
    /// <remarks>
    /// Shared with <c>MacDnsConfigurator</c> on purpose: one place defines the networksetup grammar,
    /// so the two executors cannot drift apart on a literal as small and as load-bearing as
    /// <c>empty</c>.
    /// </remarks>
    public static IReadOnlyList<string> SetDnsServers(string service, IReadOnlyCollection<string> servers)
    {
        ArgumentNullException.ThrowIfNull(servers);

        var validated = RequireService(service);
        var arguments = new List<string>(2 + Math.Max(servers.Count, 1)) { "-setdnsservers", validated };

        if (servers.Count == 0)
        {
            arguments.Add(ClearDnsServersLiteral);
        }
        else
        {
            foreach (var server in servers)
            {
                if (!NetworkText.IsIpAddress(server))
                {
                    throw new ArgumentException($"'{server}' is not an IP literal.", nameof(servers));
                }

                arguments.Add(server);
            }
        }

        return arguments;
    }

    /// <summary>
    /// Every argv shape this class can produce, so the grammar can be asserted exhaustively in one
    /// place — above all that no <c>-set*proxy</c> call carries a trailing <c>on|off</c>.
    /// </summary>
    public static IReadOnlyList<IReadOnlyList<string>> AllShapes() => new[]
    {
        ListAllServices(),
        ListServiceOrder(),
        GetWebProxy("Wi-Fi"),
        SetWebProxy("Wi-Fi", "127.0.0.1", 10809),
        SetWebProxyState("Wi-Fi", true),
        SetWebProxyState("Wi-Fi", false),
        GetSecureWebProxy("Wi-Fi"),
        SetSecureWebProxy("Wi-Fi", "127.0.0.1", 10809),
        SetSecureWebProxyState("Wi-Fi", false),
        GetSocksProxy("Wi-Fi"),
        SetSocksProxy("Wi-Fi", "127.0.0.1", 10808),
        SetSocksProxyState("Wi-Fi", true),
        GetAutoProxyUrl("Wi-Fi"),
        SetAutoProxyUrl("Wi-Fi", "http://127.0.0.1:10810/proxy.pac"),
        SetAutoProxyState("Wi-Fi", false),
        GetBypassDomains("Wi-Fi"),
        SetBypassDomains("Wi-Fi", new[] { "localhost" }),
        SetBypassDomains("Wi-Fi", Array.Empty<string>()),
        GetDnsServers("Wi-Fi"),
        SetDnsServers("Wi-Fi", new[] { "1.1.1.1" }),
        SetDnsServers("Wi-Fi", Array.Empty<string>()),
    };

    /// <summary>True when a network-service name is safe to hand to <c>networksetup</c>.</summary>
    public static bool IsSafeServiceName(string? service)
    {
        if (string.IsNullOrWhiteSpace(service) || service.Length > MaxServiceNameLength)
        {
            return false;
        }

        if (service[0] == '-')
        {
            return false;
        }

        return !service.Any(char.IsControl);
    }

    private static string RequireService(string service)
    {
        if (service is null)
        {
            throw new ArgumentNullException(nameof(service));
        }

        if (!IsSafeServiceName(service))
        {
            throw new ArgumentException(
                $"'{service}' is not a usable network-service name.", nameof(service));
        }

        return service;
    }

    private static string RequireHost(string host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        if (host[0] == '-')
        {
            throw new ArgumentException($"'{host}' is not a usable proxy host.", nameof(host));
        }

        return host;
    }

    private static string RequirePort(int port)
    {
        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be 1-65535.");
        }

        return port.ToString(CultureInfo.InvariantCulture);
    }

    private static string RequireBypassDomain(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        if (domain[0] == '-' || domain.Any(char.IsControl))
        {
            throw new ArgumentException($"'{domain}' is not a usable bypass domain.", nameof(domain));
        }

        return domain;
    }

    private static string OnOff(bool on) => on ? "on" : "off";
}

/// <summary>One proxy's settings as <c>networksetup -get*proxy</c> reports them.</summary>
/// <remarks>
/// <c>Url</c> is only populated by <c>-getautoproxyurl</c>; <c>Server</c>/<c>Port</c> only by the
/// manual getters. A disabled proxy still reports its server and port, which is why both are
/// captured regardless of <see cref="Enabled"/> — the values are the user's, and restoring them is
/// the difference between "the VPN exited" and "the user's corporate proxy configuration was
/// destroyed".
/// </remarks>
public sealed record NetworksetupProxyEntry(bool Enabled, string? Server, int Port, string? Url)
{
    /// <summary>The entry as <c>host:port</c>, or <c>null</c> when no server is configured.</summary>
    public string? Describe() =>
        string.IsNullOrWhiteSpace(Server)
            ? null
            : Port > 0
                ? string.Create(CultureInfo.InvariantCulture, $"{Server}:{Port}")
                : Server;
}

/// <summary>
/// Configures the macOS system proxy through <c>networksetup</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Per service, not global.</b> <c>networksetup</c> operates on <i>network services</i>
/// ("Wi-Fi", "Thunderbolt Bridge"), not on BSD interfaces, and there is no global proxy object: what
/// applications see as "the system proxy" is the <b>primary</b> service's configuration. The plan's
/// <see cref="SystemProxyPlan.TargetInterfaces"/> entries are therefore treated as service names; an
/// empty list means the primary service, resolved from <c>-listnetworkserviceorder</c> (the first
/// entry) with <c>-listallnetworkservices</c> as the fallback.
/// </para>
/// <para>
/// <b>Changes persist across reboot.</b> These are SystemConfiguration preference writes, so a stale
/// proxy pointing at a local port that no longer exists survives a crash and a reboot and black-holes
/// every proxy-honouring application. <see cref="ResetAsync"/> therefore actively turns the proxies
/// <i>off</i> rather than trusting that a previous run cleaned up, and it walks every service rather
/// than only the primary one, because the primary service changes when the user moves between Wi-Fi
/// and Ethernet.
/// </para>
/// <para>
/// <b>Known interface limitation, reported rather than hidden.</b>
/// <see cref="SystemProxySnapshot"/> is a single flat record with no field for the service it came
/// from, so a faithful per-service restore cannot be expressed through the abstraction. Capture reads
/// the primary service and <see cref="RestoreAsync"/> writes back to the service that is primary at
/// restore time. Adding a service identifier (or a per-service map) to the snapshot is the interface
/// change that would make this exact; until then the behaviour is documented and the risk is stated
/// in the platform report.
/// </para>
/// <para>
/// <b>What proxy mode cannot do.</b> It only affects applications that choose to honour the system
/// proxy — Firefox uses it only with "Use system proxy settings", JVM applications need
/// <c>java.net.useSystemProxies</c>, and many Electron/Chromium applications override proxy
/// configuration in code. It also cannot cover UDP/QUIC. Proxy mode is never treated as leak
/// protection; TUN mode with the Kill Switch is.
/// </para>
/// </remarks>
public sealed class MacSystemProxy : ISystemProxy
{
    private readonly ICommandRunner _runner;
    private readonly Func<bool> _isElevated;

    public MacSystemProxy(ICommandRunner? runner = null, Func<bool>? isElevated = null)
    {
        _runner = runner ?? new ProcessCommandRunner();
        _isElevated = isElevated ?? DefaultElevationCheck;
    }

    /// <summary>
    /// True when this is macOS and <c>networksetup</c> exists.
    /// </summary>
    /// <remarks>
    /// Read-only inspection works unprivileged, so elevation is not part of the capability answer;
    /// the mutating calls report the missing privilege themselves. The property spawns no process —
    /// it is read by the UI.
    /// </remarks>
    public bool IsSupported => OperatingSystem.IsMacOS() && _runner.Exists(NetworksetupCommands.Binary);

    public async Task<Result<SystemProxySnapshot>> CaptureAsync(CancellationToken cancellationToken)
    {
        var guard = Guard();
        if (guard is not null)
        {
            return Result<SystemProxySnapshot>.Fail(guard);
        }

        var service = await ResolvePrimaryServiceAsync(cancellationToken).ConfigureAwait(false);
        if (service is null)
        {
            return Result<SystemProxySnapshot>.Fail(NoService());
        }

        var http = await ReadEntryAsync(NetworksetupCommands.GetWebProxy(service), cancellationToken)
            .ConfigureAwait(false);
        var https = await ReadEntryAsync(NetworksetupCommands.GetSecureWebProxy(service), cancellationToken)
            .ConfigureAwait(false);
        var socks = await ReadEntryAsync(NetworksetupCommands.GetSocksProxy(service), cancellationToken)
            .ConfigureAwait(false);
        var pac = await ReadEntryAsync(NetworksetupCommands.GetAutoProxyUrl(service), cancellationToken)
            .ConfigureAwait(false);
        var bypass = await ReadBypassDomainsAsync(service, cancellationToken).ConfigureAwait(false);

        var mode = pac.Enabled
            ? "auto"
            : http.Enabled || https.Enabled || socks.Enabled
                ? "manual"
                : "none";

        return Result<SystemProxySnapshot>.Ok(new SystemProxySnapshot
        {
            Mode = mode,
            Enabled = !string.Equals(mode, "none", StringComparison.Ordinal),
            PacUrl = pac.Url,
            HttpProxy = http.Describe(),
            HttpsProxy = https.Describe(),
            SocksProxy = socks.Describe(),
            BypassList = bypass.Count == 0 ? null : string.Join(", ", bypass),
        });
    }

    public async Task<Result> ApplyAsync(SystemProxyPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return validation;
        }

        var guard = Guard(requireElevation: true);
        if (guard is not null)
        {
            return Result.Fail(guard);
        }

        foreach (var target in plan.TargetInterfaces)
        {
            if (!NetworksetupCommands.IsSafeServiceName(target))
            {
                return Result.Fail(ServiceNameInvalid(target));
            }
        }

        var services = await ResolveTargetServicesAsync(plan.TargetInterfaces, cancellationToken)
            .ConfigureAwait(false);

        if (services.Count == 0)
        {
            return Result.Fail(NoService());
        }

        // Every write is attempted per service, and the first failure stops the sequence for that
        // service and is reported with the command that failed. A half-configured proxy that reports
        // success is the failure mode this guards against.
        foreach (var service in services)
        {
            var applied = await ApplyToServiceAsync(service, plan, cancellationToken).ConfigureAwait(false);
            if (applied.IsFailure)
            {
                return applied;
            }
        }

        return Result.Ok();
    }

    public async Task<Result> RestoreAsync(SystemProxySnapshot snapshot, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var guard = Guard(requireElevation: true);
        if (guard is not null)
        {
            return Result.Fail(guard);
        }

        var service = await ResolvePrimaryServiceAsync(cancellationToken).ConfigureAwait(false);
        if (service is null)
        {
            return Result.Fail(NoService());
        }

        foreach (var arguments in BuildRestoreCommands(service, snapshot))
        {
            var result = await RunAsync(arguments, cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return Result.Fail(CommandFailed("error.proxy.restore_failed", arguments, result));
            }
        }

        return Result.Ok();
    }

    /// <summary>
    /// Turns the system proxy off on every network service.
    /// </summary>
    /// <remarks>
    /// Emergency cleanup has no captured snapshot, and a proxy pointing at a listener that no longer
    /// exists survives a reboot. The four state verbs are issued per service, over the whole service
    /// list rather than the primary one, because the user may switch between Wi-Fi and Ethernet after
    /// the crash. Bypass domains are deliberately left alone: they only exclude hosts from a proxy,
    /// and clearing them would destroy a user's own configuration to no benefit.
    /// </remarks>
    public async Task<Result> ResetAsync(CancellationToken cancellationToken)
    {
        var guard = Guard(requireElevation: true);
        if (guard is not null)
        {
            return Result.Fail(guard);
        }

        var services = await ListServicesAsync(includeDisabled: true, cancellationToken).ConfigureAwait(false);
        if (services.Count == 0)
        {
            return Result.Fail(NoService());
        }

        var failures = new List<string>();

        foreach (var service in services)
        {
            foreach (var arguments in new[]
                     {
                         NetworksetupCommands.SetWebProxyState(service, on: false),
                         NetworksetupCommands.SetSecureWebProxyState(service, on: false),
                         NetworksetupCommands.SetSocksProxyState(service, on: false),
                         NetworksetupCommands.SetAutoProxyState(service, on: false),
                     })
            {
                var result = await RunAsync(arguments, cancellationToken).ConfigureAwait(false);
                if (!result.Succeeded)
                {
                    failures.Add(
                        $"'{service}': {string.Join(' ', arguments)} failed: {Trim(result.Combined)}");
                }
            }
        }

        return failures.Count == 0
            ? Result.Ok()
            : Result.Fail(ResetFailed(string.Join("; ", failures)));
    }

    public async Task<SystemProxyState> InspectAsync(CancellationToken cancellationToken)
    {
        if (!IsSupported)
        {
            return new SystemProxyState { IsConfigured = false };
        }

        var service = await ResolvePrimaryServiceAsync(cancellationToken).ConfigureAwait(false);
        if (service is null)
        {
            return new SystemProxyState { IsConfigured = false };
        }

        var http = await ReadEntryAsync(NetworksetupCommands.GetWebProxy(service), cancellationToken)
            .ConfigureAwait(false);
        var socks = await ReadEntryAsync(NetworksetupCommands.GetSocksProxy(service), cancellationToken)
            .ConfigureAwait(false);
        var pac = await ReadEntryAsync(NetworksetupCommands.GetAutoProxyUrl(service), cancellationToken)
            .ConfigureAwait(false);

        var active = http.Enabled ? http.Describe() : null;
        active ??= socks.Enabled ? socks.Describe() : null;

        // "Points at MyVpn" is judged from the loopback host, because this executor cannot know which
        // local port MyVpn chose. A loopback proxy that is not MyVpn's would be a false positive, which
        // is why the Kill Switch never relies on this value.
        var pointsAtUs = IsLoopback(active) || IsLoopback(pac.Url);

        return new SystemProxyState
        {
            IsConfigured = http.Enabled || socks.Enabled || pac.Enabled,
            ActiveProxy = active,
            PacUrl = string.IsNullOrWhiteSpace(pac.Url) ? null : pac.Url,
            PointsAtMyVpn = pointsAtUs,
        };
    }

    // ------------------------------------------------------------------ pure helpers

    /// <summary>
    /// Parses <c>networksetup -listallnetworkservices</c>, dropping the header line and the leading
    /// <c>*</c> that marks a disabled service.
    /// </summary>
    public static IReadOnlyList<string> ParseServiceList(string? output) =>
        ParseServiceEntries(output).Select(e => e.Name).ToArray();

    /// <summary>
    /// Parses <c>-listallnetworkservices</c> keeping the enabled/disabled distinction, which
    /// <see cref="ResetAsync"/> needs: a disabled service still carries proxy preferences that will
    /// apply the moment the user enables it again.
    /// </summary>
    public static IReadOnlyList<(string Name, bool Enabled)> ParseServiceEntries(string? output)
    {
        var services = new List<(string Name, bool Enabled)>();

        if (string.IsNullOrEmpty(output))
        {
            return services;
        }

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("An asterisk", StringComparison.Ordinal))
            {
                continue;
            }

            var enabled = true;
            if (line[0] == '*')
            {
                enabled = false;
                line = line[1..].Trim();
            }

            if (line.Length > 0 && NetworksetupCommands.IsSafeServiceName(line))
            {
                services.Add((line, enabled));
            }
        }

        return services;
    }

    /// <summary>
    /// Parses <c>networksetup -listnetworkserviceorder</c>; the first entry is the primary service.
    /// </summary>
    /// <remarks>
    /// The output is a numbered list followed by a parenthesised detail line per service
    /// ("(Hardware Port: Wi-Fi, Device: en0)"), so only the numbered lines are taken and the
    /// parenthesised detail is skipped.
    /// </remarks>
    public static IReadOnlyList<string> ParseServiceOrder(string? output)
    {
        var services = new List<string>();

        if (string.IsNullOrEmpty(output))
        {
            return services;
        }

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length < 4 || line[0] != '(')
            {
                continue;
            }

            var close = line.IndexOf(')');
            if (close <= 1)
            {
                continue;
            }

            var index = line[1..close];
            if (!index.All(char.IsAsciiDigit))
            {
                // The detail line "(Hardware Port: …)" is not a numbered entry.
                continue;
            }

            var name = line[(close + 1)..].Trim();
            if (name.Length > 0 && NetworksetupCommands.IsSafeServiceName(name))
            {
                services.Add(name);
            }
        }

        return services;
    }

    /// <summary>
    /// Parses the output of <c>-getwebproxy</c>, <c>-getsecurewebproxy</c>,
    /// <c>-getsocksfirewallproxy</c> or <c>-getautoproxyurl</c>.
    /// </summary>
    /// <remarks>
    /// A line the parser does not recognise is skipped rather than throwing: the getters' output is
    /// plain <c>Key: value</c> text that has been stable for years, and an inspection path must not
    /// fail because a future macOS adds a line.
    /// </remarks>
    public static NetworksetupProxyEntry ParseProxyEntry(string? output)
    {
        var enabled = false;
        string? server = null;
        string? url = null;
        var port = 0;

        if (string.IsNullOrEmpty(output))
        {
            return new NetworksetupProxyEntry(false, null, 0, null);
        }

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            var key = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();

            if (key.Equals("Enabled", StringComparison.OrdinalIgnoreCase))
            {
                enabled = value.Equals("Yes", StringComparison.OrdinalIgnoreCase)
                          || value.Equals("1", StringComparison.Ordinal)
                          || value.Equals("on", StringComparison.OrdinalIgnoreCase);
            }
            else if (key.Equals("Server", StringComparison.OrdinalIgnoreCase))
            {
                server = NullLiteral(value);
            }
            else if (key.Equals("Port", StringComparison.OrdinalIgnoreCase))
            {
                _ = int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out port);
            }
            else if (key.Equals("URL", StringComparison.OrdinalIgnoreCase))
            {
                url = NullLiteral(value);
            }
        }

        return new NetworksetupProxyEntry(enabled, server, port, url);
    }

    /// <summary>
    /// Parses <c>-getproxybypassdomains</c>: either a list of domains or the "there aren't any"
    /// sentence.
    /// </summary>
    public static IReadOnlyList<string> ParseBypassDomains(string? output)
    {
        var domains = new List<string>();

        if (string.IsNullOrEmpty(output) || output.Contains("aren't any", StringComparison.OrdinalIgnoreCase))
        {
            return domains;
        }

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length > 0)
            {
                domains.Add(line);
            }
        }

        return domains;
    }

    /// <summary>
    /// Merges the user's existing bypass list with the one MyVpn wants.
    /// </summary>
    /// <remarks>
    /// <c>-setproxybypassdomains</c> <i>replaces</i> the list, so writing only MyVpn's entries would
    /// silently delete the user's own exceptions. The previous list is available in
    /// <see cref="SystemProxyPlan.Previous"/>; when it is absent, only MyVpn's entries are written and
    /// the loss is unavoidable — which is one more reason the capture happens before every apply.
    /// </remarks>
    public static IReadOnlyList<string> MergeBypassDomains(SystemProxyPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var entries = new List<string>();

        if (!string.IsNullOrWhiteSpace(plan.Previous?.BypassList))
        {
            entries.AddRange(plan.Previous!.BypassList!
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        // Loopback is always bypassed: sending a request for MyVpn's own local inbound back through
        // the proxy is a loop, and it breaks the connection verification the session performs.
        entries.Add("localhost");
        entries.Add("127.0.0.1");
        entries.Add("::1");

        entries.AddRange(plan.BypassDomains.Where(d => !string.IsNullOrWhiteSpace(d)));
        entries.AddRange(plan.BypassNetworks.Select(n => n.ToString()));

        return entries
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// Builds the write sequence that puts a captured snapshot back.
    /// </summary>
    /// <remarks>
    /// Pure, so the exact argv of a restore — including the case where the snapshot says "off" — is
    /// asserted by tests rather than discovered on a user's machine after the VPN exits.
    /// </remarks>
    public static IReadOnlyList<IReadOnlyList<string>> BuildRestoreCommands(
        string service,
        SystemProxySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var commands = new List<IReadOnlyList<string>>();
        var manual = !string.Equals(snapshot.Mode, "auto", StringComparison.OrdinalIgnoreCase);

        if (manual)
        {
            commands.AddRange(BuildManualCommands(
                service,
                snapshot.HttpProxy,
                snapshot.HttpsProxy,
                snapshot.SocksProxy,
                snapshot.Enabled));
        }
        else
        {
            // Whatever the snapshot says, the manual proxies must end up off in PAC mode.
            commands.Add(NetworksetupCommands.SetWebProxyState(service, on: false));
            commands.Add(NetworksetupCommands.SetSecureWebProxyState(service, on: false));
            commands.Add(NetworksetupCommands.SetSocksProxyState(service, on: false));
        }

        if (!string.IsNullOrWhiteSpace(snapshot.PacUrl) && !manual)
        {
            commands.Add(NetworksetupCommands.SetAutoProxyUrl(service, snapshot.PacUrl!));
        }
        else
        {
            commands.Add(NetworksetupCommands.SetAutoProxyState(service, on: false));
        }

        if (!string.IsNullOrWhiteSpace(snapshot.BypassList))
        {
            commands.Add(NetworksetupCommands.SetBypassDomains(
                service,
                snapshot.BypassList!
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)));
        }

        return commands;
    }

    // ------------------------------------------------------------------ error mapping (pure)

    /// <summary>Error for a call made on a host that is not macOS.</summary>
    public static MyVpnError UnsupportedOnThisHost() =>
        new MyVpnError(
            ErrorCodes.SystemProxySetFailed,
            "error.platform.macos_only",
            ErrorSeverity.Error,
            "The macOS system proxy is configured with 'networksetup', which only exists on macOS. "
            + "This call is refused before any process is started.",
            "diagnostics.run");

    /// <summary>Error for a missing <c>networksetup</c>.</summary>
    public static MyVpnError ToolMissing() =>
        new MyVpnError(
            ErrorCodes.PlatformToolMissing,
            "error.platform.tool_missing",
            ErrorSeverity.Error,
            "The 'networksetup' tool was not found, so the system proxy cannot be configured.",
            "diagnostics.run")
            .WithArg("tool", NetworksetupCommands.Binary);

    /// <summary>Error for a mutating call without privileges.</summary>
    public static MyVpnError NotElevated() =>
        new MyVpnError(
            ErrorCodes.PrivilegeDenied,
            "error.proxy.needs_privileges",
            ErrorSeverity.Error,
            "Changing network settings with 'networksetup' requires administrator privileges. "
            + "MyVpn needs its privileged helper installed; the UI must never run as root itself.",
            "privilege.install_helper");

    /// <summary>Error for a machine with no usable network service.</summary>
    public static MyVpnError NoService() =>
        new MyVpnError(
            ErrorCodes.SystemProxySetFailed,
            "error.proxy.no_service",
            ErrorSeverity.Error,
            "No network service could be resolved, so there is nothing to configure. "
            + "'networksetup -listallnetworkservices' returned no usable entries.",
            "diagnostics.run");

    /// <summary>Error for a rejected service name in the plan.</summary>
    public static MyVpnError ServiceNameInvalid(string? service) =>
        new MyVpnError(
            ErrorCodes.SystemProxySetFailed,
            "error.proxy.service_name_invalid",
            ErrorSeverity.Error,
            $"'{service}' is not a usable network-service name.",
            "diagnostics.run");

    /// <summary>Error for a failed write, naming the exact command that failed.</summary>
    public static MyVpnError CommandFailed(string messageKey, IReadOnlyList<string> arguments, CommandResult result) =>
        new MyVpnError(
            ErrorCodes.SystemProxySetFailed,
            messageKey,
            ErrorSeverity.Error,
            $"networksetup {string.Join(' ', arguments)} failed: {Trim(result.Combined)}");

    /// <summary>Error for a reset that could not turn every proxy off.</summary>
    public static MyVpnError ResetFailed(string detail) =>
        new MyVpnError(
            ErrorCodes.SystemProxyRestoreFailed,
            "error.proxy.restore_failed",
            ErrorSeverity.Critical,
            "The system proxy could not be fully disabled, so an application may still be pointed at "
            + $"a proxy that is no longer listening: {detail}",
            "network.restore");

    // ------------------------------------------------------------------ internals

    private MyVpnError? Guard(bool requireElevation = false)
    {
        if (!OperatingSystem.IsMacOS())
        {
            return UnsupportedOnThisHost();
        }

        if (!_runner.Exists(NetworksetupCommands.Binary))
        {
            return ToolMissing();
        }

        if (requireElevation && !_isElevated())
        {
            return NotElevated();
        }

        return null;
    }

    private async Task<Result> ApplyToServiceAsync(
        string service,
        SystemProxyPlan plan,
        CancellationToken cancellationToken)
    {
        var usePac = plan.UsePac && !string.IsNullOrWhiteSpace(plan.PacUrl);

        // (1) Bypass domains first: they are values, not switches, and writing them before any proxy
        //     is enabled means the desktop never sees a proxy without its exceptions in place.
        if (plan.BypassDomains.Count > 0 || plan.BypassNetworks.Count > 0
            || !string.IsNullOrWhiteSpace(plan.Previous?.BypassList))
        {
            var merged = MergeBypassDomains(plan);
            var bypass = await RunAsync(
                NetworksetupCommands.SetBypassDomains(service, merged), cancellationToken)
                .ConfigureAwait(false);

            if (!bypass.Succeeded)
            {
                return Result.Fail(CommandFailed(
                    "error.proxy.set_failed", NetworksetupCommands.SetBypassDomains(service, merged), bypass));
            }
        }

        if (usePac)
        {
            // (2) PAC mode: turn the manual proxies off first, then set (and thereby enable) PAC, so
            //     the last state written is the one the plan asked for.
            foreach (var off in new[]
                     {
                         NetworksetupCommands.SetWebProxyState(service, on: false),
                         NetworksetupCommands.SetSecureWebProxyState(service, on: false),
                         NetworksetupCommands.SetSocksProxyState(service, on: false),
                     })
            {
                var result = await RunAsync(off, cancellationToken).ConfigureAwait(false);
                if (!result.Succeeded)
                {
                    return Result.Fail(CommandFailed("error.proxy.set_failed", off, result));
                }
            }

            var pac = await RunAsync(
                NetworksetupCommands.SetAutoProxyUrl(service, plan.PacUrl!), cancellationToken)
                .ConfigureAwait(false);

            return pac.Succeeded
                ? Result.Ok()
                : Result.Fail(CommandFailed(
                    "error.proxy.set_failed",
                    NetworksetupCommands.SetAutoProxyUrl(service, plan.PacUrl!),
                    pac));
        }

        // (3) Manual mode. Each protocol's values are written and then its state made explicit —
        //     including the "off" case, because a previous apply may have left it on.
        foreach (var step in BuildManualCommands(
                     service,
                     plan.EnableHttp ? $"127.0.0.1:{plan.HttpPort}" : null,
                     plan.EnableHttp ? $"127.0.0.1:{plan.HttpPort}" : null,
                     plan.EnableSocks ? $"127.0.0.1:{plan.SocksPort}" : null,
                     enabled: true))
        {
            var result = await RunAsync(step, cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return Result.Fail(CommandFailed("error.proxy.set_failed", step, result));
            }
        }

        // (4) PAC must not stay enabled alongside manual proxies: it would win for applications that
        //     evaluate it, pointing them at a PAC file MyVpn is not serving in this mode.
        var autoOff = await RunAsync(
            NetworksetupCommands.SetAutoProxyState(service, on: false), cancellationToken)
            .ConfigureAwait(false);

        return autoOff.Succeeded
            ? Result.Ok()
            : Result.Fail(CommandFailed(
                "error.proxy.set_failed", NetworksetupCommands.SetAutoProxyState(service, on: false), autoOff));
    }

    /// <summary>
    /// Builds the value+state writes for the three manual proxies.
    /// </summary>
    /// <remarks>
    /// A <c>null</c> endpoint means "this protocol is not in the plan", which is expressed as an
    /// explicit <c>off</c> rather than as silence: silence would leave a proxy from a previous apply
    /// enabled and pointing at a port that is no longer listening.
    /// </remarks>
    private static IReadOnlyList<IReadOnlyList<string>> BuildManualCommands(
        string service,
        string? http,
        string? https,
        string? socks,
        bool enabled)
    {
        var commands = new List<IReadOnlyList<string>>(6);

        var (httpHost, httpPort) = SplitHostPort(http);
        if (httpHost is not null && enabled)
        {
            commands.Add(NetworksetupCommands.SetWebProxy(service, httpHost, httpPort));
            commands.Add(NetworksetupCommands.SetWebProxyState(service, on: true));
        }
        else
        {
            commands.Add(NetworksetupCommands.SetWebProxyState(service, on: false));
        }

        var (httpsHost, httpsPort) = SplitHostPort(https);
        if (httpsHost is not null && enabled)
        {
            commands.Add(NetworksetupCommands.SetSecureWebProxy(service, httpsHost, httpsPort));
            commands.Add(NetworksetupCommands.SetSecureWebProxyState(service, on: true));
        }
        else
        {
            commands.Add(NetworksetupCommands.SetSecureWebProxyState(service, on: false));
        }

        var (socksHost, socksPort) = SplitHostPort(socks);
        if (socksHost is not null && enabled)
        {
            commands.Add(NetworksetupCommands.SetSocksProxy(service, socksHost, socksPort));
            commands.Add(NetworksetupCommands.SetSocksProxyState(service, on: true));
        }
        else
        {
            commands.Add(NetworksetupCommands.SetSocksProxyState(service, on: false));
        }

        return commands;
    }

    /// <summary>
    /// Splits a captured <c>host:port</c> value. IPv6 literals keep their brackets, so the last colon
    /// is the separator only for the bracketed form.
    /// </summary>
    private static (string? Host, int Port) SplitHostPort(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return (null, 0);
        }

        var text = value.Trim();

        // An IPv6 literal is bracketed ("[::1]:1080"), so only the bracketed form may split on the
        // last colon; a bare host with no port is kept whole.
        var separator = -1;
        if (text.StartsWith('['))
        {
            var bracket = text.LastIndexOf("]:", StringComparison.Ordinal);
            separator = bracket >= 0 ? bracket + 1 : -1;
        }
        else if (text.IndexOf(':') == text.LastIndexOf(':'))
        {
            separator = text.LastIndexOf(':');
        }

        if (separator <= 0)
        {
            return (text, 0);
        }

        var host = text[..separator].Trim('[', ']');
        _ = int.TryParse(text[(separator + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var port);

        return (host, port);
    }

    private async Task<IReadOnlyList<string>> ResolveTargetServicesAsync(
        IReadOnlyList<string> targets,
        CancellationToken cancellationToken)
    {
        if (targets.Count > 0)
        {
            return targets
                .Where(NetworksetupCommands.IsSafeServiceName)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
        }

        var primary = await ResolvePrimaryServiceAsync(cancellationToken).ConfigureAwait(false);
        return primary is null ? Array.Empty<string>() : new[] { primary };
    }

    private async Task<string?> ResolvePrimaryServiceAsync(CancellationToken cancellationToken)
    {
        var order = await RunAsync(NetworksetupCommands.ListServiceOrder(), cancellationToken)
            .ConfigureAwait(false);

        if (order.Succeeded)
        {
            var primary = ParseServiceOrder(order.StandardOutput).FirstOrDefault();
            if (primary is not null)
            {
                return primary;
            }
        }

        var all = await ListServicesAsync(includeDisabled: false, cancellationToken).ConfigureAwait(false);
        return all.FirstOrDefault();
    }

    private async Task<IReadOnlyList<string>> ListServicesAsync(
        bool includeDisabled,
        CancellationToken cancellationToken)
    {
        var result = await RunAsync(NetworksetupCommands.ListAllServices(), cancellationToken)
            .ConfigureAwait(false);

        if (!result.Succeeded)
        {
            return Array.Empty<string>();
        }

        return includeDisabled
            ? ParseServiceList(result.StandardOutput)
            : ParseServiceEntries(result.StandardOutput)
                .Where(e => e.Enabled)
                .Select(e => e.Name)
                .ToArray();
    }

    private async Task<NetworksetupProxyEntry> ReadEntryAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var result = await RunAsync(arguments, cancellationToken).ConfigureAwait(false);
        return result.Succeeded
            ? ParseProxyEntry(result.StandardOutput)
            : new NetworksetupProxyEntry(false, null, 0, null);
    }

    private async Task<IReadOnlyList<string>> ReadBypassDomainsAsync(
        string service,
        CancellationToken cancellationToken)
    {
        var result = await RunAsync(NetworksetupCommands.GetBypassDomains(service), cancellationToken)
            .ConfigureAwait(false);

        return result.Succeeded ? ParseBypassDomains(result.StandardOutput) : Array.Empty<string>();
    }

    private Task<CommandResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken) =>
        _runner.RunAsync(NetworksetupCommands.Binary, arguments, cancellationToken);

    private static string? NullLiteral(string value) =>
        value.Length == 0
        || value.Equals("(null)", StringComparison.OrdinalIgnoreCase)
        || value.Equals("none", StringComparison.OrdinalIgnoreCase)
            ? null
            : value;

    private static bool IsLoopback(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && (value.StartsWith("127.", StringComparison.Ordinal)
            || value.StartsWith("localhost", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("[::1]", StringComparison.Ordinal)
            || value.StartsWith("::1", StringComparison.Ordinal));

    private static string Trim(string? value)
    {
        var text = (value ?? string.Empty)
            .Replace('\n', ' ')
            .Replace('\r', ' ')
            .Trim();

        return text.Length <= 300 ? text : text[..300] + "…";
    }

    private static bool DefaultElevationCheck()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return false;
        }

        try
        {
            return GetEffectiveUserId() == 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint GetEffectiveUserId();
}
