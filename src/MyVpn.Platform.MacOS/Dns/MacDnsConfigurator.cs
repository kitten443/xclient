using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.MacOS.Proxy;

namespace MyVpn.Platform.MacOS.Dns;

/// <summary>
/// One resolver block from <c>scutil --dns</c>.
/// </summary>
/// <param name="Domain">The resolver's domain, when the block declares one.</param>
/// <param name="NameServers">The nameserver addresses, in the order scutil printed them.</param>
/// <param name="InterfaceName">Interface the resolver is scoped to, from <c>if_index</c>.</param>
/// <param name="Flags">The flag tokens, e.g. <c>Scoped</c>, <c>Supplemental</c>.</param>
/// <param name="Section">Which of scutil's three sections the block appeared in.</param>
public sealed record ScutilResolver(
    string? Domain,
    IReadOnlyList<string> NameServers,
    string? InterfaceName,
    IReadOnlyList<string> Flags,
    string Section)
{
    /// <summary>True when the resolver is bound to an interface (<c>Scoped</c>).</summary>
    public bool IsScoped => Flags.Contains("Scoped", StringComparer.OrdinalIgnoreCase);

    /// <summary>True for a split-DNS resolver (<c>Supplemental</c>).</summary>
    public bool IsSupplemental => Flags.Contains("Supplemental", StringComparer.OrdinalIgnoreCase);

    /// <summary>True for a per-service resolver (<c>Service-specific</c>).</summary>
    public bool IsServiceSpecific => Flags.Contains("Service-specific", StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Configures macOS DNS through <c>networksetup</c>, <c>scutil</c> and <c>/etc/resolver/</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this executor has to exist, and why a route is not enough.</b> Blocking port 53 outside the
/// tunnel stops the leak but leaves resolution <i>broken</i> rather than redirected, because
/// mDNSResponder binds its DNS sockets with <c>IP_BOUND_IF</c> to a specific interface and the "Super"
/// DNS client prefers the <b>primary service's</b> resolvers for names it cannot match more
/// specifically. A route change therefore does not move resolution onto the tunnel: the queries are
/// bound to <c>en0</c> by design. The fix has two halves, and this class is the configuration half:
/// point the resolvers the Super client selects at the tunnel, and let the Kill Switch's packet rules
/// make sure nothing else answers.
/// </para>
/// <para>
/// <b>What is written where.</b>
/// <list type="bullet">
/// <item><description>
/// the <b>primary</b> network service's resolver list, with
/// <c>networksetup -setdnsservers &lt;service&gt; …</c>. The primary service is what the Super client
/// falls back to, which is exactly the lever that matters; an empty list is cleared with the
/// documented literal <c>empty</c>.
/// </description></item>
/// <item><description>
/// one root-owned file per split-DNS domain under <c>/etc/resolver/</c>, the mechanism
/// <c>resolver(5)</c> documents: the file name <i>is</i> the domain, and the body is
/// <c>nameserver &lt;ip&gt;</c> (with the documented <c>address.port</c> form for a non-standard port).
/// Each file carries MyVpn's marker comment, which is how <see cref="RemoveAllOwnedAsync"/> recognises
/// its own files after a crash without a journal.
/// </description></item>
/// <item><description>
/// <b>nothing else.</b> Search domains are deliberately not touched: <see cref="DnsPlan"/> carries the
/// domains MyVpn would like to set but has no field for the ones it would have to restore, and
/// <c>resolver(5)</c> notes that search is only used by the Super resolver — so the honest action is to
/// leave the user's search configuration alone. That is an interface gap, and it is reported as one.
/// </description></item>
/// </list>
/// </para>
/// <para>
/// <b>Partial restore is impossible to express, so it is avoided.</b> <see cref="DnsPlan"/> has no
/// field for the network service the previous resolvers belonged to. Rather than lose the value,
/// <see cref="DnsPlan.PreviousManager"/> — documented as the name of the manager that owned DNS — is
/// written as <c>networksetup:&lt;service&gt;</c>, which names the owner precisely and lets
/// <see cref="RestoreAsync"/> put the resolvers back on the service they came from. An unrecognised
/// value falls back to the current primary service. This is a documented workaround for a missing
/// field, not a free-form convention: see the platform report.
/// </para>
/// <para>
/// <b>Verification uses <c>scutil --dns</c>, never <c>-getdnsservers</c> alone.</b> The getter reports
/// what was configured on one service; <c>scutil --dns</c> is the resolver stack's own view — domain,
/// nameservers, <c>if_index</c> and the <c>Scoped</c>/<c>Supplemental</c>/<c>Service-specific</c> flags
/// — and it is the only one of the two that can show that a resolver is bound to the physical
/// interface.
/// </para>
/// </remarks>
public sealed class MacDnsConfigurator : IDnsConfigurator
{
    /// <summary>
    /// Marker written into every resolver file MyVpn creates, so ownership can be established from the
    /// file itself after a crash.
    /// </summary>
    public const string ResolverFileMarker = "# Generated by MyVpn — do not edit.";

    /// <summary>Directory <c>resolver(5)</c> reads split-DNS files from.</summary>
    public const string ResolverDirectory = "/etc/resolver";

    /// <summary>
    /// <c>MAXNS</c> from <c>resolver(5)</c>: at most three nameservers may be listed per resolver.
    /// </summary>
    public const int MaxNameServersPerFile = 3;

    /// <summary>Default interface name used when the caller does not supply one.</summary>
    public const string DefaultTunnelInterfaceName = "utun0";

    private readonly ICommandRunner _runner;
    private readonly Func<bool> _isElevated;
    private readonly string _tunnelInterfaceName;

    public MacDnsConfigurator(
        ICommandRunner? runner = null,
        Func<bool>? isElevated = null,
        string? tunnelInterfaceName = null)
    {
        _runner = runner ?? new ProcessCommandRunner();
        _isElevated = isElevated ?? DefaultElevationCheck;
        _tunnelInterfaceName = string.IsNullOrWhiteSpace(tunnelInterfaceName)
            ? DefaultTunnelInterfaceName
            : tunnelInterfaceName!;
    }

    /// <summary>
    /// True when this is macOS and <c>networksetup</c> exists.
    /// </summary>
    /// <remarks>
    /// Cheap and process-free, as capability reporting requires. Elevation is checked by the mutating
    /// calls: <c>scutil --dns</c> and the getters work unprivileged, so inspection stays available.
    /// </remarks>
    public bool IsSupported => OperatingSystem.IsMacOS() && _runner.Exists(NetworksetupCommands.Binary);

    public async Task<Result<DnsPlan>> ApplyAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return Result<DnsPlan>.Fail(validation.Error!);
        }

        var guard = Guard();
        if (guard is not null)
        {
            return Result<DnsPlan>.Fail(guard);
        }

        var service = await ResolvePrimaryServiceAsync(cancellationToken).ConfigureAwait(false);
        if (service is null)
        {
            return Result<DnsPlan>.Fail(NoService());
        }

        foreach (var domain in plan.SplitDnsDomains)
        {
            if (!IsSafeResolverDomain(domain))
            {
                return Result<DnsPlan>.Fail(ResolverDomainInvalid(domain));
            }
        }

        var previous = await ReadDnsServersAsync(service, cancellationToken).ConfigureAwait(false);

        var applied = plan with
        {
            PreviousServers = previous,

            // See the class remarks: this is how the service name survives the round trip through an
            // abstraction that has no field for it.
            PreviousManager = FormatPreviousManager(service),
        };

        if (plan.Servers.Count == 0)
        {
            // "No resolver configured" means MyVpn does not touch DNS. Writing the clear literal here
            // would delete the user's own configuration for no benefit.
            return Result<DnsPlan>.Ok(applied);
        }

        // (1) Split-DNS files first. If one cannot be written, nothing has been changed yet, so the
        //     failure leaves the machine exactly as it was.
        var created = new List<string>();
        foreach (var domain in plan.SplitDnsDomains.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var written = await WriteResolverFileAsync(domain, plan.Servers, cancellationToken)
                .ConfigureAwait(false);

            if (written.IsFailure)
            {
                DeleteResolverFiles(created);
                return Result<DnsPlan>.Fail(written.Error!);
            }

            created.Add(ResolverFilePath(domain));
        }

        // (2) The primary service's resolvers. This is the half that makes the Super client select
        //     them; the tunnel interface's own resolvers alone would never be consulted for an
        //     ordinary name.
        var servers = plan.Servers.Select(s => s.Address).ToArray();
        var set = await RunAsync(
            NetworksetupCommands.SetDnsServers(service, servers), cancellationToken)
            .ConfigureAwait(false);

        if (!set.Succeeded)
        {
            DeleteResolverFiles(created);
            return Result<DnsPlan>.Fail(ConfigureFailed(service, servers, set));
        }

        return Result<DnsPlan>.Ok(applied);
    }

    public async Task<Result> RestoreAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var guard = Guard();
        if (guard is not null)
        {
            return Result.Fail(guard);
        }

        var service = plan.PreviousManager is not null
                      && TryParsePreviousManager(plan.PreviousManager, out var parsed)
            ? parsed
            : await ResolvePrimaryServiceAsync(cancellationToken).ConfigureAwait(false);

        if (service is null)
        {
            return Result.Fail(NoService());
        }

        var restore = await RunAsync(
            NetworksetupCommands.SetDnsServers(service, plan.PreviousServers), cancellationToken)
            .ConfigureAwait(false);

        // The split-DNS files are MyVpn's own and are removed unconditionally: leaving one behind
        // would keep sending a domain to a resolver inside a tunnel that no longer exists.
        DeleteResolverFiles(plan.SplitDnsDomains.Select(ResolverFilePath).ToArray());

        return restore.Succeeded
            ? Result.Ok()
            : Result.Fail(RestoreFailed(service, restore));
    }

    /// <summary>
    /// Removes every DNS override MyVpn owns: the primary service's resolver list and the
    /// <c>/etc/resolver</c> files that carry MyVpn's marker.
    /// </summary>
    /// <remarks>
    /// The clear literal is used rather than a guessed list, because emergency cleanup has no plan and
    /// a resolver pointing at a tunnel that no longer exists makes the machine look like it has no
    /// internet at all. Ownership of the files is decided by their marker comment, so the user's own
    /// <c>/etc/resolver</c> entries survive.
    /// </remarks>
    public async Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
    {
        var guard = Guard();
        if (guard is not null)
        {
            return Result.Fail(guard);
        }

        var failures = new List<string>();

        var service = await ResolvePrimaryServiceAsync(cancellationToken).ConfigureAwait(false);
        if (service is null)
        {
            failures.Add("no network service could be resolved");
        }
        else
        {
            var cleared = await RunAsync(
                NetworksetupCommands.SetDnsServers(service, Array.Empty<string>()), cancellationToken)
                .ConfigureAwait(false);

            if (!cleared.Succeeded)
            {
                failures.Add($"clearing the resolver list on '{service}' failed: {Trim(cleared.Combined)}");
            }
        }

        foreach (var path in EnumerateOwnedResolverFiles())
        {
            if (!DeleteFile(path))
            {
                failures.Add($"'{path}' could not be removed");
            }
        }

        return failures.Count == 0
            ? Result.Ok()
            : Result.Fail(RemoveFailed(string.Join("; ", failures)));
    }

    /// <summary>
    /// Reads the resolver stack's own view with <c>scutil --dns</c>.
    /// </summary>
    /// <remarks>
    /// <see cref="DnsState.PlainDnsReachableOutsideTunnel"/> is derived from the resolvers' interfaces:
    /// a resolver whose <c>if_index</c> is not the tunnel's is a resolver that will answer on the
    /// physical link, which is precisely the leak the research describes. When no tunnel interface
    /// name is known the flag errs towards warning, and
    /// <c>dns.leak.tunnel_interface_unknown</c> says why.
    /// </remarks>
    public async Task<DnsState> InspectAsync(CancellationToken cancellationToken)
    {
        if (!IsSupported)
        {
            return new DnsState
            {
                ActiveServers = Array.Empty<string>(),
                InterfaceName = null,
                PlainDnsReachableOutsideTunnel = false,
            };
        }

        var result = await _runner.RunAsync("scutil", new[] { "--dns" }, cancellationToken)
            .ConfigureAwait(false);

        if (!result.Succeeded)
        {
            return new DnsState
            {
                ActiveServers = Array.Empty<string>(),
                InterfaceName = null,
                PlainDnsReachableOutsideTunnel = false,
            };
        }

        var resolvers = ParseScutilDns(result.StandardOutput);
        var servers = resolvers
            .SelectMany(r => r.NameServers)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var primary = resolvers.FirstOrDefault();
        var leaks = new List<string>();

        var outsideTunnel = resolvers.Any(r =>
            !string.Equals(r.InterfaceName, _tunnelInterfaceName, StringComparison.Ordinal));

        if (outsideTunnel && servers.Length > 0)
        {
            leaks.Add("dns.leak.plaintext_outside_tunnel");
        }

        var hasIpv6 = servers.Any(s => IPAddress.TryParse(s, out var address)
                                       && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

        if (hasIpv6)
        {
            leaks.Add("dns.leak.ipv6_resolver");
        }

        return new DnsState
        {
            ActiveServers = servers,
            InterfaceName = primary?.InterfaceName,
            PlainDnsReachableOutsideTunnel = outsideTunnel && servers.Length > 0,
            HasIpv6Resolver = hasIpv6,
            PotentialLeaks = leaks,
        };
    }

    // ------------------------------------------------------------------ pure helpers

    /// <summary>
    /// Parses <c>networksetup -getdnsservers</c>.
    /// </summary>
    /// <remarks>
    /// The empty case is detected by the documented sentence
    /// ("There aren't any DNS Servers set on …"), which is also what shipping clients test for; every
    /// other non-empty line must be an IP literal or it is ignored rather than written back later.
    /// </remarks>
    public static IReadOnlyList<string> ParseDnsServers(string? output)
    {
        var servers = new List<string>();

        if (string.IsNullOrEmpty(output) || output.Contains("aren't any", StringComparison.OrdinalIgnoreCase))
        {
            return servers;
        }

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length > 0 && NetworkText.IsIpAddress(line))
            {
                servers.Add(line);
            }
        }

        return servers;
    }

    /// <summary>Renders the <c>PreviousManager</c> value that carries the network service name.</summary>
    public static string FormatPreviousManager(string service)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(service);
        return $"networksetup:{service}";
    }

    /// <summary>Reads the service name back out of a <see cref="DnsPlan.PreviousManager"/> value.</summary>
    public static bool TryParsePreviousManager(string? value, out string service)
    {
        service = string.Empty;

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        const string prefix = "networksetup:";
        if (!value.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var candidate = value[prefix.Length..].Trim();
        if (!NetworksetupCommands.IsSafeServiceName(candidate))
        {
            return false;
        }

        service = candidate;
        return true;
    }

    /// <summary>
    /// Renders a <c>/etc/resolver/&lt;domain&gt;</c> file.
    /// </summary>
    /// <remarks>
    /// <c>resolver(5)</c> documents the format: the file name is the domain, <c>nameserver</c> takes an
    /// IPv4 or IPv6 address, and a non-standard port is written as a trailing dot followed by the port
    /// (<c>10.0.0.17.55</c>). At most <c>MAXNS</c> (three) nameservers are listed, as documented.
    /// </remarks>
    public static string RenderResolverFile(string domain, IReadOnlyList<DnsServerEntry> servers)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentNullException.ThrowIfNull(servers);

        var builder = new System.Text.StringBuilder(256);
        builder.Append(ResolverFileMarker).Append('\n');
        builder.Append(CultureInfo.InvariantCulture, $"# domain: {domain}\n");

        foreach (var server in servers.Take(MaxNameServersPerFile))
        {
            builder.Append(CultureInfo.InvariantCulture, $"nameserver {RenderResolverAddress(server)}\n");
        }

        return builder.ToString();
    }

    /// <summary>Renders one nameserver line value, including the documented non-standard port form.</summary>
    public static string RenderResolverAddress(DnsServerEntry server)
    {
        ArgumentNullException.ThrowIfNull(server);
        return server.Port == 53
            ? server.Address
            : string.Create(CultureInfo.InvariantCulture, $"{server.Address}.{server.Port}");
    }

    /// <summary>
    /// True when a split-DNS domain may become a file name under <c>/etc/resolver</c>.
    /// </summary>
    /// <remarks>
    /// The domain is turned into a path, so this is a containment check as much as a DNS check: a value
    /// containing <c>/</c>, a backslash or a <c>..</c> label could otherwise write outside the
    /// directory. A leading <c>*.</c> wildcard is stripped — <c>resolver(5)</c> names files by domain,
    /// and a wildcard is expressed as the bare suffix.
    /// </remarks>
    public static bool IsSafeResolverDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        var value = domain.Trim();
        if (value.Contains('/', StringComparison.Ordinal)
            || value.Contains('\\', StringComparison.Ordinal)
            || value.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        return NetworkText.IsValidHostName(value);
    }

    /// <summary>Resolves the file path for a domain; the caller must have validated it first.</summary>
    public static string ResolverFilePath(string domain)
    {
        if (!IsSafeResolverDomain(domain))
        {
            throw new ArgumentException($"'{domain}' is not a usable resolver domain.", nameof(domain));
        }

        var value = domain.Trim();
        if (value.StartsWith("*.", StringComparison.Ordinal))
        {
            value = value[2..];
        }

        return Path.Combine(ResolverDirectory, value);
    }

    /// <summary>True when a file's content marks it as one of MyVpn's resolver files.</summary>
    public static bool ContainsOwnedMarker(string? contents) =>
        !string.IsNullOrEmpty(contents)
        && contents.Contains(ResolverFileMarker, StringComparison.Ordinal);

    /// <summary>
    /// Parses <c>scutil --dns</c> into resolver blocks.
    /// </summary>
    /// <remarks>
    /// The three sections the tool prints ("DNS configuration", "… (for scoped queries)", "… (for
    /// service-specific queries)") are tracked because a resolver's meaning depends on which one it
    /// came from: only the first supplies the default resolver, while the others carry the
    /// <c>Scoped</c>/<c>Supplemental</c>/<c>Service-specific</c> flags. Lines the parser does not
    /// recognise are skipped; a diagnostic view must not fail because a macOS update added a field.
    /// </remarks>
    public static IReadOnlyList<ScutilResolver> ParseScutilDns(string? output)
    {
        var resolvers = new List<ScutilResolver>();

        if (string.IsNullOrEmpty(output))
        {
            return resolvers;
        }

        var section = "DNS configuration";
        string? domain = null;
        string? interfaceName = null;
        var nameservers = new List<string>();
        var flags = new List<string>();

        void Flush()
        {
            if (nameservers.Count > 0 || flags.Count > 0 || domain is not null)
            {
                resolvers.Add(new ScutilResolver(
                    domain, nameservers.ToArray(), interfaceName, flags.ToArray(), section));
            }

            domain = null;
            interfaceName = null;
            nameservers = new List<string>();
            flags = new List<string>();
        }

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith("DNS configuration", StringComparison.Ordinal))
            {
                Flush();
                section = line;
                continue;
            }

            if (line.StartsWith("resolver #", StringComparison.Ordinal))
            {
                Flush();
                continue;
            }

            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            var key = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();

            if (key.StartsWith("nameserver[", StringComparison.Ordinal))
            {
                if (NetworkText.IsIpAddress(value))
                {
                    nameservers.Add(value);
                }
            }
            else if (key.Equals("domain", StringComparison.Ordinal))
            {
                domain = value;
            }
            else if (key.Equals("if_index", StringComparison.Ordinal))
            {
                interfaceName = ParseInterfaceFromIfIndex(value);
            }
            else if (key.Equals("flags", StringComparison.Ordinal))
            {
                flags.AddRange(value
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }
        }

        Flush();
        return resolvers;
    }

    /// <summary>Extracts the interface name from an <c>if_index : 14 (en0)</c> value.</summary>
    public static string? ParseInterfaceFromIfIndex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var open = value.IndexOf('(');
        var close = value.LastIndexOf(')');

        return open >= 0 && close > open
            ? value[(open + 1)..close].Trim()
            : null;
    }

    // ------------------------------------------------------------------ error mapping (pure)

    /// <summary>Error for a call made on a host that is not macOS.</summary>
    public static MyVpnError UnsupportedOnThisHost() =>
        new MyVpnError(
            ErrorCodes.DnsConfigureFailed,
            "error.platform.macos_only",
            ErrorSeverity.Error,
            "macOS DNS is configured with 'networksetup', 'scutil' and /etc/resolver, none of which "
            + "exist on this host. This call is refused before any process is started.",
            "diagnostics.run");

    /// <summary>Error for a mutating call without privileges.</summary>
    public static MyVpnError NotElevated() =>
        new MyVpnError(
            ErrorCodes.PrivilegeDenied,
            "error.dns.needs_privileges",
            ErrorSeverity.Error,
            "Changing DNS settings requires administrator privileges, and /etc/resolver is "
            + "root-owned. MyVpn needs its privileged helper installed.",
            "privilege.install_helper");

    /// <summary>Error for a machine with no usable network service.</summary>
    public static MyVpnError NoService() =>
        new MyVpnError(
            ErrorCodes.DnsConfigureFailed,
            "error.dns.no_service",
            ErrorSeverity.Error,
            "No network service could be resolved, so there is no service whose resolvers can be "
            + "changed.",
            "diagnostics.run");

    /// <summary>Error for a split-DNS domain that cannot become a file name.</summary>
    public static MyVpnError ResolverDomainInvalid(string? domain) =>
        new MyVpnError(
            ErrorCodes.DnsConfigureFailed,
            "error.dns.resolver_domain_invalid",
            ErrorSeverity.Error,
            $"'{domain}' cannot be used as a /etc/resolver file name: it must be a plain DNS name "
            + "with no path separators and no '..' component.",
            "dns.reapply");

    /// <summary>Error for a resolver list the platform rejected.</summary>
    public static MyVpnError ConfigureFailed(
        string service,
        IReadOnlyCollection<string> servers,
        CommandResult result) =>
        new MyVpnError(
            ErrorCodes.DnsConfigureFailed,
            "error.dns.configure_failed",
            ErrorSeverity.Error,
            $"Setting resolvers on '{service}' to [{string.Join(", ", servers)}] failed: "
            + Trim(result.Combined),
            "dns.reapply");

    /// <summary>Error for a failed restore of the previous resolvers.</summary>
    public static MyVpnError RestoreFailed(string service, CommandResult result) =>
        new MyVpnError(
            ErrorCodes.DnsRestoreFailed,
            "error.dns.restore_failed",
            ErrorSeverity.Critical,
            $"The previous resolvers could not be restored on '{service}': {Trim(result.Combined)}",
            "network.restore");

    /// <summary>Error for a failed cleanup.</summary>
    public static MyVpnError RemoveFailed(string detail) =>
        new MyVpnError(
            ErrorCodes.DnsRestoreFailed,
            "error.dns.restore_failed",
            ErrorSeverity.Critical,
            $"Not every DNS override could be removed: {detail}",
            "network.restore");

    /// <summary>Error for a resolver file that could not be written.</summary>
    public static MyVpnError ResolverFileWriteFailed(string path, string detail) =>
        new MyVpnError(
            ErrorCodes.DnsConfigureFailed,
            "error.dns.resolver_file_failed",
            ErrorSeverity.Error,
            $"The split-DNS file '{path}' could not be written: {detail}",
            "dns.reapply");

    // ------------------------------------------------------------------ internals

    private MyVpnError? Guard()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return UnsupportedOnThisHost();
        }

        if (!_runner.Exists(NetworksetupCommands.Binary))
        {
            return new MyVpnError(
                ErrorCodes.PlatformToolMissing,
                "error.platform.tool_missing",
                ErrorSeverity.Error,
                "The 'networksetup' tool was not found, so DNS cannot be configured.",
                "diagnostics.run")
                .WithArg("tool", NetworksetupCommands.Binary);
        }

        if (!_isElevated())
        {
            return NotElevated();
        }

        return null;
    }

    private async Task<Result> WriteResolverFileAsync(
        string domain,
        IReadOnlyList<DnsServerEntry> servers,
        CancellationToken cancellationToken)
    {
        var path = ResolverFilePath(domain);

        try
        {
            if (!Directory.Exists(ResolverDirectory))
            {
                Directory.CreateDirectory(ResolverDirectory);
            }

            await File.WriteAllTextAsync(path, RenderResolverFile(domain, servers), cancellationToken)
                .ConfigureAwait(false);

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    path,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite
                    | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            }

            return Result.Ok();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result.Fail(ResolverFileWriteFailed(path, $"{ex.GetType().Name}: {ex.Message}"));
        }
    }

    private IEnumerable<string> EnumerateOwnedResolverFiles()
    {
        if (!Directory.Exists(ResolverDirectory))
        {
            yield break;
        }

        IEnumerable<string> candidates;
        try
        {
            candidates = Directory.EnumerateFiles(ResolverDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var path in candidates)
        {
            string? contents = null;
            try
            {
                contents = File.ReadAllText(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Unreadable files are not ours to delete.
            }

            if (ContainsOwnedMarker(contents))
            {
                yield return path;
            }
        }
    }

    private static void DeleteResolverFiles(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            DeleteFile(path);
        }
    }

    private static bool DeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private async Task<string?> ResolvePrimaryServiceAsync(CancellationToken cancellationToken)
    {
        var order = await RunAsync(NetworksetupCommands.ListServiceOrder(), cancellationToken)
            .ConfigureAwait(false);

        if (order.Succeeded)
        {
            var primary = MacSystemProxy.ParseServiceOrder(order.StandardOutput).FirstOrDefault();
            if (primary is not null)
            {
                return primary;
            }
        }

        var all = await RunAsync(NetworksetupCommands.ListAllServices(), cancellationToken)
            .ConfigureAwait(false);

        return all.Succeeded
            ? MacSystemProxy.ParseServiceList(all.StandardOutput).FirstOrDefault()
            : null;
    }

    private async Task<IReadOnlyList<string>> ReadDnsServersAsync(
        string service,
        CancellationToken cancellationToken)
    {
        var result = await RunAsync(NetworksetupCommands.GetDnsServers(service), cancellationToken)
            .ConfigureAwait(false);

        return result.Succeeded ? ParseDnsServers(result.StandardOutput) : Array.Empty<string>();
    }

    private Task<CommandResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken) =>
        _runner.RunAsync(NetworksetupCommands.Binary, arguments, cancellationToken);

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
