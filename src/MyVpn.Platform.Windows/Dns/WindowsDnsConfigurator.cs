using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Dns;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Windows.Execution;

namespace MyVpn.Platform.Windows.Dns;

/// <summary>
/// The <c>netsh</c> command lines that configure per-interface DNS, as pure functions.
/// </summary>
/// <remarks>
/// <para>
/// <b>Which API this is.</b> The supported in-process API is
/// <c>SetInterfaceDnsSettings(GUID Interface, const DNS_INTERFACE_SETTINGS*)</c> from
/// <c>netioapi.h</c> — note the name: <c>DNS_SetInterfaceDnsSettings</c> does not exist, and the
/// brief's spelling must not appear anywhere. It is also worth recording what is easy to get
/// wrong about it: only the fields whose bit is set in <c>Flags</c> are written and the rest must
/// be zeroed, and <c>DNS_SETTING_IPV6</c> retargets the <i>whole structure</i>, so a dual-stack
/// configuration takes two calls. This executor drives the same store through the in-box
/// <c>netsh</c> front-end instead, because <c>netsh</c> is argv-driven (no additional struct
/// marshalling, no risk of silently writing the wrong family) and because the value it writes is
/// the one this class reads back to verify.
/// </para>
/// <para>
/// <b>Every argument is named.</b> <c>netsh</c> matches <c>name=</c>, <c>source=</c>,
/// <c>address=</c>, <c>index=</c> and <c>validate=no</c> explicitly, and the named form is stable
/// across the positional orderings that differ between Windows releases. <c>validate=no</c>
/// matters on a machine whose only working resolver is the one being configured: netsh's own
/// validation would otherwise query the server before the tunnel is up and fail the apply.
/// </para>
/// </remarks>
public static class WindowsDnsCommands
{
    public const string NetshTool = "netsh.exe";

    /// <summary>Sets the first resolver of an interface, replacing whatever was configured.</summary>
    public static IReadOnlyList<string> SetPrimary(string interfaceName, string server, bool ipv6)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(server);

        return new[]
        {
            "interface",
            ipv6 ? "ipv6" : "ip",
            "set",
            "dns",
            $"name={interfaceName}",
            "source=static",
            $"address={server}",

            // Registers this adapter's addresses in DNS. The tunnel adapter is normally the only
            // one that should register, which is why the flag is set explicitly rather than left
            // to the machine default.
            "register=primary",
            "validate=no",
        };
    }

    /// <summary>Appends a further resolver at the given 1-based index.</summary>
    public static IReadOnlyList<string> AddServer(string interfaceName, string server, int index, bool ipv6)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(server);

        if (index < 2)
        {
            throw new ArgumentOutOfRangeException(
                nameof(index),
                index,
                "The first resolver is set with SetPrimary; additional ones start at index 2.");
        }

        return new[]
        {
            "interface",
            ipv6 ? "ipv6" : "ip",
            "add",
            "dns",
            $"name={interfaceName}",
            server,
            $"index={index.ToString(CultureInfo.InvariantCulture)}",
            "validate=no",
        };
    }

    /// <summary>Hands the interface back to DHCP-provided resolvers.</summary>
    public static IReadOnlyList<string> ResetToDhcp(string interfaceName, bool ipv6)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);

        return new[]
        {
            "interface",
            ipv6 ? "ipv6" : "ip",
            "set",
            "dns",
            $"name={interfaceName}",
            "source=dhcp",
        };
    }
}

/// <summary>One NRPT rule as MyVpn writes it.</summary>
public sealed record WindowsNrptRule
{
    /// <summary>Stable rule GUID derived from the namespace, so a restore can find it again.</summary>
    public required Guid Key { get; init; }

    /// <summary>Namespace the rule applies to, e.g. <c>corp.example.com</c>.</summary>
    public required string Domain { get; init; }

    /// <summary>Resolvers to use for that namespace.</summary>
    public required IReadOnlyList<string> Servers { get; init; }

    /// <summary>Value of the ownership marker written alongside the rule.</summary>
    public required string Identifier { get; init; }
}

/// <summary>
/// Name Resolution Policy Table rules, as registry data.
/// </summary>
/// <remarks>
/// <para>
/// <b>Split DNS goes through the NRPT.</b> The documented management surface is Group Policy
/// ("Name Resolution Policy") and the <c>Add-DnsClientNrptRule</c> cmdlet family; both write the
/// registry form below, which is specified in MS-GPNRPT §2.2.2.2. MyVpn writes the registry
/// directly because the cmdlets are a PowerShell surface (a separate process, localized output,
/// no argv-only contract) while the registry layout is a published specification.
/// </para>
/// <para>
/// <b>Names that do not exist.</b> <c>DnsSetNrptTable</c>, <c>DnsAddPolicyTableRule</c> and
/// <c>DnsRemovePolicyTableRule</c> are not documented public APIs — they are absent from the
/// official <c>windns.h</c> function list. They must never appear in this code.
/// </para>
/// <para>
/// <b>The GPO trap.</b> <c>HKLM\SOFTWARE\Policies\...</c> is the managed location: domain policy
/// or MDM can lock it or revert MyVpn's rules at the next policy refresh. That is the price of
/// using the documented split-DNS mechanism, and it is why the per-interface DNS configuration
/// (which lives in the non-policy store) remains the primary path and is verified by reading it
/// back.
/// </para>
/// </remarks>
public static class WindowsNrptRules
{
    /// <summary>Policy-store location of the NRPT; the Group Policy mechanism writes here.</summary>
    public const string PolicyConfigPath =
        @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

    /// <summary>Service-store equivalent, used by the DNS client when policy is absent.</summary>
    public const string ServiceConfigPath =
        @"SYSTEM\CurrentControlSet\services\Dnscache\Parameters\DnsPolicyConfig";

    /// <summary>
    /// Ownership marker written beside each rule.
    /// </summary>
    /// <remarks>
    /// The DNS client ignores values it does not know, so an extra <c>REG_SZ</c> here is inert as
    /// far as name resolution is concerned and makes cleanup exact: after a crash,
    /// <see cref="RemoveAllOwnedAsync"/> can identify our rules without the plan that created
    /// them. The alternative — deleting every rule under the key — would remove a rule an
    /// administrator or another product installed.
    /// </remarks>
    public const string OwnerValueName = "MyVpnRule";

    /// <summary>NRPT rule schema version; the documented value for a policy rule is 1.</summary>
    public const int SchemaVersion = 1;

    /// <summary>
    /// Derives the rule GUID for a namespace.
    /// </summary>
    /// <remarks>
    /// Deterministic on purpose: a restore that has only the domain (not the plan) must be able to
    /// find the rule it created. SHA-256 is used as a name-based derivation, and the RFC 4122
    /// version/variant bits are set so the result is a well-formed UUID rather than an arbitrary
    /// 16-byte value.
    /// </remarks>
    public static Guid RuleKeyFor(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes("myvpn.nrpt:" + domain.Trim().ToLowerInvariant()));
        var guidBytes = bytes[..16];

        guidBytes[7] = (byte)((guidBytes[7] & 0x0F) | 0x50);
        guidBytes[8] = (byte)((guidBytes[8] & 0x3F) | 0x80);

        return new Guid(guidBytes);
    }

    /// <summary>Builds the rules for a plan's split-DNS domains.</summary>
    public static IReadOnlyList<WindowsNrptRule> FromPlan(DnsPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var domains = new List<string>(plan.SplitDnsDomains);
        foreach (var server in plan.Servers)
        {
            domains.AddRange(server.Domains);
        }

        var servers = plan.Servers
            .Where(s => NetworkText.IsIpAddress(s.Address))
            .Select(s => s.Address.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (servers.Length == 0)
        {
            return Array.Empty<WindowsNrptRule>();
        }

        return domains
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Trim().TrimStart('.'))
            .Where(IsSafeNamespace)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
            .Select(d => new WindowsNrptRule
            {
                Key = RuleKeyFor(d),
                Domain = d,
                Servers = servers,
                Identifier = plan.TunnelInterface,
            })
            .ToArray();
    }

    /// <summary>
    /// True when a split-DNS namespace is safe to write into the registry.
    /// </summary>
    /// <remarks>
    /// A namespace becomes a registry value and a rule key. Dots, letters, digits, hyphens and
    /// underscores are what a DNS name is made of; anything else — a wildcard, a slash, a control
    /// character — is refused rather than escaped, because the NRPT's own syntax for those cases
    /// is not something this executor claims to support.
    /// </remarks>
    public static bool IsSafeNamespace(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain) || domain.Length > 255)
        {
            return false;
        }

        if (domain is "." or "*")
        {
            // The catch-all namespace has its own meaning and is not a split-DNS domain.
            return false;
        }

        foreach (var c in domain)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_'))
            {
                return false;
            }
        }

        // Every label must be non-empty and within the DNS length limit, so a value such as
        // "corp..example.com" or a leading dot is refused rather than written as a namespace the
        // DNS client would interpret differently from what the user asked for.
        foreach (var label in domain.Split('.'))
        {
            if (label.Length is 0 or > 63)
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>
/// Configures the host resolver on Windows through <c>netsh</c> and the NRPT.
/// </summary>
/// <remarks>
/// <para>
/// <b>Xray owns the tunnel's resolver; this executor owns the host's.</b> The plan's servers are
/// applied to the tunnel interface, and split-DNS namespaces get NRPT rules. Nothing here blocks
/// plaintext DNS — that is the Kill Switch's job, and duplicating it would produce two mechanisms
/// that can disagree. The WFP rule set permits DNS only to the configured resolvers, which is
/// what makes "no plaintext leak" true rather than aspirational.
/// </para>
/// <para>
/// <b>Reading back.</b> Every apply is followed by a verification that reads the interface's
/// configured resolvers out of the registry — the non-localized source of truth behind
/// <c>SetInterfaceDnsSettings</c> — and fails if they did not take. Trusting <c>netsh</c>'s exit
/// code is how a client reports "protected" while queries still leave through the uplink.
/// </para>
/// <para>
/// <b>DoH and fake DNS are deliberately not attempted.</b> DoH needs
/// <c>DNS_INTERFACE_SETTINGS3</c> plus a <c>DNS_SERVER_PROPERTY</c> array, and "Require DoH" is
/// documented to fail for a resolver that is not on the known-DoH list; fake-DNS is an Xray
/// feature that this layer does not own. Both would be silent partial successes, so they are left
/// to the layers that can do them properly.
/// </para>
/// </remarks>
public sealed class WindowsDnsConfigurator : IDnsConfigurator
{
    private const string ManagedManager = "windows-netsh+nrpt";

    private const string LeakIpv6Resolver = "error.dns.leak.ipv6_resolver";
    private const string LeakPlainResolverPresent = "error.dns.leak.plain_resolver_present";
    private const string LeakBackendUnknown = "error.dns.leak.backend_unknown";

    private readonly ICommandRunner _runner;
    private readonly Func<bool> _isElevated;

    /// <summary>Resolvers observed immediately before the last successful apply.</summary>
    private IReadOnlyList<string> _recordedPrevious = Array.Empty<string>();

    public WindowsDnsConfigurator(ICommandRunner? runner = null, Func<bool>? isElevated = null)
    {
        _runner = runner ?? new ProcessCommandRunner();
        _isElevated = isElevated ?? WindowsPlatform.IsProcessElevated;
    }

    /// <summary>
    /// True when this host is Windows, the process may change interface DNS, and <c>netsh</c> is
    /// present.
    /// </summary>
    /// <remarks>
    /// Cheap by design: an OS probe, a token query and a file existence check. Whether the
    /// interface actually accepts the configuration is answered by the read-back, not guessed at
    /// here.
    /// </remarks>
    public bool IsSupported =>
        WindowsPlatform.IsWindows
        && _isElevated()
        && _runner.Exists(WindowsDnsCommands.NetshTool);

    /// <summary>Resolvers captured before the last successful apply.</summary>
    public IReadOnlyList<string> RecordedPreviousServers => _recordedPrevious;

    public async Task<Result<DnsPlan>> ApplyAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return Result<DnsPlan>.Fail(validation.Error!);
        }

        if (!WindowsPlatform.IsWindows)
        {
            return Result<DnsPlan>.Fail(WindowsPlatform.Unsupported("Configuring Windows DNS"));
        }

        if (!_isElevated())
        {
            return Result<DnsPlan>.Fail(NotElevated());
        }

        if (plan.Servers.Count == 0)
        {
            // "Let the system decide": nothing to configure and nothing to read back. Blocking
            // plaintext DNS with no resolver at all was already refused by the plan's own
            // validation, because it would leave the user unable to resolve anything.
            return Result<DnsPlan>.Ok(plan);
        }

        var adapter = WindowsAdapters.FindByName(plan.TunnelInterface);

        if (adapter is null)
        {
            return Result<DnsPlan>.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.no_tunnel_interface",
                ErrorSeverity.Error,
                $"The interface '{plan.TunnelInterface}' does not exist, so its resolvers cannot be "
                + "configured. The TUN adapter is created by the core and must be up first.",
                "dns.reapply")
                .WithArg("interface", plan.TunnelInterface));
        }

        // Captured before anything changes, and returned to the caller inside the plan so it can
        // be restored through the abstraction alone.
        var previous = CaptureInterfaceServers(adapter.AdapterName);
        _recordedPrevious = previous;

        var applied = await ApplyServersAsync(plan, cancellationToken).ConfigureAwait(false);
        if (applied.IsFailure)
        {
            return Result<DnsPlan>.Fail(applied.Error!);
        }

        var nrpt = ApplyNrptRules(plan);
        if (nrpt.IsFailure)
        {
            return Result<DnsPlan>.Fail(nrpt.Error!);
        }

        var verified = Verify(plan, adapter.AdapterName);
        if (verified.IsFailure)
        {
            return Result<DnsPlan>.Fail(verified.Error!);
        }

        return Result<DnsPlan>.Ok(plan with
        {
            PreviousServers = previous,
            PreviousManager = ManagedManager,
        });
    }

    public async Task<Result> RestoreAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (!WindowsPlatform.IsWindows)
        {
            return Result.Fail(WindowsPlatform.Unsupported("Restoring Windows DNS"));
        }

        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        var failures = new List<string>();

        // NRPT rules first: they take precedence over per-interface resolvers, so leaving them in
        // place would keep sending the split-DNS namespaces to a resolver that is going away.
        var removed = RemoveNrptRules(WindowsNrptRules.FromPlan(plan).Select(r => r.Key));
        if (removed.IsFailure)
        {
            failures.Add(Describe(removed.Error!));
        }

        var adapter = WindowsAdapters.FindByName(plan.TunnelInterface);

        if (adapter is null || string.IsNullOrWhiteSpace(adapter.AdapterName))
        {
            // The adapter is gone, and its per-interface DNS went with it. Reporting failure here
            // would leave a session unable to reach a clean state after a crash.
            return failures.Count == 0 ? Result.Ok() : Result.Fail(RestoreFailed(failures));
        }

        var previous = plan.PreviousServers.Count > 0 ? plan.PreviousServers : _recordedPrevious;

        var restored = await RestoreServersAsync(plan.TunnelInterface, previous, cancellationToken)
            .ConfigureAwait(false);

        if (restored.IsFailure)
        {
            failures.Add(Describe(restored.Error!));
        }

        return failures.Count == 0 ? Result.Ok() : Result.Fail(RestoreFailed(failures));
    }

    /// <summary>
    /// Removes every DNS override MyVpn owns.
    /// </summary>
    /// <remarks>
    /// Two independent mechanisms are cleared: the NRPT rules carrying MyVpn's ownership marker,
    /// and every interface whose name starts with <c>myvpn</c> is handed back to DHCP. The marker
    /// is what makes this safe to run blind after a crash — a rule installed by an administrator
    /// or another product is never touched.
    /// </remarks>
    public async Task<Result> RemoveAllOwnedAsync(CancellationToken cancellationToken)
    {
        if (!WindowsPlatform.IsWindows)
        {
            return Result.Fail(WindowsPlatform.Unsupported("Restoring Windows DNS"));
        }

        if (!_isElevated())
        {
            return Result.Fail(NotElevated());
        }

        var failures = new List<string>();
        var removed = RemoveNrptRules(keys: null);

        if (removed.IsFailure)
        {
            failures.Add(Describe(removed.Error!));
        }

        foreach (var adapter in WindowsAdapters.Enumerate(out _))
        {
            if (!adapter.FriendlyName.StartsWith("myvpn", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var ipv6 in new[] { false, true })
            {
                var result = await RunNetshAsync(
                    WindowsDnsCommands.ResetToDhcp(adapter.FriendlyName, ipv6),
                    cancellationToken).ConfigureAwait(false);

                if (!result.Succeeded)
                {
                    failures.Add(
                        $"netsh set dns source=dhcp for '{adapter.FriendlyName}' "
                        + $"(ipv{(ipv6 ? "6" : "4")}) failed with exit code {result.ExitCode}: "
                        + WindowsPlatform.Trim(result.Combined));
                }
            }
        }

        return failures.Count == 0 ? Result.Ok() : Result.Fail(RestoreFailed(failures));
    }

    public Task<DnsState> InspectAsync(CancellationToken cancellationToken)
    {
        _ = cancellationToken;

        // A query, so a non-Windows host answers with an empty observation rather than throwing:
        // the leftover check must not fail because the executor is on the wrong platform.
        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(new DnsState
            {
                ActiveServers = Array.Empty<string>(),
                InterfaceName = null,
                PlainDnsReachableOutsideTunnel = false,
            });
        }

        var adapters = WindowsAdapters.Enumerate(out _);
        var active = new List<string>();
        string? tunnelName = null;
        var outsideTunnel = new List<string>();

        foreach (var adapter in adapters)
        {
            var servers = CaptureInterfaceServers(adapter.AdapterName);

            if (servers.Count == 0)
            {
                continue;
            }

            if (adapter.FriendlyName.StartsWith("myvpn", StringComparison.OrdinalIgnoreCase))
            {
                tunnelName ??= adapter.FriendlyName;
                active.AddRange(servers);
            }
            else
            {
                outsideTunnel.AddRange(servers);
            }
        }

        var hasIpv6 = active.Concat(outsideTunnel).Any(IsNonLoopbackIpv6);
        var leaks = new List<string>();

        if (hasIpv6)
        {
            leaks.Add(LeakIpv6Resolver);
        }

        // Best effort and strictly local: no probe packet is sent. A resolver configured on an
        // adapter that is not the tunnel means queries can leave through the uplink, which is the
        // leak this executor exists to make visible.
        var plainOutside = outsideTunnel.Any(IsNonLoopbackAddress);

        if (plainOutside)
        {
            leaks.Add(LeakPlainResolverPresent);
        }

        if (tunnelName is null && active.Count == 0)
        {
            leaks.Add(LeakBackendUnknown);
        }

        return Task.FromResult(new DnsState
        {
            ActiveServers = active,
            InterfaceName = tunnelName,
            PlainDnsReachableOutsideTunnel = plainOutside,
            HasIpv6Resolver = hasIpv6,
            PotentialLeaks = leaks,
        });
    }

    // ------------------------------------------------------------------ netsh

    private async Task<Result> ApplyServersAsync(DnsPlan plan, CancellationToken cancellationToken)
    {
        // IPv4 and IPv6 are configured independently: a plan with only IPv4 resolvers must not
        // leave the v6 stack pointing at DHCP while the v6 Kill Switch is armed, so a family with
        // no server in the plan is explicitly handed back to DHCP instead of being left alone.
        foreach (var ipv6 in new[] { false, true })
        {
            var servers = plan.Servers
                .Where(s => IsIpv6(s.Address) == ipv6)
                .Select(s => s.Address.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (servers.Length == 0)
            {
                await RunNetshAsync(
                    WindowsDnsCommands.ResetToDhcp(plan.TunnelInterface, ipv6), cancellationToken)
                    .ConfigureAwait(false);

                continue;
            }

            var primary = await RunNetshAsync(
                WindowsDnsCommands.SetPrimary(plan.TunnelInterface, servers[0], ipv6),
                cancellationToken).ConfigureAwait(false);

            if (!primary.Succeeded)
            {
                return Result.Fail(ToolFailed("error.dns.netsh_failed", "netsh set dns", primary));
            }

            for (var index = 1; index < servers.Length; index++)
            {
                var added = await RunNetshAsync(
                    WindowsDnsCommands.AddServer(plan.TunnelInterface, servers[index], index + 1, ipv6),
                    cancellationToken).ConfigureAwait(false);

                if (!added.Succeeded)
                {
                    return Result.Fail(ToolFailed("error.dns.netsh_failed", "netsh add dns", added));
                }
            }
        }

        return Result.Ok();
    }

    private async Task<Result> RestoreServersAsync(
        string interfaceName,
        IReadOnlyList<string> previous,
        CancellationToken cancellationToken)
    {
        var v4 = previous.Where(a => !IsIpv6(a)).ToArray();
        var v6 = previous.Where(IsIpv6).ToArray();

        foreach (var (servers, ipv6) in new[] { (v4, false), (v6, true) })
        {
            if (servers.Length == 0)
            {
                // No record of a previous resolver for this family: handing the interface back to
                // DHCP is the documented undo and is what a fresh adapter had in the first place.
                var reset = await RunNetshAsync(
                    WindowsDnsCommands.ResetToDhcp(interfaceName, ipv6), cancellationToken)
                    .ConfigureAwait(false);

                if (!reset.Succeeded)
                {
                    return Result.Fail(ToolFailed("error.dns.restore_failed", "netsh set dns source=dhcp", reset));
                }

                continue;
            }

            var primary = await RunNetshAsync(
                WindowsDnsCommands.SetPrimary(interfaceName, servers[0], ipv6), cancellationToken)
                .ConfigureAwait(false);

            if (!primary.Succeeded)
            {
                return Result.Fail(ToolFailed("error.dns.restore_failed", "netsh set dns", primary));
            }

            for (var index = 1; index < servers.Length; index++)
            {
                var added = await RunNetshAsync(
                    WindowsDnsCommands.AddServer(interfaceName, servers[index], index + 1, ipv6),
                    cancellationToken).ConfigureAwait(false);

                if (!added.Succeeded)
                {
                    return Result.Fail(ToolFailed("error.dns.restore_failed", "netsh add dns", added));
                }
            }
        }

        return Result.Ok();
    }

    private Task<CommandResult> RunNetshAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken) =>
        _runner.RunAsync(
            WindowsPlatform.SystemTool(WindowsDnsCommands.NetshTool),
            arguments,
            cancellationToken);

    // ------------------------------------------------------------------ registry

    /// <summary>
    /// Reads the resolvers configured on one interface.
    /// </summary>
    /// <remarks>
    /// <c>NameServer</c> (IPv4) and the <c>Tcpip6</c> equivalent are what
    /// <c>SetInterfaceDnsSettings</c> writes and what a static <c>netsh</c> configuration lands
    /// in; a user-set value overrides the DHCP-provided <c>DhcpNameServer</c>. This is the
    /// non-localized read-back the verification depends on — <c>netsh ... show dns</c> and
    /// <c>ipconfig /all</c> are both localized and must never be parsed.
    /// </remarks>
    private static IReadOnlyList<string> CaptureInterfaceServers(string? adapterName)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(adapterName))
        {
            return Array.Empty<string>();
        }

        var servers = new List<string>();

        foreach (var path in new[] { Ipv4InterfacePath(adapterName), Ipv6InterfacePath(adapterName) })
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path, writable: false);
                var value = key?.GetValue("NameServer") as string;

                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                servers.AddRange(value
                    .Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Where(NetworkText.IsIpAddress));
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                // A key this process may not read contributes nothing; the verification step will
                // notice the absence rather than crash.
                _ = ex;
            }
        }

        return servers.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string Ipv4InterfacePath(string adapterName) =>
        $@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{NormalizeAdapterKey(adapterName)}";

    private static string Ipv6InterfacePath(string adapterName) =>
        $@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{NormalizeAdapterKey(adapterName)}";

    /// <summary>The per-interface key is named by the adapter GUID without braces.</summary>
    private static string NormalizeAdapterKey(string adapterName) =>
        adapterName.Trim().TrimStart('{').TrimEnd('}');

    /// <summary>Writes the plan's split-DNS rules; a failure here fails the apply.</summary>
    private static Result ApplyNrptRules(DnsPlan plan)
    {
        var rules = WindowsNrptRules.FromPlan(plan);

        if (rules.Count == 0)
        {
            return Result.Ok();
        }

        if (!OperatingSystem.IsWindows())
        {
            return Result.Fail(WindowsPlatform.Unsupported("Writing NRPT rules"));
        }

        foreach (var rule in rules)
        {
            try
            {
                using var root = Registry.LocalMachine.CreateSubKey(
                    WindowsNrptRules.PolicyConfigPath, writable: true);

                if (root is null)
                {
                    return Result.Fail(NrptFailed("the DnsPolicyConfig key could not be created"));
                }

                using var key = root.CreateSubKey(rule.Key.ToString("B"), writable: true);

                if (key is null)
                {
                    return Result.Fail(NrptFailed($"rule key '{rule.Key:B}' could not be created"));
                }

                key.SetValue("Version", WindowsNrptRules.SchemaVersion, RegistryValueKind.DWord);
                key.SetValue("Name", rule.Domain, RegistryValueKind.String);
                key.SetValue(
                    "NameServers",
                    rule.Servers.ToArray(),
                    RegistryValueKind.MultiString);

                // Inert to the DNS client, decisive for cleanup after a crash.
                key.SetValue(
                    WindowsNrptRules.OwnerValueName,
                    rule.Identifier,
                    RegistryValueKind.String);
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                return Result.Fail(NrptFailed(ex.Message));
            }
        }

        return Result.Ok();
    }

    /// <summary>
    /// Removes NRPT rules, either the given ones or every MyVpn-owned rule.
    /// </summary>
    /// <param name="keys">
    /// Rule keys to remove, or <c>null</c> to remove every rule carrying MyVpn's ownership marker.
    /// </param>
    private static Result RemoveNrptRules(IEnumerable<Guid>? keys)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Result.Fail(WindowsPlatform.Unsupported("Removing NRPT rules"));
        }

        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(
                WindowsNrptRules.PolicyConfigPath, writable: true);

            if (root is null)
            {
                // No key means no rules were ever written from this location.
                return Result.Ok();
            }

            var targets = new List<string>();

            if (keys is not null)
            {
                targets.AddRange(keys.Select(k => k.ToString("B")));
            }
            else
            {
                foreach (var name in root.GetSubKeyNames())
                {
                    using var key = root.OpenSubKey(name, writable: false);

                    if (key?.GetValue(WindowsNrptRules.OwnerValueName) is not null)
                    {
                        targets.Add(name);
                    }
                }
            }

            foreach (var name in targets)
            {
                try
                {
                    root.DeleteSubKeyTree(name, throwOnMissingSubKey: false);
                }
                catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
                {
                    return Result.Fail(NrptFailed($"rule '{name}' could not be removed: {ex.Message}"));
                }
            }

            return Result.Ok();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return Result.Fail(NrptFailed(ex.Message));
        }
    }

    /// <summary>
    /// Confirms the resolvers actually landed on the interface.
    /// </summary>
    /// <remarks>
    /// This is the step that turns "netsh exited zero" into a caught error. On a machine where
    /// another manager owns interface DNS — a domain GPO, a third-party client — the command can
    /// succeed and the value be reverted immediately.
    /// </remarks>
    private static Result Verify(DnsPlan plan, string? adapterName)
    {
        if (plan.Servers.Count == 0)
        {
            return Result.Ok();
        }

        var observed = CaptureInterfaceServers(adapterName);

        if (observed.Count == 0)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.DnsConfigureFailed,
                "error.dns.verify_failed",
                ErrorSeverity.Critical,
                $"netsh reported success but no resolver could be read back for '{plan.TunnelInterface}' "
                + $"from HKLM\\{Ipv4InterfacePath(adapterName ?? "?")}. The configuration did not take.",
                "dns.reapply"));
        }

        var missing = plan.Servers
            .Where(s => !observed.Contains(s.Address.Trim(), StringComparer.OrdinalIgnoreCase))
            .Select(s => s.Address)
            .ToArray();

        if (missing.Length == 0)
        {
            return Result.Ok();
        }

        return Result.Fail(new MyVpnError(
            ErrorCodes.DnsConfigureFailed,
            "error.dns.verify_failed",
            ErrorSeverity.Critical,
            "The resolver configuration was reported as applied, but reading the interface back shows "
            + $"different servers. Missing: {string.Join(", ", missing)}; observed: "
            + $"{string.Join(", ", observed)}.",
            "dns.reapply"));
    }

    // ------------------------------------------------------------------ helpers

    private static bool IsIpv6(string address) =>
        NetworkText.IsIpAddress(address)
        && System.Net.IPAddress.TryParse(address, out var parsed)
        && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

    private static bool IsNonLoopbackAddress(string address) =>
        System.Net.IPAddress.TryParse(address, out var parsed) && !System.Net.IPAddress.IsLoopback(parsed);

    private static bool IsNonLoopbackIpv6(string address) =>
        System.Net.IPAddress.TryParse(address, out var parsed)
        && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
        && !System.Net.IPAddress.IsLoopback(parsed);

    private static MyVpnError NotElevated() =>
        WindowsPlatform.NotElevated(
            "error.dns.not_elevated",
            "Changing interface DNS configuration requires administrative rights, and this process "
            + "has none. The UI must never run elevated; this step belongs to the privileged helper.",
            "privilege.install_helper");

    private static MyVpnError ToolFailed(string messageKey, string what, CommandResult result) =>
        new MyVpnError(
            ErrorCodes.DnsConfigureFailed,
            messageKey,
            ErrorSeverity.Error,
            $"{what} failed with exit code {result.ExitCode}: {WindowsPlatform.Trim(result.Combined)}",
            "dns.reapply");

    private static MyVpnError NrptFailed(string detail) =>
        new MyVpnError(
            ErrorCodes.DnsConfigureFailed,
            "error.dns.nrpt_write_failed",
            ErrorSeverity.Error,
            "The split-DNS rule could not be written to "
            + $@"HKLM\{WindowsNrptRules.PolicyConfigPath}: {detail}",
            "dns.reapply");

    private static MyVpnError RestoreFailed(IReadOnlyList<string> failures) =>
        new MyVpnError(
            ErrorCodes.DnsRestoreFailed,
            "error.dns.restore_failed",
            ErrorSeverity.Critical,
            "Some MyVpn DNS configuration could not be reverted: "
            + WindowsPlatform.Trim(string.Join(" | ", failures)),
            "network.restore");

    private static string Describe(MyVpnError error) =>
        error.TechnicalDetail ?? error.MessageKey;
}
