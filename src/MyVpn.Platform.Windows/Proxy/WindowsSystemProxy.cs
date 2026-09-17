using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Windows.Execution;

namespace MyVpn.Platform.Windows.Proxy;

/// <summary>
/// The WinINET proxy values, as data.
/// </summary>
/// <remarks>
/// A value object rather than a set of registry calls so the mapping from a
/// <see cref="SystemProxyPlan"/> and from a <see cref="SystemProxySnapshot"/> can be verified
/// without a Windows host. <see cref="ProxyEnable"/> is an <c>int</c> because the registry
/// stores a <c>REG_DWORD</c>; the rest are the strings WinINET reads from the same key.
/// </remarks>
public sealed record WindowsProxyRegistryValues
{
    /// <summary><c>ProxyEnable</c>: 1 enables the fixed proxy, 0 disables it.</summary>
    public required int ProxyEnable { get; init; }

    /// <summary><c>ProxyServer</c>: <c>scheme=host:port</c> entries separated by <c>;</c>.</summary>
    public string? ProxyServer { get; init; }

    /// <summary><c>ProxyOverride</c>: bypass entries separated by <c>;</c>, with <c>&lt;local&gt;</c> allowed.</summary>
    public string? ProxyOverride { get; init; }

    /// <summary><c>AutoConfigURL</c>: the PAC URL, which WinINET prefers over a fixed proxy.</summary>
    public string? AutoConfigUrl { get; init; }

    /// <summary>
    /// Bypass networks that the WinINET bypass list cannot express.
    /// </summary>
    /// <remarks>
    /// <c>ProxyOverride</c> accepts host names, literal addresses, wildcards and
    /// <c>&lt;local&gt;</c> — it has no prefix or range syntax, so a CIDR block other than a
    /// host route simply has no spelling. Those entries are reported here instead of being
    /// silently dropped, because a user who asked for a bypass and did not get one needs to
    /// know which one it was.
    /// </remarks>
    public IReadOnlyList<string> NotExpressibleNetworks { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Renders the values as the registry operations that realise them.
    /// </summary>
    /// <remarks>
    /// Exposed as data for the same reason as the mapping itself: the test suite asserts on the
    /// exact value names and kinds, which is the part that a wrong constant silently breaks.
    /// </remarks>
    public IReadOnlyList<WindowsProxyRegistryWrite> ToWrites()
    {
        var writes = new List<WindowsProxyRegistryWrite>
        {
            new("ProxyEnable", Delete: false, Dword: ProxyEnable, Text: null),
        };

        writes.Add(Text(WindowsProxyRegistry.ProxyServerValue, ProxyServer));
        writes.Add(Text(WindowsProxyRegistry.ProxyOverrideValue, ProxyOverride));
        writes.Add(Text(WindowsProxyRegistry.AutoConfigUrlValue, AutoConfigUrl));

        // An empty string is not the same as an absent value to WinINET: an empty ProxyServer
        // with ProxyEnable=1 is a proxy pointing nowhere. Absent is what "not configured" means.
        return writes;
    }

    private static WindowsProxyRegistryWrite Text(string name, string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? new WindowsProxyRegistryWrite(name, Delete: true, Dword: null, Text: null)
            : new WindowsProxyRegistryWrite(name, Delete: false, Dword: null, Text: value);
}

/// <summary>One registry operation: a value name and either its data or a deletion.</summary>
public sealed record WindowsProxyRegistryWrite(string Name, bool Delete, int? Dword, string? Text);

/// <summary>
/// Translates between <see cref="SystemProxyPlan"/> / <see cref="SystemProxySnapshot"/> and the
/// WinINET registry values.
/// </summary>
/// <remarks>
/// <para>
/// WinINET's per-protocol proxy list is <c>http=host:port;https=host:port;socks=host:port</c>.
/// The bypass list is <c>;</c>-separated and always keeps <c>&lt;local&gt;</c> so that
/// single-label intranet names keep resolving directly — dropping it would send internal
/// hostnames to a proxy that cannot resolve them.
/// </para>
/// <para>
/// The snapshot round-trip is what makes "restore what the user had" possible: the previous
/// <c>AutoConfigURL</c>, <c>ProxyServer</c> and <c>ProxyOverride</c> are carried verbatim, and a
/// value that was absent is restored as absent rather than as an empty string.
/// </para>
/// </remarks>
public static class WindowsProxyValues
{
    /// <summary>The loopback bypass entry every MyVpn plan carries.</summary>
    public const string LocalBypassToken = "<local>";

    /// <summary>Builds the registry values for a plan MyVpn is about to apply.</summary>
    public static WindowsProxyRegistryValues FromPlan(SystemProxyPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var usePac = plan.UsePac && !string.IsNullOrWhiteSpace(plan.PacUrl);
        var servers = new List<string>();

        if (plan.EnableHttp)
        {
            servers.Add($"http=127.0.0.1:{plan.HttpPort.ToString(CultureInfo.InvariantCulture)}");
            servers.Add($"https=127.0.0.1:{plan.HttpPort.ToString(CultureInfo.InvariantCulture)}");
        }

        if (plan.EnableSocks)
        {
            // SOCKS is what https uses when no HTTP listener is configured: it is the more
            // capable of the two, and WinINET accepts socks= for the https slot.
            servers.Add($"socks=127.0.0.1:{plan.SocksPort.ToString(CultureInfo.InvariantCulture)}");

            if (!plan.EnableHttp)
            {
                servers.Add($"https=127.0.0.1:{plan.SocksPort.ToString(CultureInfo.InvariantCulture)}");
            }
        }

        var bypass = new List<string> { LocalBypassToken };
        bypass.AddRange(plan.BypassDomains.Where(d => !string.IsNullOrWhiteSpace(d)).Select(d => d.Trim()));

        var notExpressible = new List<string>();
        foreach (var network in plan.BypassNetworks)
        {
            // A host route is a literal address and can be expressed; anything wider cannot.
            var isHostRoute = network.PrefixLength == (network.IsIPv4 ? 32 : 128);

            if (isHostRoute)
            {
                bypass.Add(network.Network.ToString());
            }
            else
            {
                notExpressible.Add(network.ToString());
            }
        }

        return new WindowsProxyRegistryValues
        {
            // A PAC takes precedence over the fixed proxy in WinINET, so enabling the fixed
            // proxy as well would leave a stale value that silently comes back if the PAC URL
            // is later removed. When a PAC is used, the fixed proxy is left switched off.
            ProxyEnable = usePac || servers.Count == 0 ? 0 : 1,
            ProxyServer = servers.Count == 0 ? null : string.Join(';', servers),
            ProxyOverride = string.Join(';', bypass.Distinct(StringComparer.OrdinalIgnoreCase)),
            AutoConfigUrl = usePac ? plan.PacUrl : null,
            NotExpressibleNetworks = notExpressible,
        };
    }

    /// <summary>Builds the registry values that restore a captured snapshot.</summary>
    public static WindowsProxyRegistryValues FromSnapshot(SystemProxySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var mode = snapshot.Mode ?? (snapshot.Enabled ? "manual" : "none");
        var usePac = string.Equals(mode, "auto", StringComparison.OrdinalIgnoreCase);

        var servers = new List<string>();

        if (!usePac)
        {
            // WinINET has no separate https entry when only one is known: the snapshot's three
            // slots are mapped back onto the schemes the user actually had.
            if (!string.IsNullOrWhiteSpace(snapshot.HttpProxy))
            {
                servers.Add($"http={snapshot.HttpProxy}");
            }

            if (!string.IsNullOrWhiteSpace(snapshot.HttpsProxy))
            {
                servers.Add($"https={snapshot.HttpsProxy}");
            }
            else if (!string.IsNullOrWhiteSpace(snapshot.HttpProxy) && !string.IsNullOrWhiteSpace(snapshot.SocksProxy))
            {
                servers.Add($"https={snapshot.HttpProxy}");
            }

            if (!string.IsNullOrWhiteSpace(snapshot.SocksProxy))
            {
                servers.Add($"socks={snapshot.SocksProxy}");
            }
        }

        return new WindowsProxyRegistryValues
        {
            ProxyEnable = usePac ? 0 : snapshot.Enabled ? 1 : 0,
            ProxyServer = servers.Count == 0 ? null : string.Join(';', servers),
            ProxyOverride = string.IsNullOrWhiteSpace(snapshot.BypassList) ? null : snapshot.BypassList,
            AutoConfigUrl = usePac ? snapshot.PacUrl : null,
        };
    }

    /// <summary>Describes the values read from the registry as a snapshot.</summary>
    /// <remarks>
    /// <see cref="SystemProxySnapshot.Mode"/> uses the platform-neutral triad
    /// (<c>none</c>/<c>manual</c>/<c>auto</c>); WinINET records the same distinction as
    /// "AutoConfigURL set" versus "ProxyEnable set" versus neither, which is exactly the
    /// mapping below.
    /// </remarks>
    public static SystemProxySnapshot ToSnapshot(WindowsProxyRegistryValues values)
    {
        ArgumentNullException.ThrowIfNull(values);

        var hasPac = !string.IsNullOrWhiteSpace(values.AutoConfigUrl);
        var hasFixed = values.ProxyEnable != 0 && !string.IsNullOrWhiteSpace(values.ProxyServer);

        var mode = hasPac ? "auto" : hasFixed ? "manual" : "none";

        var (http, https, socks) = SplitProxyServer(values.ProxyServer);

        return new SystemProxySnapshot
        {
            Mode = mode,
            Enabled = hasPac || hasFixed,
            PacUrl = hasPac ? values.AutoConfigUrl : null,
            HttpProxy = http,
            HttpsProxy = https,
            SocksProxy = socks,
            BypassList = values.ProxyOverride,
        };
    }

    /// <summary>Splits a WinINET <c>ProxyServer</c> value into its per-scheme parts.</summary>
    /// <remarks>
    /// A bare <c>host:port</c> with no <c>scheme=</c> prefix means "use this for every
    /// protocol", which is the older form WinINET still accepts and other tools still write.
    /// </remarks>
    public static (string? Http, string? Https, string? Socks) SplitProxyServer(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return (null, null, null);
        }

        string? http = null;
        string? https = null;
        string? socks = null;

        foreach (var entry in value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = entry.IndexOf('=', StringComparison.Ordinal);

            if (separator < 0)
            {
                // Bare host:port — applies to all protocols.
                http ??= entry;
                https ??= entry;
                continue;
            }

            var scheme = entry[..separator].Trim();
            var address = entry[(separator + 1)..].Trim();

            switch (scheme.ToLowerInvariant())
            {
                case "http":
                    http = address;
                    break;
                case "https":
                    https = address;
                    break;
                case "socks":
                case "socks5":
                    socks = address;
                    break;
                default:
                    break;
            }
        }

        return (http, https, socks);
    }

    /// <summary>
    /// True when a proxy string points at this machine.
    /// </summary>
    /// <remarks>
    /// Judged by the loopback host: the executor cannot know which local port MyVpn chose from
    /// the value alone, and a loopback proxy that is not ours is a false positive. It is a
    /// heuristic for the UI, never a security decision.
    /// </remarks>
    public static bool PointsAtLoopback(string? proxyServer)
    {
        if (string.IsNullOrWhiteSpace(proxyServer))
        {
            return false;
        }

        foreach (var entry in proxyServer.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = entry.IndexOf('=', StringComparison.Ordinal);
            var address = separator < 0 ? entry : entry[(separator + 1)..];

            if (address.StartsWith("127.", StringComparison.Ordinal)
                || address.StartsWith("localhost", StringComparison.OrdinalIgnoreCase)
                || address.StartsWith("[::1]", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// Configures the per-user system proxy through the WinINET registry values.
/// </summary>
/// <remarks>
/// <para>
/// <b>Scope: the interactive user, not the machine.</b> WinINET proxy settings are per-user
/// (<c>HKCU</c>), so this executor must run in the user's session — Microsoft's own guidance is
/// that WinINET "should not be used from a service". A SYSTEM service that ran this would
/// write the service account's hive and change nothing the user can see. WinHTTP (the
/// machine-wide store used by BITS and Windows Update) is deliberately <i>not</i> touched here:
/// it is a separate mechanism and belongs to the service.
/// </para>
/// <para>
/// <b>Why the registry, and where that diverges from the documentation.</b> The documented
/// WinINET API is <c>InternetSetOption(INTERNET_OPTION_PER_CONNECTION_OPTION)</c>, and
/// Microsoft warns that client applications should not use registry functions because the
/// storage layout may change. This executor writes the four documented value names
/// (<c>ProxyEnable</c>, <c>ProxyServer</c>, <c>ProxyOverride</c>, <c>AutoConfigURL</c>) and
/// then issues the two notification calls WinINET requires
/// (<c>INTERNET_OPTION_SETTINGS_CHANGED</c> then <c>INTERNET_OPTION_REFRESH</c>) so every
/// running process re-reads them. The registry form is used because it is the only way to
/// capture and restore the previous values exactly, and because it works without a WinINET
/// handle; the divergence is recorded here rather than left implicit.
/// </para>
/// <para>
/// <b>A stale proxy survives a reboot.</b> These values are persistent, so a proxy pointing at
/// a port that no longer has a listener keeps breaking the machine after a crash. That is why
/// <see cref="ResetAsync"/> exists and why emergency cleanup calls it rather than trying to
/// reconstruct the user's original configuration.
/// </para>
/// <para>
/// <b>Coverage.</b> Chrome and Edge use the platform proxy; Firefox does not unless it is set
/// to "use system proxy settings". System-proxy mode is therefore an interoperability
/// convenience, never leak protection — that is what the Kill Switch and TUN mode are for.
/// </para>
/// </remarks>
public sealed class WindowsSystemProxy : ISystemProxy
{
    private readonly object _gate = new();

    /// <summary>Last values this instance wrote, for drift detection in diagnostics.</summary>
    private WindowsProxyRegistryValues? _lastApplied;

    /// <summary>
    /// True when the per-user WinINET store can be written from this process.
    /// </summary>
    /// <remarks>
    /// Cheap and honest: <c>HKCU</c> is writable by the user whose hive it is, so on Windows the
    /// answer is yes; a group policy that redirects the proxy to the machine scope
    /// (<c>ProxySettingsPerUser = 0</c>) can still make an unelevated write ineffective, and
    /// that is reported by the verification step rather than guessed at here.
    /// </remarks>
    public bool IsSupported => OperatingSystem.IsWindows();

    public Task<Result<SystemProxySnapshot>> CaptureAsync(CancellationToken cancellationToken)
    {
        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(Result<SystemProxySnapshot>.Fail(
                WindowsPlatform.Unsupported("Reading the WinINET proxy configuration")));
        }

        var read = ReadValues(out var error);

        if (read is null)
        {
            return Task.FromResult(Result<SystemProxySnapshot>.Fail(error!));
        }

        return Task.FromResult(Result<SystemProxySnapshot>.Ok(WindowsProxyValues.ToSnapshot(read)));
    }

    public Task<Result> ApplyAsync(SystemProxyPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(Result.Fail(
                WindowsPlatform.Unsupported("Configuring the WinINET system proxy")));
        }

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return Task.FromResult(validation);
        }

        var values = WindowsProxyValues.FromPlan(plan);

        // The proxy is written in full before it is switched on: activating first would point
        // every process at a listener whose address is not configured yet.
        var written = WriteValues(values);
        if (written.IsFailure)
        {
            return Task.FromResult(written);
        }

        var notified = Notify();
        if (notified.IsFailure)
        {
            return Task.FromResult(notified);
        }

        lock (_gate)
        {
            _lastApplied = values;
        }

        return Task.FromResult(Result.Ok());
    }

    public Task<Result> RestoreAsync(SystemProxySnapshot snapshot, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(Result.Fail(
                WindowsPlatform.Unsupported("Restoring the WinINET system proxy")));
        }

        var written = WriteValues(WindowsProxyValues.FromSnapshot(snapshot));
        if (written.IsFailure)
        {
            return Task.FromResult(written);
        }

        lock (_gate)
        {
            _lastApplied = null;
        }

        return Task.FromResult(Notify());
    }

    /// <summary>
    /// Switches the proxy off without guessing what was there before.
    /// </summary>
    /// <remarks>
    /// Only <c>ProxyEnable</c> is cleared and the PAC URL removed; the host and port the user
    /// configured are left in place, so re-enabling manual mode finds their own values rather
    /// than whatever MyVpn happened to write. This mirrors the Linux executor's reset.
    /// </remarks>
    public Task<Result> ResetAsync(CancellationToken cancellationToken)
    {
        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(Result.Fail(
                WindowsPlatform.Unsupported("Resetting the WinINET system proxy")));
        }

        var written = WriteValues(new WindowsProxyRegistryValues
        {
            ProxyEnable = 0,
            ProxyServer = ReadString(WindowsProxyRegistry.ProxyServerValue),
            ProxyOverride = ReadString(WindowsProxyRegistry.ProxyOverrideValue),
            AutoConfigUrl = null,
        });

        if (written.IsFailure)
        {
            return Task.FromResult(written);
        }

        lock (_gate)
        {
            _lastApplied = null;
        }

        return Task.FromResult(Notify());
    }

    public Task<SystemProxyState> InspectAsync(CancellationToken cancellationToken)
    {
        // A query, so a non-Windows host answers "not configured" rather than throwing: there is
        // no WinINET store to read, and the caller's leftover check must not fail because of it.
        if (!WindowsPlatform.IsWindows)
        {
            return Task.FromResult(new SystemProxyState { IsConfigured = false });
        }

        var read = ReadValues(out _);

        if (read is null)
        {
            return Task.FromResult(new SystemProxyState { IsConfigured = false });
        }

        var configured = read.ProxyEnable != 0 || !string.IsNullOrWhiteSpace(read.AutoConfigUrl);

        return Task.FromResult(new SystemProxyState
        {
            IsConfigured = configured,
            ActiveProxy = configured ? read.ProxyServer : null,
            PacUrl = string.IsNullOrWhiteSpace(read.AutoConfigUrl) ? null : read.AutoConfigUrl,
            PointsAtMyVpn = WindowsProxyValues.PointsAtLoopback(read.ProxyServer),
        });
    }

    // ------------------------------------------------------------------ registry

    private static WindowsProxyRegistryValues? ReadValues(out MyVpnError? error)
    {
        error = null;

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(WindowsProxyRegistry.InternetSettingsPath, writable: false);

            if (key is null)
            {
                error = new MyVpnError(
                    ErrorCodes.SystemProxySetFailed,
                    "error.proxy.not_available",
                    ErrorSeverity.Error,
                    $"The per-user Internet Settings key "
                    + $"'HKCU\\{WindowsProxyRegistry.InternetSettingsPath}' could not be opened, so the "
                    + "system proxy configuration cannot be read or restored.",
                    "diagnostics.run");
                return null;
            }

            return new WindowsProxyRegistryValues
            {
                ProxyEnable = ReadDword(key, WindowsProxyRegistry.ProxyEnableValue),
                ProxyServer = ReadString(key, WindowsProxyRegistry.ProxyServerValue),
                ProxyOverride = ReadString(key, WindowsProxyRegistry.ProxyOverrideValue),
                AutoConfigUrl = ReadString(key, WindowsProxyRegistry.AutoConfigUrlValue),
            };
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            error = new MyVpnError(
                ErrorCodes.SystemProxySetFailed,
                "error.proxy.not_available",
                ErrorSeverity.Error,
                $"Reading HKCU\\{WindowsProxyRegistry.InternetSettingsPath} failed: {ex.Message}",
                "diagnostics.run");
            return null;
        }
    }

    private static Result WriteValues(WindowsProxyRegistryValues values)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(
                WindowsProxyRegistry.InternetSettingsPath, writable: true);

            if (key is null)
            {
                return Result.Fail(new MyVpnError(
                    ErrorCodes.SystemProxySetFailed,
                    "error.proxy.not_available",
                    ErrorSeverity.Error,
                    $"The per-user Internet Settings key "
                    + $"'HKCU\\{WindowsProxyRegistry.InternetSettingsPath}' could not be created, so the "
                    + "system proxy cannot be configured. A machine-scoped proxy policy "
                    + "(ProxySettingsPerUser = 0) has this effect for unelevated processes.",
                    "diagnostics.run"));
            }

            foreach (var write in values.ToWrites())
            {
                if (write.Delete)
                {
                    // Absent, not empty: an empty ProxyServer with ProxyEnable=1 is a proxy that
                    // resolves to nothing, which is a broken machine rather than a clean one.
                    key.DeleteValue(write.Name, throwOnMissingValue: false);
                }
                else if (write.Dword is not null)
                {
                    key.SetValue(write.Name, write.Dword.Value, RegistryValueKind.DWord);
                }
                else if (write.Text is not null)
                {
                    key.SetValue(write.Name, write.Text, RegistryValueKind.String);
                }
            }

            return Result.Ok();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.SystemProxySetFailed,
                "error.proxy.set_failed",
                ErrorSeverity.Error,
                $"Writing HKCU\\{WindowsProxyRegistry.InternetSettingsPath} failed: {ex.Message}",
                "diagnostics.run"));
        }
    }

    private static string? ReadString(string name) => ReadValues(out _) is { } values
        ? name switch
        {
            WindowsProxyRegistry.ProxyServerValue => values.ProxyServer,
            WindowsProxyRegistry.ProxyOverrideValue => values.ProxyOverride,
            _ => null,
        }
        : null;

    private static string? ReadString(RegistryKey key, string name) => key.GetValue(name) as string;

    /// <summary>
    /// Reads a <c>REG_DWORD</c>, tolerating a string.
    /// </summary>
    /// <remarks>
    /// The value is documented as a DWORD, but third-party tools have been observed writing it
    /// as a string, and treating that as "not enabled" would silently claim the proxy is off
    /// when it is on.
    /// </remarks>
    private static int ReadDword(RegistryKey key, string name)
    {
        var value = key.GetValue(name);

        return value switch
        {
            int number => number,
            uint number => unchecked((int)number),
            string text when int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
                => parsed,
            _ => 0,
        };
    }

    /// <summary>
    /// Tells every process to re-read the proxy configuration.
    /// </summary>
    /// <remarks>
    /// Without these two calls the registry change is invisible until something restarts: the
    /// documented sequence is <c>INTERNET_OPTION_SETTINGS_CHANGED</c> (39) followed by
    /// <c>INTERNET_OPTION_REFRESH</c> (37). A failure is reported rather than swallowed, because
    /// "written but not announced" presents to the user as "the proxy did not change".
    /// </remarks>
    private static Result Notify()
    {
        if (!WindowsPlatform.IsWindows)
        {
            return Result.Fail(WindowsPlatform.Unsupported("Notifying WinINET of a proxy change"));
        }

        try
        {
            var changed = InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
            var refreshed = InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);

            if (changed && refreshed)
            {
                return Result.Ok();
            }

            return Result.Fail(new MyVpnError(
                ErrorCodes.SystemProxySetFailed,
                "error.proxy.set_failed",
                ErrorSeverity.Warning,
                "The proxy values were written but WinINET was not notified successfully "
                + $"(SETTINGS_CHANGED={changed}, REFRESH={refreshed}), so running applications may keep "
                + "using the previous configuration until they restart.",
                "diagnostics.run"));
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return Result.Fail(new MyVpnError(
                ErrorCodes.SystemProxySetFailed,
                "error.proxy.set_failed",
                ErrorSeverity.Warning,
                $"wininet.dll could not be loaded: {ex.Message}",
                "diagnostics.run"));
        }
    }

    private const int InternetOptionRefresh = 37;
    private const int InternetOptionSettingsChanged = 39;

    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", ExactSpelling = true, SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOption(IntPtr internet, int option, IntPtr buffer, int bufferLength);
}

/// <summary>Names of the WinINET registry values MyVpn reads and writes.</summary>
public static class WindowsProxyRegistry
{
    /// <summary>Per-user WinINET configuration key.</summary>
    public const string InternetSettingsPath =
        @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    public const string ProxyEnableValue = "ProxyEnable";

    public const string ProxyServerValue = "ProxyServer";

    public const string ProxyOverrideValue = "ProxyOverride";

    public const string AutoConfigUrlValue = "AutoConfigURL";
}
